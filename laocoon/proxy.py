"""Laocoon as an OpenAI-compatible proxy: protects an app with ZERO code changes.

    app (LLM_PROVIDER=openai, LLM_BASE_URL=http://proxy:9000/v1)  ->  POST /v1/chat/completions  ->  upstream LLM

The app still executes its own tools. The proxy decides what the LLM sees and which tool calls the app ever gets:
  request:   G1 on a new user message (a blocked message never reaches the LLM) · the tools of THIS run (① firewall:
             role tools ∩ X-Laocoon-Tool-Config, bound args hidden) · the conversation canary in the system prompt
             (③) · role filters + G2 labelling/quarantine on every tool result (②)
  response:  every tool_call goes through Turn.check_call; allowed calls are rewritten with the deterministically
             filled arguments, denied/held calls are removed and explained; a text answer goes through check_reply
  approvals: the user types `έγκριση ap_xxxx` (or `approve ap_xxxx`); the proxy answers with the stored tool call,
             exactly as approved, without calling the LLM.

Identity: LAOCOON_IDENTITY=system_prompt (demo: read 'User id / Username / Role' from the system message the app's
server builds from the session, cross-checked with the app DB) or signed_header (production: X-Laocoon-Principal,
HMAC). Always read from the ORIGINAL messages, never from user messages, tool output or anything the model wrote.

Facts: LAOCOON_AUTHZ_SOURCE=db (a read-only handle on the app database, LAOCOON_ECLASS_DB) or lookup (the seamless
proxy: no database at all). With `lookup` the app only points its base URL here; the rules come from the policy, and
the facts behind them from the app's own read tools: observed in the results of the model's calls, or looked up by
holding the model's calls and asking the app to run a read call first (facts.py, holds.py). Lookup traffic never
reaches the model. The identity block must appear exactly once and is confirmed through the app (get_user).
Or views: a database login that can read only the views of the policy's data_model (laocoon/views.py), asked
live for every check like `db`. PostgreSQL (LAOCOON_VIEWS_DSN) enforces that limit itself; on SQLite
(LAOCOON_VIEWS_DB, default LAOCOON_ECLASS_DB) Laocoon enforces it on itself with TEMP views and an authorizer.
Or authzen: the customer's own policy decision point answers every check over OpenID AuthZEN 1.0
(LAOCOON_AUTHZEN_PDP; laocoon/authzen.py), whatever store it sits on. No database handle at all; the identity block
is read strictly and confirmed by the PDP (or comes from the signed header).

Run:  gunicorn laocoon.proxy:app --bind 0.0.0.0:9000
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

import requests
from flask import Flask, Response, abort, jsonify, redirect, request

from . import config, identity
from .adapters.eclass import EclassAdapter, readonly_query
from .adapters.eclass_lookup import EclassLookupAdapter
from .adapters.eclass_authzen import EclassAuthzenAdapter
from .adapters.eclass_views import EclassViewsAdapter
from .approvals import ApprovalError
from .audit import canonical
from .console import console_html
from .facts import FactView, NeedFacts, Unverifiable
from .firewall import ToolConfig
from .guard import APPROVE_RE, REJECT_RE, Guard, _is_request
from .holds import MAX_ROUNDS, is_lookup_id, split as split_lookups
from .memory import STATUSES as MEMORY_STATUSES
from .private import assert_clean, keyed_conversation_key, map_content, tokenise_arguments
from .runtime import layer_enabled, register_runtime
from .web import ConsoleAccess, register_web

GEMINI_SIG = {"google": {"thought_signature": "skip_thought_signature_validator"}}
TOOL_CONFIG_HEADER = "X-Laocoon-Tool-Config"


def _env(name, default=None):
    return config.env(name, default)


def _header(name, default=None):
    """A request header, or its spelling before the rename (X-Laocoon-* was X-Odysseus-*)."""
    return request.headers.get(name) or request.headers.get(name.replace("X-Laocoon-", "X-Odysseus-"), default)


class ProxyConfig:
    def __init__(self):
        self.app_key = _env("LAOCOON_APP_KEY", "")
        self.identity = _env("LAOCOON_IDENTITY", "system_prompt")
        self.authz_source = (_env("LAOCOON_AUTHZ_SOURCE", "db") or "db").strip().lower()
        if self.authz_source not in ("db", "lookup", "views", "authzen"):
            raise ValueError(f"LAOCOON_AUTHZ_SOURCE must be db, lookup, views or authzen, not {self.authz_source!r}")
        self.eclass_db = _env("LAOCOON_ECLASS_DB", "/eclass-data/eclass.db")
        self.upstream_url = (_env("LAOCOON_UPSTREAM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
                             or "").rstrip("/")
        self.upstream_key = _env("LAOCOON_UPSTREAM_API_KEY") or _env("AI_STUDIO_API_KEY", "")
        self.upstream_model = _env("LAOCOON_UPSTREAM_MODEL", "")          # "" = keep the app's model name
        self.console_token = _env("LAOCOON_CONSOLE_TOKEN", "")
        self.timeout = float(_env("LAOCOON_UPSTREAM_TIMEOUT", "120"))


def build_guard(cfg: ProxyConfig) -> Guard:
    # the classifier (② Siren Guard) is configured by LAOCOON_GUARD_* / TYPESAFE_API_KEY, read by the Guard itself.
    # The opt-in planner (LAOCOON_PLANNER=openai) defaults to the agent's own upstream endpoint, key and model.
    overrides = {}
    if not (_env("LAOCOON_PLANNER_BASE_URL") or _env("LAOCOON_UPSTREAM_BASE_URL")):
        overrides["planner_base_url"] = cfg.upstream_url
    if not (_env("LAOCOON_PLANNER_API_KEY") or _env("LAOCOON_UPSTREAM_API_KEY") or _env("AI_STUDIO_API_KEY")):
        overrides["planner_api_key"] = cfg.upstream_key
    if cfg.authz_source == "lookup":                      # seamless: never opens the app database
        return Guard.from_env(EclassLookupAdapter(), **overrides)
    if cfg.authz_source == "views":                       # only the data_model's views (the Guard configures it)
        return Guard.from_env(EclassViewsAdapter(), **overrides)
    if cfg.authz_source == "authzen":                     # the customer's PDP (the Guard configures it)
        g = Guard.from_env(EclassAuthzenAdapter(), **overrides)
        if cfg.identity != "signed_header" and not g.adapter.config.identity_action:
            raise ValueError("LAOCOON_AUTHZ_SOURCE=authzen with LAOCOON_IDENTITY=system_prompt needs "
                             "authzen.identity.action in the policy: the PDP must confirm the identity block")
        return g
    return Guard.from_env(EclassAdapter(readonly_query(cfg.eclass_db)), **overrides)


def _text(content):
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


def _completion(model, message, finish="stop"):
    return {"id": "chatcmpl-lcn-" + secrets.token_hex(6), "object": "chat.completion", "created": int(time.time()),
            "model": model or "laocoon", "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def _sse(data):
    """Minimal streaming support: the full answer as one chunk (the checks need the whole response)."""
    ch = data["choices"][0]
    delta = {"role": "assistant", "content": ch["message"].get("content") or ""}
    if ch["message"].get("tool_calls"):
        delta["tool_calls"] = [dict(tc, index=i) for i, tc in enumerate(ch["message"]["tool_calls"])]
    base = {k: data[k] for k in ("id", "created", "model")}
    yield "data: " + json.dumps({**base, "object": "chat.completion.chunk",
                                 "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}) + "\n\n"
    yield "data: " + json.dumps({**base, "object": "chat.completion.chunk",
                                 "choices": [{"index": 0, "delta": {}, "finish_reason": ch["finish_reason"]}]}) + "\n\n"
    yield "data: [DONE]\n\n"


def _tail_results(messages):
    """The tool results at the end of the conversation with the calls they answer: [(name, args, result)]."""
    i, out = len(messages) - 1, []
    while i >= 0 and messages[i].get("role") == "tool":
        out.append(messages[i])
        i -= 1
    if i < 0 or messages[i].get("role") != "assistant":
        return []
    calls = {tc.get("id"): tc.get("function") or {} for tc in messages[i].get("tool_calls") or []}
    res = []
    for m in reversed(out):
        fn = calls.get(m.get("tool_call_id"))
        if not fn:
            continue
        try:
            args = json.loads(fn.get("arguments") or "{}")
            result = json.loads(_text(m.get("content")))
        except (json.JSONDecodeError, TypeError):
            continue
        res.append((fn.get("name"), args if isinstance(args, dict) else {}, result))
    return res


def conversation_key(principal, messages, secret: bytes | None = None) -> str:
    """Stable per conversation: the canary must be the same in every request of it (③). With private_data the key
    is keyed (`secret`), so a short first message such as a bare AMKA cannot be recovered from the audit log."""
    first = next((m.get("content") for m in messages if m.get("role") == "user"), "")
    if secret is not None:
        return keyed_conversation_key(secret, principal["id"], canonical(first))
    return hashlib.sha256(f"{principal['id']}|{canonical(first)}".encode()).hexdigest()[:24]


def create_app(cfg: ProxyConfig | None = None, guard: Guard | None = None) -> Flask:
    app = Flask(__name__)
    state = {"cfg": cfg, "guard": guard}
    lock = threading.Lock()

    def C() -> ProxyConfig:
        if state["cfg"] is None:
            state["cfg"] = ProxyConfig()
        return state["cfg"]

    def G() -> Guard:
        with lock:
            if state["guard"] is None:
                state["guard"] = build_guard(C())
            elif C().authz_source == "lookup" and not hasattr(state["guard"].adapter, "verify_identity"):
                # an injected guard must match the facts source: a db adapter cannot answer lookups
                raise RuntimeError("LAOCOON_AUTHZ_SOURCE=lookup needs a guard built on a lookup adapter")
            return state["guard"]

    app.config["laocoon_state"] = state

    # ---------------------------------------------------------------- helpers
    def reply(body, message, finish="stop"):
        data = _completion(body.get("model"), message, finish)
        if body.get("stream"):
            return Response(_sse(data), mimetype="text/event-stream")
        return jsonify(data)

    def text_reply(body, text):
        return reply(body, {"role": "assistant", "content": text})

    def principal_for(messages):
        cfg, g = C(), G()
        if cfg.identity == "signed_header":
            return identity.verify_header(g.settings.secret, _header(identity.HEADER, ""))
        if cfg.authz_source == "lookup":                  # no database to cross-check with: strict, then a lookup
            return identity.from_system_prompt_strict(messages, (g.policy_data.get("identity") or {}).get("fields"),
                                                      g.policy_data.get("roles"))
        if cfg.authz_source == "authzen":                 # strict, then confirmed by the PDP (identity action)
            p = identity.from_system_prompt_strict(messages, (g.policy_data.get("identity") or {}).get("fields"),
                                                   g.policy_data.get("roles"))
            return p if p is not None and g.adapter.verify_identity(p) else None
        return identity.from_system_prompt(messages, g.adapter)

    def upstream(body):
        cfg = C()
        body = dict(body, stream=False)
        if cfg.upstream_model:
            body["model"] = cfg.upstream_model
        headers = {"Content-Type": "application/json"}
        if cfg.upstream_key:
            headers["Authorization"] = f"Bearer {cfg.upstream_key}"
        r = requests.post(cfg.upstream_url + "/chat/completions", json=body, headers=headers,
                          timeout=(10, cfg.timeout))
        return r

    def _args(fn):
        try:
            a = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            a = {}
        return a if isinstance(a, dict) else {}

    def _same(hold, kind):
        return hold if hold is not None and hold.kind == kind else None

    def hold_reply(body, principal, messages, kind, lookups, payload=None, prev=None, conversation=None):
        """Answer the app with lookup calls instead of the model's answer. None when the chain is exhausted (too
        many rounds, or the same lookups again: their results did not settle it); the caller then decides with
        what it has, which fails closed."""
        g = G()
        lookups = list(lookups)
        if prev is not None and (prev.round >= MAX_ROUNDS or all(lk.key() in prev.done for lk in lookups)):
            g.audit.log("lookup", principal, action="exhausted", rule="facts", severity="medium",
                        reason=f"{kind}: the lookups did not settle the decision after {prev.round} round(s)")
            return None
        hid, calls = g.holds.create(principal, conversation or conversation_key(principal, messages), kind, lookups,
                                    payload, prev)
        g.audit.log("lookup", principal, tool=",".join(sorted({lk.tool for lk in lookups})), action="lookup",
                    rule="facts", severity="info",
                    reason=f"{kind}: {len(calls)} lookup(s) through the app, round {(prev.round + 1) if prev else 1}"
                           + ("" if not any(lk.speculative for lk in lookups) else ", some outside the user's scope"),
                    provenance={"hold": hid, "lookups": [[lk.tool, lk.as_args()] for lk in lookups][:20]})
        return reply(body, {"role": "assistant", "content": "", "tool_calls": calls}, "tool_calls")

    # ---------------------------------------------------------------- the endpoint
    @app.post("/v1/chat/completions")
    def chat_completions():
        cfg = C()
        auth = request.headers.get("Authorization", "")
        if cfg.app_key and not hmac.compare_digest(auth, f"Bearer {cfg.app_key}"):
            return jsonify(error={"message": "invalid Laocoon app key", "type": "auth"}), 401
        body = request.get_json(silent=True) or {}
        messages = body.get("messages") or []

        if not layer_enabled(G):                              # passthrough (baseline through the proxy):
            r = upstream(body)                                # LAOCOON_ENABLED or the console's laocoon.enabled
            return Response(r.content, status=r.status_code, mimetype="application/json")

        g = G()
        lookup_mode = cfg.authz_source == "lookup"
        tail = []
        if lookup_mode:                                       # the conversation as the model knows it
            messages, tail = split_lookups(messages)
        principal = principal_for(messages)                   # from the ORIGINAL messages, before any rewriting
        if principal is None:
            g.audit.log("identity", None, action="deny", rule="identity", severity="high",
                        reason="no verifiable principal in request")
            return jsonify(error={"message": "Laocoon: cannot establish the user's identity", "type": "auth"}), 401
        ckey = conversation_key(principal, messages, g.settings.secret if g.private is not None else None)

        hold = None
        if lookup_mode:
            facts = FactView(g.store, principal["id"], ttl=getattr(g.adapter, "ttl", None))
            principal = dict(principal, attrs={**(principal.get("attrs") or {}), "facts": facts})
            if tail:                                          # results of the lookups we asked for
                hold = g.holds.resume(principal, tail)
                if hold is None:
                    g.audit.log("lookup", principal, action="deny", rule="facts", severity="medium",
                                reason="lookup results that do not match a live hold (expired, another user or "
                                       "altered): ignored")
                else:
                    for lk, result in hold.results:
                        g.adapter.ingest(facts, lk.tool, lk.as_args(), result, at=hold.created_at)
            else:                                             # results of the model's own calls: observed facts
                for name, args, result in _tail_results(messages):
                    g.adapter.ingest(facts, name, args, result)
            try:
                verified = g.adapter.verify_identity(principal)
            except NeedFacts as e:
                r = hold_reply(body, principal, messages, "identity", e.lookups, prev=_same(hold, "identity"),
                               conversation=ckey)
                if r is not None:
                    return r
                verified = False
            except Unverifiable:
                verified = False
            if not verified:
                g.audit.log("identity", principal, action="deny", rule="identity", severity="high",
                            reason="the app's own record of this user does not match the system prompt")
                return jsonify(error={"message": "Laocoon: cannot establish the user's identity",
                                      "type": "auth"}), 401

        resuming = hold is not None and hold.kind == "calls" and isinstance((hold.payload or {}).get("message"), dict)
        last_user = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)
        convo = [m for m in messages[:last_user + 1] if m.get("role") != "system"]
        turn_id = "px_" + hashlib.sha256((str(principal["id"]) + canonical(convo)).encode()).hexdigest()[:24]
        system_prompt = next((_text(m.get("content")) for m in messages if m.get("role") == "system"), "")
        user_msgs = [_text(m.get("content")) for m in messages if m.get("role") == "user"][-3:]
        # the user's own requests (no approvals typed in the chat, no Laocoon notices) and the side effects already
        # called since the latest one: the opt-in planner's input and its call counts (the proxy is stateless)
        real = [i for i, m in enumerate(messages) if m.get("role") == "user" and _is_request(_text(m.get("content")))]
        requests_ = [_text(messages[i].get("content")) for i in real][-20:]
        prior = [(tc.get("function") or {}).get("name") for m in messages[(real[-1] + 1 if real else 0):]
                 if m.get("role") == "assistant" for tc in (m.get("tool_calls") or [])]
        tools_in = body.get("tools") or []
        new_message = last_user == len(messages) - 1 and not resuming   # a user message, not a continuation
        utext = _text(messages[-1].get("content")) if new_message else ""
        m_ok, m_no = (APPROVE_RE.match(utext), REJECT_RE.match(utext)) if new_message else (None, None)
        message = utext if new_message else (user_msgs[-1] if user_msgs else "")   # G1 judges the real new message
        pd = g.private.context(ckey, principal) if g.private is not None else None   # private_data map
        check_input = new_message and not (m_ok or m_no)
        turn = g.begin_turn(principal, message, turn_id=turn_id,
                            declarations=tools_in, system_prompt=system_prompt, user_messages=requests_,
                            prior_calls=prior,
                            conversation_id=ckey, tool_config=ToolConfig.parse(_header(TOOL_CONFIG_HEADER)),
                            check_input=check_input and pd is None, private=pd)
        if turn.killed or turn.blocked:                       # kill switch, or G1 blocked the message: no LLM call
            return text_reply(body, turn.refusal())

        # ④ approval typed in the chat: answer with the stored call, exactly as approved, no LLM call
        if m_ok or m_no:
            aid = (m_ok or m_no).group(1)
            try:
                if m_no:
                    g.resolve_approval(aid, principal, "deny", executor=None)
                    return text_reply(body, f"[Laocoon] Η ενέργεια {aid} απορρίφθηκε και δεν θα εκτελεστεί.")
                if lookup_mode:                               # re-check with fresh facts before claiming
                    pending = g.approvals.get(aid)
                    if pending and pending["status"] == "pending" and int(pending["user_id"]) == principal["id"]:
                        needs = turn.plan_check(pending["tool"], pending["args"])
                        if needs:
                            r = hold_reply(body, principal, messages, "approval", needs, prev=_same(hold, "approval"),
                                           conversation=ckey)
                            if r is not None:
                                return r
                row = g.claim_approval(aid, principal)
            except ApprovalError as e:
                return text_reply(body, f"[Laocoon] {e}")
            call = {"id": "call_" + aid, "type": "function", "extra_content": GEMINI_SIG,
                    "function": {"name": row["tool"], "arguments": json.dumps(row["args"], ensure_ascii=False)}}
            return reply(body, {"role": "assistant", "content": "", "tool_calls": [call]}, "tool_calls")

        def tool_input(m, name, a):
            try:
                raw = json.loads(_text(m.get("content")))
            except (json.JSONDecodeError, TypeError):
                raw = _text(m.get("content"))
            if lookup_mode:                                             # released ids: no lookup, no re-check
                nargs = g.policy.normalise_for_labels(principal, name, a)
            else:
                _, nargs, _ = g.policy.evaluate(principal, name, a)      # same normalisation as at call time
            return raw, nargs

        # private_data, pass (a): every value of the request is collected before any message is forwarded
        prepared = {}
        if pd is not None:
            seen = {}
            for i, m in enumerate(messages):
                role, text = m.get("role"), _text(m.get("content"))
                if role == "system":
                    pd.collect_text(text, "app")
                elif role == "user":
                    if not text.startswith("[Laocoon]") and not APPROVE_RE.match(text) and not REJECT_RE.match(text):
                        pd.collect_text(text, "typed", subject=principal["id"])
                elif role == "assistant":
                    pd.collect_text(text, "history")
                    for tc in m.get("tool_calls") or []:
                        fn = tc.get("function") or {}
                        seen[tc.get("id")] = (fn.get("name"), _args(fn))
                        pd.tokenise_obj(_args(fn), origin="history")
                elif role == "tool" and m.get("tool_call_id") in seen:
                    name, a = seen[m["tool_call_id"]]
                    raw, nargs = tool_input(m, name, a)
                    prepared[i] = (nargs, turn.prepare_result(name, nargs, raw))
            if check_input:                                   # G1 on the message in placeholder form
                turn.check_input()
                if turn.blocked:
                    return text_reply(body, turn.refusal())

        # the forwarded copy: canary in the system prompt (③), filters + G2 on every tool result (①②)
        calls = {}
        last_assistant = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=-1)
        fwd, protected = [], False
        for i, m in enumerate(messages):
            if m.get("role") == "system" and not protected:
                m = dict(m, content=turn.protect_system_prompt(_text(m.get("content"))))
                protected = True
            if m.get("role") == "user":
                ap = APPROVE_RE.match(_text(m.get("content")))
                if ap:   # tell the model what the bare "έγκριση ap_x" meant (forwarded copy only)
                    row = g.approvals.get(ap.group(1)) or {}
                    m = dict(m, content=f"[Laocoon] Ο χρήστης ενέκρινε ρητά την ενέργεια {row.get('tool', '')} "
                                        f"({ap.group(1)}) και η εφαρμογή την εκτέλεσε. Ανέφερε σύντομα το αποτέλεσμα.")
                elif pd is not None:
                    m = dict(m, content=map_content(m.get("content"), lambda t: pd.tokenise_text(t, origin="typed")))
            if m.get("role") == "assistant":
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    calls[tc.get("id")] = (fn.get("name"), _args(fn))       # the real arguments, for the labels
                if pd is not None:          # what Laocoon re-hydrated earlier goes back to placeholders
                    m = dict(m, content=map_content(m.get("content"), lambda t: pd.tokenise_text(t, origin="history")))
                    if m.get("tool_calls"):
                        m["tool_calls"] = [dict(tc, function=dict(tc.get("function") or {}, arguments=tokenise_arguments(
                            pd, (tc.get("function") or {}).get("arguments")))) for tc in m["tool_calls"]]
            if m.get("role") == "tool" and m.get("tool_call_id") in calls:
                name, a = calls[m["tool_call_id"]]
                if i in prepared:
                    nargs, prep = prepared[i]
                    labelled = turn.label_result(name, nargs, None, quiet=i < last_assistant or resuming, prepared=prep)
                else:
                    raw, nargs = tool_input(m, name, a)
                    labelled = turn.label_result(name, nargs, raw, quiet=i < last_assistant or resuming)
                m = dict(m, content=json.dumps(labelled, ensure_ascii=False, default=str))
            fwd.append(m)

        out = dict(body, messages=fwd)
        filtered = turn.tools(tools_in) if tools_in else []
        if filtered:
            out["tools"] = pd.tokenise_obj(filtered, origin="app") if pd is not None else filtered
        else:
            out.pop("tools", None)
            out.pop("tool_choice", None)
        if pd is not None:                                # last line: nothing declared may leave in clear
            fixed, found = assert_clean(pd, {"messages": out["messages"], "tools": out.get("tools") or []})
            if found:
                out["messages"] = fixed["messages"]
                if out.get("tools"):
                    out["tools"] = fixed["tools"]
                g.audit.log("guard", principal, turn_id=turn.id, action="error", rule="private_data:residual",
                            severity="high", reason=f"{found} δηλωμένα προσωπικά δεδομένα βρέθηκαν στο αίτημα προς το "
                                                    "μοντέλο μετά την ψευδωνυμοποίηση και αντικαταστάθηκαν.")
            pd.flush_vault()

        if resuming:                                      # the model already answered: decide its held calls now
            msg = hold.payload["message"]
            if pd is not None:                            # stored in placeholder form
                msg = dict(msg, content=turn.render(msg.get("content")))
            data = _completion(body.get("model"), msg, "tool_calls")
            tcs = msg.get("tool_calls") or []
        else:
            t0 = time.monotonic()
            try:
                r = upstream(out)
            except requests.RequestException as e:
                return jsonify(error={"message": f"upstream unreachable: {type(e).__name__}"}), 502
            if r.status_code != 200:
                return Response(r.content, status=r.status_code, mimetype="application/json")
            data = r.json()
            choices = data.get("choices") or []
            if not choices or not choices[0].get("message"):
                return jsonify(data)
            msg = choices[0]["message"]
            tcs = msg.get("tool_calls") or []
            for tc in tcs:                                # the lookup id prefix is reserved for the proxy
                if is_lookup_id(tc.get("id")):
                    tc["id"] = "call_" + secrets.token_hex(6)

            content = turn.check_reply(_text(msg.get("content")))   # G3 on whatever the model wrote
            if turn.killed and tcs:                                  # the text leaked: nothing of this answer runs
                return text_reply(body, content)
            msg["content"] = content
            if not tcs:
                data["laocoon"] = {"upstream_ms": int((time.monotonic() - t0) * 1000)}
                return Response(_sse(data), mimetype="text/event-stream") if body.get("stream") else jsonify(data)

        if lookup_mode:                                   # facts first: hold the calls and look them up
            needs, decided = turn.plan([((tc.get("function") or {}).get("name"), _args(tc.get("function") or {}))
                                        for tc in tcs])
            if needs and not decided:
                stored = msg if pd is None else dict(       # no value at rest: the resuming request re-mints ids
                    msg, content=pd.tokenise_text(_text(msg.get("content")), origin="model"),
                    tool_calls=[dict(tc, function=dict(tc.get("function") or {}, arguments=tokenise_arguments(
                        pd, (tc.get("function") or {}).get("arguments"), origin="model"))) for tc in tcs])
                r = hold_reply(body, principal, messages, "calls", needs, payload={"message": stored},
                               prev=hold if resuming else None, conversation=ckey)
                if r is not None:
                    return r

        decisions = []
        for tc in tcs:
            fn = tc.get("function") or {}
            decisions.append((tc, turn.check_call(fn.get("name"), _args(fn))))

        if all(d.action == "allow" for _, d in decisions):
            for tc, d in decisions:                   # the app executes the filled, normalised arguments
                tc["function"]["arguments"] = json.dumps(d.args, ensure_ascii=False)
            return Response(_sse(data), mimetype="text/event-stream") if body.get("stream") else jsonify(data)

        # strictest outcome for the batch: nothing in it runs; explain each call
        notes = []
        for tc, d in decisions:
            name = d.tool
            if d.action == "deny":
                notes.append(f"[Laocoon] Μπλοκαρίστηκε: {name} — {d.reason}")
            elif d.action == "kill":
                notes.append(f"[Laocoon] Η συνεδρία σταμάτησε: {d.reason}")
            elif d.action == "ask":
                rows = "; ".join(f"{k}: {v}" for k, v in (d.preview or {}).get("rows", []))
                notes.append(f"[Laocoon] Η ενέργεια «{(d.preview or {}).get('title', name)}» χρειάζεται έγκριση "
                             f"({d.reason}) [{rows}]. Για να εκτελεστεί, γράψε: έγκριση {d.approval_id}")
            else:
                notes.append(f"[Laocoon] Δεν εκτελέστηκε: {name} (στην ίδια ομάδα ενεργειών υπήρχε μπλοκαρισμένη ενέργεια).")
        content = _text(msg.get("content")).strip()
        text = ((content + "\n\n") if content else "") + "\n".join(notes)
        msg = {"role": "assistant", "content": turn.render(text)}      # reasons and card rows: table A
        data["choices"][0] = {"index": 0, "message": msg, "finish_reason": "stop"}
        return Response(_sse(data), mimetype="text/event-stream") if body.get("stream") else jsonify(data)

    @app.get("/v1/models")
    def models():
        m = C().upstream_model or "laocoon-protected"
        return jsonify(object="list", data=[{"id": m, "object": "model", "owned_by": "laocoon"}])

    @app.get("/health")
    def health():
        return jsonify(ok=True, enabled=layer_enabled(G))

    # ---------------------------------------------------------------- ⑤ console
    # operators sign in with a name and password (LAOCOON_CONSOLE_USERS) or the console token (web.ConsoleAccess)
    access = ConsoleAccess(lambda: C().console_token, login_url="/laocoon/login", get_guard=G)
    console_auth = access.require

    # sign-in and the welcome page (public), policy studio (page + API, signed in); -> the links between the pages
    nav = register_web(app, G, access, title="Laocoon proxy")
    register_runtime(app, G, access, api_base="/laocoon/api")      # the mitigation switches (runtime.py)

    @app.route("/odysseus", defaults={"rest": ""}, methods=["GET", "POST", "DELETE"])
    @app.route("/odysseus/<path:rest>", methods=["GET", "POST", "DELETE"])
    def former_name(rest):
        """Links from before the rename (/odysseus...) keep working; 308 keeps the method and the body."""
        qs = request.query_string.decode()
        return redirect("/laocoon" + ("/" + rest if rest else "") + ("?" + qs if qs else ""), code=308)

    @app.get("/laocoon")
    def console():
        console_auth(page=True)
        return access.page(console_html(api_base="/laocoon/api", title="Laocoon proxy", nav=access.nav(nav)))

    @app.get("/laocoon/api/events")
    def c_events():
        console_auth()
        return jsonify(events=G().events(int(request.args.get("after", 0)), 300))

    @app.get("/laocoon/api/state")
    def c_state():
        console_auth()
        g = G()
        c = g.classifier
        return jsonify(counters=g.audit.counters(), kills=g.kills.active(), flags=g.flags(),
                       pending=g.approvals.pending(),
                       classifier={"enabled": c.enabled, "backend": type(c.backend).__name__, "model": c.model,
                                   **({"members": c.backend.stats()} if hasattr(c.backend, "stats") else {})},
                       runtime=g.runtime.summary(),
                       memory=g.memory.stats() if g.memory is not None else {"mode": "off"},
                       planner={"enabled": g.planner.enabled, "model": g.planner.model,
                                "off_plan": g.planner.config["off_plan"]})

    @app.route("/laocoon/api/kill", methods=["POST", "DELETE"])
    def c_kill():
        console_auth()
        g = G()
        b = request.get_json(silent=True) or {}
        if request.method == "DELETE":
            g.revive(b.get("scope", "global"), b.get("key") or "*")
        else:
            g.kill(b.get("scope", "global"), b.get("key") or "*", b.get("reason") or "manual stop", b.get("ttl"))
        return jsonify(ok=True, kills=g.kills.active())

    @app.post("/laocoon/api/flags/<int:fid>")
    def c_flag(fid):
        console_auth()
        G().store.execute("UPDATE flags SET status = ? WHERE id = ?",
                          ((request.get_json(silent=True) or {}).get("status", "dismissed"), fid))
        return jsonify(ok=True)

    @app.get("/laocoon/api/verify")
    def c_verify():
        console_auth()
        return jsonify(G().verify_chain())

    @app.get("/laocoon/api/export.jsonl")
    def c_export():
        console_auth()
        return Response(G().audit.export_jsonl(), mimetype="application/x-ndjson")

    # ---------------------------------------------------------------- ⑥ attack memory (opt-in: LAOCOON_MEMORY)
    def memory():
        mem = G().memory
        if mem is None:
            abort(404, "the attack memory is off (set LAOCOON_MEMORY=on or match)")
        return mem

    def memory_log(action, reason):
        G().audit.log("memory", None, action=action, rule="memory:console", severity="info", reason=reason)

    @app.get("/laocoon/api/memory")
    def c_memory():
        console_auth()
        mem = memory()
        status = request.args.get("status", "all")
        if status not in ("all", *MEMORY_STATUSES):
            abort(400, f"status must be all or one of {', '.join(MEMORY_STATUSES)}")
        return jsonify(stats=mem.stats(), attacks=mem.list(status, min(1000, int(request.args.get("limit", 200)))))

    @app.post("/laocoon/api/memory")
    def c_memory_add():
        console_auth()
        b = request.get_json(silent=True) or {}
        try:
            row = memory().add(b.get("text", ""), b.get("kind", "content"), b.get("label"), by="console")
        except ValueError as e:
            return jsonify(error=str(e)), 400
        memory_log("add", f"#{row['id']} added from the console")
        return jsonify(attack=row)

    @app.route("/laocoon/api/memory/<int:aid>", methods=["GET", "POST", "DELETE"])
    def c_memory_one(aid):
        console_auth()
        mem = memory()
        if request.method == "DELETE":
            ok = mem.delete(aid)
            if ok:
                memory_log("delete", f"#{aid} deleted from the console")
            return jsonify(ok=ok), 200 if ok else 404
        if request.method == "POST":
            b = request.get_json(silent=True) or {}
            try:
                row = mem.set_status(aid, b.get("status"), by="console", label=b.get("label"))
            except ValueError as e:
                return jsonify(error=str(e)), 400
            if row is not None:
                memory_log(row["status"], f"#{aid} -> {row['status']} from the console")
        else:
            row = mem.get(aid)
        return (jsonify(attack=row), 200) if row is not None else (jsonify(error="not found"), 404)

    @app.get("/laocoon/api/memory/export.jsonl")
    def c_memory_export():
        console_auth()
        return Response(memory().export(), mimetype="application/x-ndjson")

    @app.post("/laocoon/api/memory/import")
    def c_memory_import():
        console_auth()
        # JSON lines as the body (curl with the token), or {"jsonl": "..."} (a signed-in page: writes must be JSON)
        text = (request.get_json(silent=True) or {}).get("jsonl", "") if request.is_json else request.get_data(as_text=True)
        res = memory().import_lines(str(text or "").splitlines(), by="console")
        memory_log("import", f"{res['added']} attacks imported, {res['skipped']} skipped")
        return jsonify(res)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9000")), threaded=True)

"""Held decisions and their lookups (seamless proxy, `LAOCOON_AUTHZ_SOURCE=lookup`).

When a decision needs facts the proxy does not have, it does not call the model and does not answer with the model's
calls. It stores what it was deciding (a *hold*) and answers the app with lookup tool calls instead:

    app ──request──► proxy: model wants set_final_grade(CS220); is the user the teacher of CS220? unknown
    app ◄──────────  tool_calls: [list_courses()]            id odyl_<hold>_<i>_<mac>   (no model call)
    app runs it, appends the result, calls again
    app ──request──► proxy: verifies the ids, learns the facts, decides the held calls
    app ◄──────────  the model's calls with the filled arguments, or the explanation of why they were blocked

The ids carry an HMAC of (hold, index, tool, arguments), so a lookup result is accepted only for the exact call the
proxy asked for, by the same user, before the hold expires. Lookup messages are removed from every copy forwarded
to the model: it never sees them. Kinds: `calls` (the model's held answer), `identity` (verify who the user is
before anything else), `approval` (re-check an approved call with fresh facts).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field

from .facts import Lookup

PREFIX = "odyl_"
HOLD_TTL = 180                 # seconds the app has to run the lookups and call back
MAX_ROUNDS = 5                 # lookup rounds for one decision (a chain: course → assignments → submissions)
MAX_LOOKUPS = 30               # lookups in one round
GEMINI_SIG = {"google": {"thought_signature": "skip_thought_signature_validator"}}


@dataclass
class Hold:
    id: str
    user_id: int
    kind: str
    round: int
    lookups: list
    done: list
    payload: dict | None
    created_at: float
    results: list = field(default_factory=list)      # [(Lookup, parsed result)]


def _text(content):
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content if isinstance(content, str) else ""


def is_lookup_id(cid) -> bool:
    return isinstance(cid, str) and cid.startswith(PREFIX)


def _is_lookup_message(m) -> bool:
    if m.get("role") == "tool":
        return is_lookup_id(m.get("tool_call_id"))
    if m.get("role") == "assistant":
        tcs = m.get("tool_calls") or []
        return bool(tcs) and all(is_lookup_id((tc or {}).get("id")) for tc in tcs) and not _text(m.get("content")).strip()
    return False


def split(messages):
    """-> (logical messages without any lookup traffic, trailing lookup results [(tool_call_id, content)])."""
    logical = [m for m in messages if not _is_lookup_message(m)]
    tail = []
    i = len(messages) - 1
    while i >= 0 and messages[i].get("role") == "tool" and is_lookup_id(messages[i].get("tool_call_id")):
        tail.append((messages[i]["tool_call_id"], _text(messages[i].get("content"))))
        i -= 1
    if tail and not (i >= 0 and _is_lookup_message(messages[i]) and messages[i].get("role") == "assistant"):
        tail = []                                     # results without the call that asked for them: ignore
    return logical, list(reversed(tail))


class Holds:
    def __init__(self, store, secret: bytes):
        self.store = store
        self.secret = secret

    def _mac(self, hid, i, lk: Lookup) -> str:
        msg = f"{hid}|{i}|{lk.key()}".encode()
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()[:16]

    def create(self, principal, conversation, kind, lookups, payload=None, prev: Hold | None = None):
        """-> (hold id, the tool calls to send to the app)."""
        hid = secrets.token_hex(6)
        now = time.time()
        lookups = list(lookups)[:MAX_LOOKUPS]
        done = (list(prev.done) if prev else []) + [lk.key() for lk in lookups]
        self.store.execute(
            "INSERT INTO holds (id, user_id, conversation, kind, round, lookups, done, payload, created_at, expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (hid, int(principal["id"]), conversation, kind, (prev.round + 1) if prev else 1,
             json.dumps([[lk.tool, list(map(list, lk.args)), lk.speculative] for lk in lookups], default=str),
             json.dumps(done), json.dumps(payload, ensure_ascii=False, default=str) if payload is not None else None,
             now, now + HOLD_TTL))
        self.store.execute("DELETE FROM holds WHERE expires_at < ?", (now - HOLD_TTL,))
        calls = [{"id": f"{PREFIX}{hid}_{i}_{self._mac(hid, i, lk)}", "type": "function", "extra_content": GEMINI_SIG,
                  "function": {"name": lk.tool, "arguments": json.dumps(lk.as_args(), ensure_ascii=False)}}
                 for i, lk in enumerate(lookups)]
        return hid, calls

    def resume(self, principal, tail) -> Hold | None:
        """The hold that the trailing lookup results answer, with the results attached; None if they do not verify
        (another user, expired, tampered id, unknown hold)."""
        parsed = []
        for cid, content in tail:
            parts = cid[len(PREFIX):].split("_")
            if len(parts) != 3 or not parts[1].isdigit():
                return None
            parsed.append((parts[0], int(parts[1]), parts[2], content))
        hids = {p[0] for p in parsed}
        if len(hids) != 1:
            return None
        hid = hids.pop()
        row = self.store.query("SELECT * FROM holds WHERE id = ?", (hid,), one=True)
        if not row or int(row["user_id"]) != int(principal["id"]) or time.time() > row["expires_at"]:
            return None
        lookups = [Lookup(t, tuple(tuple(a) for a in args), bool(spec)) for t, args, spec in json.loads(row["lookups"])]
        hold = Hold(hid, int(row["user_id"]), row["kind"], int(row["round"]), lookups, json.loads(row["done"]),
                    json.loads(row["payload"]) if row["payload"] else None, float(row["created_at"]))
        for _, i, mac, content in parsed:
            if i >= len(lookups) or not hmac.compare_digest(mac, self._mac(hid, i, lookups[i])):
                return None
            try:
                result = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                result = {"error": "unparseable lookup result"}
            hold.results.append((lookups[i], result))
        return hold

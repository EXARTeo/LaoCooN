"""Web routes besides the console API: operator sign-in, the welcome page and the policy studio (page + JSON API).

`register_web(app, get_guard, access)` adds them to a Flask app (the proxy). The studio never changes the running
policy: it validates, renders, diffs and saves drafts; a draft becomes active only through deployment
(`LAOCOON_POLICY=<file>` and a restart), so a stolen console session cannot loosen the firewall live.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import quote

from flask import abort, jsonify, make_response, redirect, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import studio
from .config import PACKAGE_DIR, env
from .console import login_html, policies_html, settings_html, welcome_html

MAX_BODY = 512 * 1024
DRAFT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
DEFAULT_EVAL = PACKAGE_DIR.parent / "eval" / "results" / "latest.md"


# ---------------------------------------------------------------------------------------------- operator sign-in
SESSION_COOKIE = "lcn_console"
SESSION_HOURS = 12
TOKEN_USER = "token"                       # the session of someone who opened a page with the console token
DEMO_USERS = {"admin": "laocoon"}          # only while LAOCOON_CONSOLE_USERS is unset; the sign-in page says so


def console_users() -> tuple[dict, bool]:
    """LAOCOON_CONSOLE_USERS="name:password,…" -> ({name: password}, False). Unset: the demo account, True."""
    raw = env("LAOCOON_CONSOLE_USERS")
    if not raw or not raw.strip():
        return dict(DEMO_USERS), True
    users = {}
    for item in raw.split(","):
        name, sep, password = item.strip().partition(":")
        if name.strip() and sep and password and name.strip() != TOKEN_USER:
            users[name.strip()] = password
    return users, False


def _safe_next(url: str | None, fallback: str) -> str:
    """Only a path on this site: no scheme, no host, no //host, no backslash tricks."""
    url = (url or "").strip()
    if not url.startswith("/") or url.startswith("//") or "\\" in url or any(ord(c) < 32 for c in url):
        return fallback
    return url


class ConsoleAccess:
    """Who may open the console and the policy studio.

    - an operator signed in with a name and password (LAOCOON_CONSOLE_USERS): a signed, HttpOnly, SameSite=Lax
      cookie that lasts SESSION_HOURS;
    - a request with the console token (X-Laocoon-Token or ?token=), for scripts and the links from before sign-in
      existed; a page opened that way also gets the cookie, so the token can leave the URL.
    With neither a token nor users configured the pages are open, as before (local development).
    Cookie-authenticated writes must be JSON from this origin: a form on another site cannot send them.
    """

    def __init__(self, token, *, login_url="/laocoon/login", get_guard=None):
        self._token = token                # () -> the configured console token ("" = none)
        self.login_url = login_url
        self.get_guard = get_guard

    def protected(self) -> bool:
        return bool(self._token()) or bool((env("LAOCOON_CONSOLE_USERS") or "").strip())

    def _signer(self) -> URLSafeTimedSerializer:
        # The key changes with the token, the secret and the accounts: rotating any of them signs everyone out.
        users, _ = console_users()
        material = "|".join((self._token() or "", env("LAOCOON_SECRET", "") or "",
                             json.dumps(sorted(users.items()))))
        return URLSafeTimedSerializer(hashlib.sha256(b"laocoon/console-session|" + material.encode()).hexdigest(),
                                      salt="laocoon-console")

    def _given_token(self) -> str:
        return (request.headers.get("X-Laocoon-Token") or request.headers.get("X-Odysseus-Token")
                or request.args.get("token", ""))

    def token_ok(self) -> bool:
        tok, given = self._token(), self._given_token()
        return bool(tok and given) and hmac.compare_digest(given, tok)

    def session_user(self) -> str | None:
        raw = request.cookies.get(SESSION_COOKIE)
        if not raw:
            return None
        try:
            name = (self._signer().loads(raw, max_age=SESSION_HOURS * 3600) or {}).get("u")
        except (BadSignature, AttributeError):
            return None
        if name == TOKEN_USER:
            return name if self._token() else None
        return name if name in console_users()[0] else None

    def who(self) -> str | None:
        """The operator of this request: a user name, "token", "" for an open console; None = no access."""
        if self.token_ok():
            return TOKEN_USER
        user = self.session_user()
        if user:
            return user
        return None if self.protected() else ""

    def require(self, page=False) -> str:
        who = self.who()
        if who is None:
            if page:
                abort(redirect(self.login_url + "?next=" + quote(request.full_path.rstrip("?"), safe="/?=&")))
            abort(401)
        if who not in ("",) and not self.token_ok() and request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if not request.is_json or (origin and origin.rstrip("/") != request.host_url.rstrip("/")):
                abort(403)                                    # a cross-site form riding on the cookie
        return who

    def issue(self, resp, user: str):
        resp.set_cookie(SESSION_COOKIE, self._signer().dumps({"u": user}), max_age=SESSION_HOURS * 3600,
                        httponly=True, samesite="Lax", secure=request.is_secure, path="/")
        return resp

    def page(self, html: str):
        """A page response; opened with ?token=, it also signs the browser in, so the next link needs no token."""
        resp = make_response(html)
        if request.args.get("token") and self.token_ok() and not self.session_user():
            self.issue(resp, TOKEN_USER)
        return resp

    def nav(self, nav: dict) -> dict:
        """The links between the pages plus who is signed in (the header shows it and offers sign-out)."""
        who = self.who()
        out = dict(nav)
        if self.protected():
            out["user"] = who or ""
        return out


# ---------------------------------------------------------------------------------------------- eval numbers
def eval_metrics(path=None) -> dict:
    """The summary table of the latest eval report (eval/run.py), for the welcome page. {} when absent."""
    p = Path(path or env("LAOCOON_EVAL_RESULTS") or DEFAULT_EVAL)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return {}
    head = text.split("\n## ", 1)[0]
    rows, columns = [], []
    for line in head.splitlines():
        if not line.startswith("|") or set(line.replace("|", "").strip()) <= {"-", " "}:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not columns:
            columns = cells[1:]
            continue
        if all(v in ("—", "-", "") for v in cells[1:]):
            continue
        rows.append({"metric": cells[0], "values": cells[1:]})
    title = re.search(r"^# .*?(\d{4}-\d{2}-\d{2})", head, re.M)
    model = re.search(r"model `([^`]+)`", head)
    llm = re.search(r"LLM: \*\*(\w+)\*\*", head)
    runs = re.search(r"runs per scenario: (\d+)", head)
    if not rows:
        return {}
    return {"date": title.group(1) if title else None, "model": model.group(1) if model else None,
            "llm": llm.group(1) if llm else None, "runs": int(runs.group(1)) if runs else None,
            "columns": columns, "rows": rows}


# ---------------------------------------------------------------------------------------------- drafts
def drafts_dir(guard) -> Path:
    d = env("LAOCOON_POLICY_DRAFTS")
    return Path(d) if d else Path(guard.settings.db_path).resolve().parent / "policy-drafts"


def _draft_path(guard, name) -> Path:
    if not DRAFT_RE.match(name or ""):
        abort(400, "bad draft name")
    return drafts_dir(guard) / f"{name}.yaml"


def list_drafts(guard) -> list[dict]:
    d = drafts_dir(guard)
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.glob("*.yaml"), key=lambda f: f.stat().st_mtime, reverse=True):
        if DRAFT_RE.match(f.stem):
            st = f.stat()
            out.append({"name": f.stem, "updated": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime)),
                        "size": st.st_size})
    return out


def _templates(guard) -> list[dict]:
    active = Path(guard.settings.policy_path)
    out = [{"id": "active", "title": "Ενεργή πολιτική", "detail": active.name},
           {"id": "blank", "title": "Κενή πολιτική", "detail": "όλα απαγορεύονται, χωρίς εργαλεία"}]
    folder = active.parent
    if folder.is_dir():
        for f in sorted(folder.glob("*.yaml")):
            if f.resolve() != active.resolve() and DRAFT_RE.match(f.stem):
                out.append({"id": "file:" + f.stem, "title": f.name, "detail": "αρχείο στον φάκελο πολιτικών"})
    return out


def _template_text(guard, tid) -> str:
    active = Path(guard.settings.policy_path)
    if tid == "active":
        return active.read_text(encoding="utf-8")
    if tid == "blank":
        return studio.to_yaml(studio.BLANK)
    if tid.startswith("file:") and DRAFT_RE.match(tid[5:]):
        f = active.parent / f"{tid[5:]}.yaml"
        if f.is_file():
            return f.read_text(encoding="utf-8")
    abort(404)


# ---------------------------------------------------------------------------------------------- routes
def register_web(app, get_guard, access: ConsoleAccess, *, api_base="/laocoon/api", console_url="/laocoon",
                 policies_url="/laocoon/policies", settings_url="/laocoon/settings", home_url="/",
                 title="Laocoon proxy") -> dict:
    """Add sign-in, the welcome page (public), the policy studio and the mitigations page (behind `access`), and
    the studio's API. The mitigations API is laocoon/runtime.py. -> the nav links."""
    nav = {"home": home_url, "console": console_url, "policies": policies_url, "settings": settings_url,
           "login": access.login_url, "logout": api_base + "/logout"}
    auth = access.require

    def body() -> dict:
        if (request.content_length or 0) > MAX_BODY:
            abort(413)
        return request.get_json(silent=True) or {}

    @app.get(home_url, endpoint="web_welcome")
    def welcome():
        return welcome_html(console_url=console_url, policies_url=policies_url, metrics=eval_metrics(),
                            app_url=env("LAOCOON_APP_URL", ""), nav=access.nav(nav))

    @app.get(access.login_url, endpoint="web_login")
    def login_page():
        nxt = _safe_next(request.args.get("next"), console_url)
        if access.who() is not None and not request.args.get("again"):
            return redirect(nxt)
        users, demo = console_users()
        return login_html(api_base=api_base, next_url=nxt, demo=demo and access.protected(),
                          token_login=bool(access._token()), nav=access.nav(nav))

    @app.post(api_base + "/login", endpoint="web_login_api")
    def login_api():
        b = body()
        name, password = str(b.get("username") or "").strip(), str(b.get("password") or "")
        users, _ = console_users()
        expected = users.get(name)
        # compare against something even for an unknown name, so the timing does not tell names apart
        ok = hmac.compare_digest(password.encode(), (expected if expected is not None else "\0" * 16).encode())
        if not (ok and expected is not None):
            tok = access._token()
            if not (name in ("", TOKEN_USER) and tok and hmac.compare_digest(password.encode(), tok.encode())):
                time.sleep(0.4)                                # a little friction for guessing
                return jsonify(ok=False, error="credentials"), 401
            name = TOKEN_USER
        g = get_guard()
        g.audit.log("console", {"username": name}, action="login", rule="console", severity="info",
                    reason=f"σύνδεση χειριστή «{name}» στην κονσόλα")
        return access.issue(jsonify(ok=True, user=name, next=_safe_next(b.get("next"), console_url)), name)

    @app.post(api_base + "/logout", endpoint="web_logout_api")
    def logout_api():
        resp = jsonify(ok=True, next=access.login_url)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get(settings_url, endpoint="web_settings")
    def settings_page():
        auth(page=True)
        return access.page(settings_html(api_base=api_base, title=title, nav=access.nav(nav)))

    @app.get(policies_url, endpoint="web_policies")
    def policies_page():
        auth(page=True)
        return access.page(policies_html(api_base=api_base, title=title, nav=access.nav(nav)))

    @app.get(api_base + "/policy", endpoint="web_policy")
    def policy_state():
        auth()
        g = get_guard()
        path = Path(g.settings.policy_path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = None
        return jsonify(active={"path": str(path), "name": path.name, "yaml": text},
                       analysis=studio.analyse(g.adapter, text=text) if text is not None else None,
                       catalog=studio.catalog(g.adapter), templates=_templates(g), drafts=list_drafts(g),
                       drafts_dir=str(drafts_dir(g)))

    @app.post(api_base + "/policy/analyse", endpoint="web_policy_analyse")
    def policy_analyse():
        auth()
        b = body()
        g = get_guard()
        if isinstance(b.get("yaml"), str):
            return jsonify(studio.analyse(g.adapter, text=b["yaml"]))
        base = b.get("base") if isinstance(b.get("base"), str) and len(b["base"]) <= MAX_BODY else None
        return jsonify(studio.analyse(g.adapter, data=b.get("data"), base=base))

    @app.post(api_base + "/policy/diff", endpoint="web_policy_diff")
    def policy_diff():
        auth()
        b = body()
        g = get_guard()
        against = b.get("against") or "active"
        old = _template_text(g, "active") if against == "active" else \
            _draft_path(g, against).read_text(encoding="utf-8")
        return jsonify(diff=studio.diff(old, str(b.get("yaml") or ""), old_name=against, new_name="επεξεργασία"))

    @app.get(api_base + "/policy/templates/<tid>", endpoint="web_policy_template")
    def policy_template(tid):
        auth()
        return jsonify(id=tid, yaml=_template_text(get_guard(), tid))

    @app.get(api_base + "/policy/drafts", endpoint="web_policy_drafts")
    def drafts():
        auth()
        return jsonify(drafts=list_drafts(get_guard()))

    @app.route(api_base + "/policy/drafts/<name>", methods=["GET", "PUT", "DELETE"], endpoint="web_policy_draft")
    def draft(name):
        auth()
        g = get_guard()
        path = _draft_path(g, name)
        if request.method == "GET":
            if not path.is_file():
                abort(404)
            return jsonify(name=name, yaml=path.read_text(encoding="utf-8"))
        if request.method == "DELETE":
            path.unlink(missing_ok=True)
            g.audit.log("policy", None, action="delete", rule="studio", severity="info",
                        reason=f"διαγραφή πρόχειρου πολιτικής «{name}»")
            return jsonify(ok=True, drafts=list_drafts(g))
        text = body().get("yaml")
        if not isinstance(text, str):
            abort(400, "yaml required")
        result = studio.analyse(g.adapter, text=text)
        if result["data"] is None:                     # not even YAML: nothing worth keeping
            return jsonify(saved=False, **result), 422
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
        c = result["counts"]
        g.audit.log("policy", None, action="draft", rule="studio", severity="info",
                    reason=f"αποθήκευση πρόχειρου πολιτικής «{name}» ({c['error']} σφάλματα, "
                           f"{c['warning']} προειδοποιήσεις)")
        return jsonify(saved=True, name=name, path=str(path), drafts=list_drafts(g), **result)

    return nav

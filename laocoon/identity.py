"""Who is the user? The server-built system prompt (demo) or a signed header.

The proxy NEVER takes identity from user messages, tool results or anything the model wrote.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time

HEADER = "X-Laocoon-Principal"


def _system_text(messages):
    for m in messages or []:
        if m.get("role") == "system":
            c = m.get("content")
            return c if isinstance(c, str) else "".join(p.get("text", "") for p in c or [] if isinstance(p, dict))
    return ""


def from_system_prompt(messages, adapter=None):
    """Demo mode: eClass writes 'User id / Username / Role' into the system message from the session.
    Only the FIRST system message is read, and the values are cross-checked against the app database."""
    text = _system_text(messages)
    get = lambda label: (re.search(rf"(?im)^\s*[-*]?\s*{label}\s*:\s*(.+?)\s*$", text) or [None, None])[1]
    uid, username, role = get("User id"), get("Username"), get("Role")
    if not (uid and username and role) or not uid.isdigit():
        return None
    p = {"id": int(uid), "username": username, "role": role, "attrs": {}}
    if adapter is not None:
        real = adapter.principal_by_id(p["id"])
        if not real or real["username"] != username or real["role"] != role:
            return None
        p = real
    return p


DEFAULT_LABELS = {"id": "User id", "username": "Username", "role": "Role", "name": "Name"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,64}$")


def from_system_prompt_strict(messages, labels=None, roles=None):
    """Seamless proxy (no database): the same block, read strictly. Every label must appear exactly once in the first
    system message, so a second "Role: admin" line (e.g. injected through a profile field the app writes into the
    prompt) rejects the request instead of being believed; the id is a bounded integer, the username a plain handle,
    the role one of the policy's roles. The DB cross-check is replaced by a lookup through the app (see
    EclassLookupAdapter.verify_identity)."""
    labels = {**DEFAULT_LABELS, **{k: v for k, v in (labels or {}).items() if isinstance(v, str) and v.strip()}}
    text = _system_text(messages)
    vals = {}
    for key, label in labels.items():
        hits = re.findall(rf"(?im)^[ \t]*[-*]?[ \t]*{re.escape(label)}[ \t]*:[ \t]*(.*?)[ \t]*$", text)
        if key == "name" and not hits:
            vals[key] = None
            continue
        if len(hits) != 1 or not hits[0]:
            return None
        vals[key] = hits[0]
    uid = vals["id"]
    if not (uid.isdigit() and len(uid) <= 15) or not USERNAME_RE.match(vals["username"]):
        return None
    if roles and vals["role"] not in roles:
        return None
    return {"id": int(uid), "username": vals["username"], "role": vals["role"],
            "attrs": {"full_name": vals.get("name"), "source": "system_prompt"}}


def sign_principal(secret: bytes, principal: dict, ttl=600) -> str:
    """Production mode: the app signs {id, username, role, exp} and sends it in X-Laocoon-Principal."""
    body = {"id": principal["id"], "username": principal["username"], "role": principal["role"],
            "exp": int(time.time()) + ttl}
    raw = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(secret, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_header(secret: bytes, value: str):
    try:
        raw, sig = (value or "").rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(sig, hmac.new(secret, raw.encode(), hashlib.sha256).hexdigest()):
        return None
    try:
        body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except ValueError:
        return None
    if body.get("exp", 0) < time.time():
        return None
    return {"id": int(body["id"]), "username": body["username"], "role": body["role"], "attrs": {}}

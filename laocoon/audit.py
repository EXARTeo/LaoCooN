"""⑤ Audit & control: tamper-evident event log (hash chain)."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

GENESIS = "0" * 64
MASK_KEYS = {"password", "new_password", "old_password"}


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def mask_value(v):
    s = str(v)
    return "***" + s[-2:] if len(s) > 4 else "***"


_PLACEHOLDER = re.compile(r"\s*⟦[A-Za-z][A-Za-z0-9_]{0,31}:[0-9a-z]{6,12}⟧\s*")


def mask_args(args, sensitive_fields=()):
    """Mask sensitive top-level keys. A value that is entirely a private_data placeholder is already safe and stays
    (it lets an operator follow the same value across events)."""
    if not isinstance(args, dict):
        return args
    keys = MASK_KEYS | set(sensitive_fields)
    return {k: (mask_value(v) if k in keys and v not in (None, "")
                and not (isinstance(v, str) and _PLACEHOLDER.fullmatch(v)) else v) for k, v in args.items()}


EVENT_FIELDS = ("ts", "turn_id", "user_id", "username", "role", "stage", "tool", "args", "action", "rule",
                "severity", "reason", "provenance", "prev_hash")


OPTIONAL_FIELDS = ("conversation",)      # v0.2: hash-chained when present, so v0.1 rows still verify


def _hash(row: dict) -> str:
    fields = EVENT_FIELDS + tuple(k for k in OPTIONAL_FIELDS if row.get(k) is not None)
    return hashlib.sha256(canonical({k: row.get(k) for k in fields}).encode()).hexdigest()


class AuditLog:
    def __init__(self, store, sensitive_fields=()):
        self.store = store
        self.sensitive_fields = tuple(sensitive_fields)
        self.redactor = None             # private_data: every stored string in placeholder form (Guard sets it)

    def log(self, stage, principal=None, *, turn_id=None, tool=None, args=None, action=None, rule=None,
            severity="info", reason=None, provenance=None, conversation=None, redact=None) -> int:
        principal = principal or {}
        r = redact or self.redactor
        if r is not None:
            args = r(args) if args is not None else None
            reason = r(reason) if isinstance(reason, str) else reason
            provenance = r(provenance) if isinstance(provenance, (dict, list, str)) else provenance
        row = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "turn_id": turn_id, "user_id": principal.get("id"), "username": principal.get("username"),
            "role": principal.get("role"), "stage": stage, "tool": tool,
            "args": canonical(mask_args(args, self.sensitive_fields)) if args is not None else None,
            "action": action, "rule": rule, "severity": severity,
            "reason": reason, "provenance": canonical(provenance) if isinstance(provenance, (dict, list)) else provenance,
            "conversation": str(conversation) if conversation is not None else None,
        }
        # BEGIN IMMEDIATE: two workers must never read the same prev_hash.
        with self.store.tx(immediate=True) as conn:
            last = conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            row["prev_hash"] = last["hash"] if last else GENESIS
            row["hash"] = _hash(row)
            cols = ",".join(row)
            cur = conn.execute(f"INSERT INTO events ({cols}) VALUES ({','.join('?' * len(row))})", tuple(row.values()))
            return cur.lastrowid

    def events(self, after_id=0, limit=200, user_id=None):
        sql, args = "SELECT * FROM events WHERE id > ?", [after_id]
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        sql += " ORDER BY id LIMIT ?"
        args.append(limit)
        return self.store.query(sql, args)

    def verify(self) -> dict:
        rows = self.store.query("SELECT * FROM events ORDER BY id")
        prev = GENESIS
        for r in rows:
            if r["prev_hash"] != prev or _hash(r) != r["hash"]:
                return {"ok": False, "count": len(rows), "broken_at": r["id"]}
            prev = r["hash"]
        return {"ok": True, "count": len(rows), "head": prev}

    def export_jsonl(self):
        for r in self.store.query("SELECT * FROM events ORDER BY id"):
            yield json.dumps(r, ensure_ascii=False) + "\n"

    def counters(self):
        rows = self.store.query("SELECT action, COUNT(*) AS n FROM events WHERE stage = 'check' GROUP BY action")
        out = {"allow": 0, "ask": 0, "deny": 0, "kill": 0}
        out.update({r["action"]: r["n"] for r in rows if r["action"]})
        out["flags"] = (self.store.query("SELECT COUNT(*) AS n FROM flags WHERE status = 'open'", one=True) or {}).get("n", 0)
        return out

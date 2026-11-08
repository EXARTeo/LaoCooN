"""The Laocoon adapter for the AgentDojo suites (workspace, travel, banking, slack).

AgentDojo has one user per suite and no other accounts, so most of the adapter is the default: no references to
resolve, no ABAC constraints, no output filters. What it adds is authorship for the audit trail: rows of untrusted
results (mail, files, messages, transactions) name their author, and that author is reported as the source of
anything the classifier flags. The user is never treated as the author of trusted content: a file they own can be
shared for editing and an event they organise can carry someone else's description, so every untrusted field is
classified.
"""
from __future__ import annotations

from laocoon.adapters.base import BaseAdapter


class AgentDojoAdapter(BaseAdapter):
    def __init__(self, suite: str):
        self.suite = suite

    def principal(self, user) -> dict:
        return {"id": int(user["id"]), "username": user.get("username") or "user", "role": "user",
                "attrs": {"suite": self.suite}}

    def principal_by_id(self, uid):
        return None

    def authors_of(self, tool, args, result, spec):
        """Third-party authors of the rows in an untrusted result, for provenance (never the principal)."""
        if not isinstance(spec, dict) or "author_field" not in spec:
            return []
        rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
        kind, id_field, field = spec.get("ref", tool), spec.get("id_field", "id"), spec["author_field"]
        out = []
        for i, row in enumerate(rows):
            if not isinstance(row, dict) or not row.get(field):
                continue
            rid = row.get(id_field)
            ref = f"{kind}:{rid}" if rid is not None and not isinstance(rid, (dict, list)) else kind
            out.append({"id": f"ext:{row[field]}", "username": str(row[field]), "role": "external", "ref": ref})
        return out

    def preview(self, tool, args, principal):
        return {"title": tool, "rows": [[k, str(v)[:200]] for k, v in (args or {}).items()]}

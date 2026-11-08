"""What the core needs to know about a host application. Everything else is in the policy YAML."""
from __future__ import annotations

from typing import Any, Protocol


class _Unresolvable:
    """`resolve` could not decide: the adapter only sees part of the directory (seamless proxy). Different from None
    (searched everything, not found or ambiguous)."""

    def __repr__(self):
        return "UNRESOLVABLE"

    def __bool__(self):
        return False


UNRESOLVABLE = _Unresolvable()


class Adapter(Protocol):
    def principal(self, user) -> dict: ...                                   # {id, username, role, attrs}
    def principal_by_id(self, uid) -> dict | None: ...
    def resolve(self, kind: str, ref) -> int | None: ...                     # None = not found / ambiguous
    def constraint(self, name: str, principal: dict, value, args: dict) -> bool: ...
    def choices(self, constraint: str, principal: dict) -> list[str] | None: ...   # None = no closed answer
    def apply_filter(self, name: str, principal: dict, tool: str, result, args: dict) -> Any: ...
    def derive(self, name: str, args: dict) -> int | None: ...
    def authors_of(self, tool: str, args: dict, result, spec) -> list[dict]: ...
    def preview(self, tool: str, args: dict, principal: dict) -> dict: ...
    def subject_of(self, tool: str, args: dict, row: dict) -> int | None: ...   # private_data: whose data a row is


class BaseAdapter:
    """Sensible defaults; subclass and override what the app needs."""

    def principal(self, user) -> dict:
        return {"id": user["id"], "username": user.get("username"), "role": user.get("role"),
                "attrs": user.get("attrs") or {}}

    def principal_by_id(self, uid):
        return None

    def subject_of(self, tool, args, row):
        """private_data: the user a result row is about (unknown by default: such values count as someone else's)."""
        return None

    def principal_by_username(self, username):
        return None

    def resolve(self, kind, ref):
        try:
            return int(ref)
        except (TypeError, ValueError):
            return None

    def constraint(self, name, principal, value, args):
        if name == "self":
            return value is not None and int(value) == int(principal["id"])
        raise KeyError(f"unknown constraint {name!r}")

    def choices(self, constraint, principal):
        """The values that satisfy `constraint` for this principal, when that set is small and closed
        (e.g. the codes of the courses a student is enrolled in). The firewall offers them to the model as
        an enum; the constraint is still checked at call time. None = no closed answer."""
        return None

    def apply_filter(self, name, principal, tool, result, args):
        raise KeyError(f"unknown filter {name!r}")

    def catalog(self) -> dict:
        """The names a policy may use with this adapter, with short Greek labels, for the policy studio.
        `strict`: the lists are complete, so an unknown constraint or filter is an error (it would raise
        KeyError at call time); otherwise it is only a warning."""
        return {"strict": False,
                "constraints": {"self": {"label": "ο ίδιος ο συνδεδεμένος χρήστης", "value": "id"}},
                "filters": {}, "ref_kinds": {"user": "χρήστης"}, "untrusted_output": {}}

    def derive(self, name, args):
        return None

    def authors_of(self, tool, args, result, spec):
        """Generic: rows carry an author field (username or id)."""
        if not isinstance(spec, dict) or "author_field" not in spec:
            return []
        rows = result if isinstance(result, list) else (result.get("rows") if isinstance(result, dict) else None)
        out = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            who = row.get(spec["author_field"])
            p = self.principal_by_username(who) if isinstance(who, str) else self.principal_by_id(who)
            if p:
                out.append({**p, "ref": f"{spec.get('ref', tool)}:{row.get(spec.get('id_field', 'id'))}"})
        return out

    def preview(self, tool, args, principal):
        return {"title": tool, "rows": [[k, str(v)[:200]] for k, v in args.items()]}

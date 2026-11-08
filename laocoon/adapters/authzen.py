"""A generic adapter that asks an AuthZEN policy decision point (`LAOCOON_AUTHZ_SOURCE=authzen`; laocoon/authzen.py).

Laocoon keeps its own rules (roles, bound arguments, fields, approvals). The PDP answers the questions the rules
ask, through the policy's `authzen` mapping:
  - constraints     → Access Evaluation (all of a list in one batch when the PDP offers it);
  - the user's scope (scope enums, scope filters) → Resource Search;
  - references by name and labels → Resource Search with the kind's `search` action, using the results'
    `properties` (a PDP that returns none: ids only, no enums, cards show ids);
  - relations to users (who teaches a course) → Subject Search;
  - the identity block → an evaluation of the identity action with the claimed username and role.

Users have integer ids (the identity block and bound arguments compare them); other kinds may use string ids
(`id: string`, e.g. document-store ids). Whenever the PDP cannot answer, the decision fails closed: constraints and
references raise `Unverifiable` (deny, severity medium, no freeze), the identity check fails (401), scope enums are
left out and scope filters drop rows.
"""
from __future__ import annotations

import logging

from ..authzen import AuthzenClient, AuthzenConfig, AuthzenError, STRING_ID, client_from_env
from ..facts import Unverifiable
from ..views import as_id
from .base import UNRESOLVABLE, BaseAdapter

log = logging.getLogger("laocoon.authzen")


def _cf(s) -> str:
    return " ".join(str(s or "").casefold().split())


def _match(m, value, ref) -> bool:
    if value is None:
        return False
    v = str(value)
    if m == "exact":
        return v == ref
    if m == "iexact":
        return _cf(v) == _cf(ref)
    if m == "upper_nospace":
        return v == ref.upper().replace(" ", "")
    return _cf(ref) in _cf(v)                              # contains


class AuthzenAdapter(BaseAdapter):
    PURE_CONSTRAINTS: dict = {}
    fact_sourced = True                  # the policy passes the caller to resolve() and authors_of(): searches are
    #                                      always "what this subject may see"

    def __init__(self, client: AuthzenClient | None = None, config: AuthzenConfig | None = None, tool_names=(),
                 env=None):
        self.client, self.config, self.tool_names, self.env = client, config, list(tool_names), env

    # ------------------------------------------------------------------ set-up
    def configure(self, policy_data):
        if self.config is None:
            self.config = AuthzenConfig.from_policy(policy_data)
            if self.config is None:
                raise ValueError("LAOCOON_AUTHZ_SOURCE=authzen needs an authzen section in the policy")
        if self.client is None:
            from ..config import env
            self.client = client_from_env(self.env or env)

    def _ask(self, fn, *args, **kw):
        try:
            return fn(*args, **kw)
        except AuthzenError as e:
            log.warning("authzen: %s", e)
            raise Unverifiable(f"the policy decision point could not answer ({e})") from None

    def status(self) -> dict:
        c = self.client
        return {"source": c.describe(), "endpoints": sorted((c.endpoints or {}).keys()), "calls": c.calls,
                "errors": c.errors, "last_error": c.last_error, "missing_request_id": c.missing_request_id}

    # ------------------------------------------------------------------ the wire forms
    def _subject(self, principal, properties=True) -> dict:
        s = {"type": self.config.subject, "id": str(int(principal["id"]))}
        if properties:
            s["properties"] = {"username": principal.get("username"), "role": principal.get("role")}
        return s

    @staticmethod
    def _p(principal_or_id):
        return principal_or_id if isinstance(principal_or_id, dict) else {"id": int(principal_or_id)}

    def _oid(self, kind, value) -> str | None:
        """The resource id as the PDP knows it, or None for something that is not an id of that kind."""
        res = self.config.resources.get(kind)
        if res is not None and res.id == "string":
            s = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
            return s if STRING_ID.match(s) else None
        v = as_id(value)
        return None if v is None else str(v)

    def _native(self, kind, sid):
        res = self.config.resources.get(kind)
        return sid if res is not None and res.id == "string" else as_id(sid)

    # ------------------------------------------------------------------ identity
    def verify_identity(self, principal) -> bool:
        """The identity block of the system prompt, confirmed by the PDP: an evaluation of the identity action on
        the user's own record, with the claimed username and role. False without an identity action."""
        a = self.config.identity_action
        if not a:
            return False
        user = self.config.resources.get("user")
        resource = {"type": user.type if user else self.config.subject, "id": str(int(principal["id"]))}
        try:
            return bool(self._ask(self.client.evaluate, self._subject(principal), {"name": a}, resource))
        except Unverifiable:
            return False

    def principal_by_id(self, uid):
        return None                      # AuthZEN is not a directory: identities are confirmed, not looked up

    # ------------------------------------------------------------------ ① constraints
    def constraint(self, name, principal, value, args):
        if value is None:
            return False
        if name in self.PURE_CONSTRAINTS:
            return bool(self.PURE_CONSTRAINTS[name](value))
        if name == "self":
            v = as_id(value)
            return v is not None and v == int(principal["id"])
        chk = self.config.constraints.get(name)
        if chk is None:
            raise KeyError(f"unknown constraint {name!r}")
        oid = self._oid(chk.kind, value)
        if oid is None:
            return False
        resource = {"type": self.config.resources[chk.kind].type, "id": oid}
        return bool(self._ask(self.client.evaluate, self._subject(principal), {"name": chk.action}, resource))

    def all_of(self, names, principal, value) -> bool | None:
        """Several constraints on one value in one batch (None: not expressible as one batch)."""
        checks = [self.config.constraints.get(n) for n in names]
        if not checks or any(c is None for c in checks):
            return None
        items = []
        for c in checks:
            oid = self._oid(c.kind, value)
            if oid is None:
                return False
            items.append(({"name": c.action}, {"type": self.config.resources[c.kind].type, "id": oid}))
        return bool(self._ask(self.client.evaluate_all, self._subject(principal), items))

    # ------------------------------------------------------------------ scope (Resource Search)
    def _scope(self, name, principal) -> tuple:
        chk = self.config.constraints.get(name)
        if chk is None:
            raise KeyError(f"unknown constraint {name!r}")
        res = self.config.resources[chk.kind]
        return chk, res, self._ask(self.client.search_resources, self._subject(principal), {"name": chk.action},
                                   res.type)

    def scope_ids(self, name, principal) -> set:
        chk, _, results = self._scope(name, self._p(principal))
        out = {self._native(chk.kind, r["id"]) for r in results}
        return {x for x in out if x is not None}

    def scope_values(self, name, principal, prop) -> set:
        _, _, results = self._scope(name, self._p(principal))
        if any(r["properties"] is None or prop not in r["properties"] for r in results):
            raise Unverifiable(f"the PDP's results do not carry the property {prop!r}")
        return {r["properties"][prop] for r in results}

    def choices(self, constraint, principal):
        chk = self.config.constraints.get(constraint)
        res = self.config.resources.get(chk.kind) if chk else None
        if res is None or not res.enum:
            return None
        try:
            vals = self.scope_values(constraint, principal, res.enum)
        except (Unverifiable, KeyError):
            return None
        return sorted({str(v) for v in vals if v})

    # ------------------------------------------------------------------ references (the directory search)
    def _directory(self, kind, principal, hint) -> list | None:
        res = self.config.resources.get(kind)
        if res is None or not res.search:
            return None
        ctx = {"laocoon": {"reference": str(hint)[:128]}}
        return self._ask(self.client.search_resources, self._subject(principal), {"name": res.search}, res.type,
                         ctx)

    def resolve(self, kind, ref, principal=None, bound=False):
        if ref is None or (isinstance(ref, str) and not ref.strip()):
            return None
        s = str(ref).strip()
        if kind == "user" and principal is not None:
            name = (principal.get("attrs") or {}).get("full_name")
            if s == str(principal["id"]) or s == principal.get("username") or (name and _cf(s) == _cf(name)):
                return int(principal["id"])
            if bound:
                return UNRESOLVABLE      # an identity argument is never looked up: it is the user, or denied
        res = self.config.resources.get(kind)
        if res is None:
            return super().resolve(kind, ref)
        if principal is None:
            return UNRESOLVABLE
        # an id: integer kinds take digits (any number form when the kind has no name tiers); string kinds
        # without name tiers take the reference as their id
        if (res.id == "int" and (s.isdigit() or not res.refs)) or (res.id == "string" and not res.refs):
            oid = self._oid(kind, s)
            return None if oid is None else self._existing(kind, principal, oid)
        results = self._directory(kind, principal, s)
        if res.id == "string" and any(r["id"] == s for r in results):
            return s
        for tier in res.refs:            # unique match, ambiguous → None (deny), never "the first"
            hits = {r["id"] for r in results if r["properties"] and any(
                _match(m, r["properties"].get(p), s) for p, m in tier.items())}
            if len(hits) == 1:
                return self._native(kind, hits.pop())
            if hits:
                return None
        return None

    def _existing(self, kind, principal, oid):
        """An id, checked against the directory when the kind has one; without one it goes on as written and the
        constraints decide."""
        if not self.config.resources[kind].search:
            return self._native(kind, oid)
        found = self._directory(kind, principal, oid)
        return self._native(kind, oid) if any(r["id"] == oid for r in found) else None

    def label(self, kind, oid, principal) -> str:
        res = self.config.resources.get(kind)
        if res is None or not res.label or principal is None or oid is None:
            return str(oid)
        try:
            found = self._directory(kind, principal, oid) or []
        except Unverifiable:
            return str(oid)
        for r in found:
            if r["id"] == str(oid) and r["properties"]:
                try:
                    return res.label.format(**{k: ("" if v is None else v) for k, v in r["properties"].items()})
                except (KeyError, IndexError, ValueError):
                    break
        return str(oid)

    def properties(self, kind, oid, principal) -> dict | None:
        if principal is None or oid is None:
            return None
        try:
            found = self._directory(kind, principal, oid) or []
        except Unverifiable:
            return None
        return next((r["properties"] for r in found if r["id"] == str(oid) and r["properties"]), None)

    # ------------------------------------------------------------------ relations to users (Subject Search)
    def follow(self, key, oid) -> list:
        rel = self.config.relations.get(key)
        if rel is None:
            return []
        rid = self._oid(rel.kind, oid)
        if rid is None:
            return []
        resource = {"type": self.config.resources[rel.kind].type, "id": rid}
        found = self._ask(self.client.search_subjects, self.config.subject, {"name": rel.action}, resource)
        return [x for x in (as_id(r["id"]) for r in found) if x is not None]

    def derive(self, name, args, principal=None):
        spec = self.config.derive.get(name)
        if spec is None:
            return None
        arg, key = spec
        try:
            ids = self.follow(key, (args or {}).get(arg))
        except Unverifiable:
            return None
        return ids[0] if len(ids) == 1 else None

    # ------------------------------------------------------------------ ② who wrote what was read
    def _author(self, who, principal) -> dict | None:
        """An author named in a result, found in the user directory by exact username or id (never a partial
        match). None when the directory does not know them."""
        res = self.config.resources.get("user")
        if res is None or not res.search:
            return None
        try:
            found = self._directory("user", principal, who) or []
        except Unverifiable:
            return None
        s = str(who)
        hits = [r for r in found if r["id"] == s or (r["properties"] or {}).get("username") == s]
        if len(hits) != 1 or as_id(hits[0]["id"]) is None:
            return None
        props = hits[0]["properties"] or {}
        return {"id": as_id(hits[0]["id"]), "username": props.get("username"), "role": props.get("role")}

    def authors_of(self, tool, args, result, spec, principal=None):
        """The caller's own rows are recognised by their username or id; other authors are attributed through the
        user directory when it knows them exactly, otherwise left unattributed (never guessed). Either way their
        content stays untrusted."""
        if not isinstance(spec, dict) or "author_field" not in spec or principal is None:
            return []
        rows = result if isinstance(result, list) else (result.get("rows") if isinstance(result, dict) else None)
        out, seen = [], {}
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            who = row.get(spec["author_field"])
            ref = f"{spec.get('ref', tool)}:{row.get(spec.get('id_field', 'id'))}"
            if who is None:
                continue
            if who == principal.get("username") or (as_id(who) is not None and as_id(who) == int(principal["id"])):
                out.append({"id": int(principal["id"]), "username": principal.get("username"),
                            "role": principal.get("role"), "ref": ref})
                continue
            key = str(who)
            if key not in seen:
                seen[key] = self._author(who, principal)
            a = seen[key]
            out.append({**a, "ref": ref} if a else
                       {"id": None, "username": None, "role": None, "handle": key[:64], "ref": ref})
        return out

    def catalog(self) -> dict:
        cat = super().catalog()
        if self.config is not None:
            cons = dict(cat.get("constraints") or {})
            for name, chk in self.config.constraints.items():
                cons.setdefault(name, {"label": f"{chk.action} on {chk.kind}", "value": "id"})
            known = set(self.config.constraints) | set(self.PURE_CONSTRAINTS) | {"self"}
            cat["constraints"] = {k: v for k, v in cons.items() if k in known}
            labels = cat.get("ref_kinds") or {}
            cat["ref_kinds"] = {k: labels.get(k, k) for k in self.config.resources}
            cat["strict"] = True
        return cat

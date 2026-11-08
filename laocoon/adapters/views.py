"""A generic adapter over the policy's `data_model`, read live through views (`LAOCOON_AUTHZ_SOURCE=views`).

It knows the views' naming convention (laocoon/views.py), never the app's tables: every constraint, reference,
scope enum and label is compiled from the model. App-specific vocabulary (result filters, approval cards) stays
in the app's adapter, which subclasses this one (adapters/eclass_views.py).

Failing closed: when the database cannot answer (unreachable, a view missing after a migration, a read refused),
constraints and references raise `Unverifiable`, which the gate turns into a deny at severity medium (an outage
never freezes a user); identity checks return None (401); scope enums are left out; filters drop rows.
"""
from __future__ import annotations

import logging
import threading
import time

from ..facts import Unverifiable
from ..views import Compiler, DataModel, Denied, as_id, connect_from_env
from .base import BaseAdapter

log = logging.getLogger("laocoon.views")
MISSING = object()                                     # a preview view that was not granted


class ViewsAdapter(BaseAdapter):
    PURE_CONSTRAINTS: dict = {}                        # name -> fn(value): constraints on the value itself (no data)

    def __init__(self, db=None, model: DataModel | None = None, tool_names=(), env=None):
        self.db, self.model, self.tool_names = db, model, list(tool_names)
        self.env = env
        self.c: Compiler | None = None
        self.errors, self.last_error = 0, None
        self._paths, self._have, self._lock = {}, None, threading.Lock()
        if model is not None and db is not None:
            self._bind()

    # ------------------------------------------------------------------ set-up
    def configure(self, policy_data):
        """Called by the Guard with the loaded policy: the model comes from its `data_model` section."""
        if self.model is None:
            self.model = DataModel.from_policy(policy_data)
            if self.model is None:
                raise ValueError("LAOCOON_AUTHZ_SOURCE=views needs a data_model section in the policy")
        if self.db is None:
            from ..config import env
            self.db = connect_from_env(self.model, env=self.env or env)
        self._bind()

    def _bind(self):
        self.c = Compiler(self.model, self.db.dialect, self.db.ns)
        self.functions = bool(getattr(self.db, "functions", False))

    def _q(self, sql, args=(), one=False):
        try:
            return self.db.query(sql, args, one=one)
        except Exception as e:                                  # unreachable, refused, a view missing: fail closed
            with self._lock:
                self.errors += 1
                self.last_error = (time.time(), f"{type(e).__name__}: {e}"[:300])
            log.warning("views: %s: %s", type(e).__name__, e)
            raise Unverifiable(f"the database could not answer ({type(e).__name__})") from None

    def available(self) -> dict:
        """{view: {columns}} the login can read (cached; None when the database cannot say)."""
        if self._have is None:
            try:
                self._have = self.db.available()
            except Exception as e:
                log.warning("views: cannot list the views: %s", e)
                return {}
        return self._have

    def status(self) -> dict:
        """What the login can read, against what the model needs: for the console and `views check`."""
        have, need = self.available(), self.model.required(functions=self.functions)
        missing = {v: sorted(cols - have.get(v, set())) for v, cols in need.items() if not cols <= have.get(v, set())}
        if self.functions and callable(getattr(self.db, "routines", None)):
            try:
                routines = self.db.routines()
            except Exception:
                routines = set()
            for name in self.model.constraints:
                if f"can_{name}" not in routines:
                    missing[f"can_{name}()"] = []
        return {"source": self.db.describe(), "views": sorted(have), "missing": missing,
                "previews": sorted(p.view for p in self.model.previews.values() if p.view in have),
                "errors": self.errors, "last_error": self.last_error,
                "denials": getattr(self.db, "denials", None)}

    def _path(self, text):
        p = self._paths.get(text)
        if p is None:
            p = self._paths[text] = self.model.path(text, ["(adapter)"], follow=True)
        return p

    # ------------------------------------------------------------------ identity
    def _principal_from_row(self, r):
        attrs = {"full_name": r.get("name")} if "name" in r else {}
        return {"id": int(r["id"]), "username": r["username"], "role": r["role"], "attrs": attrs}

    def principal_by_id(self, uid):
        uid = as_id(uid)
        if uid is None:
            return None
        try:
            r = self._q(self.c.get(self.model.principal), (uid,), one=True)
        except Unverifiable:
            return None
        return self._principal_from_row(r) if r else None

    def principal_by_username(self, username):
        try:
            r = self._q(self.c.get(self.model.principal, by="username"), (str(username),), one=True)
        except Unverifiable:
            return None
        return self._principal_from_row(r) if r else None

    # ------------------------------------------------------------------ references -> ids
    def _exists(self, kind, oid):
        if oid is None:
            return None
        r = self._q(self.c.get(kind), (oid,), one=True)
        return int(r["id"]) if r else None

    def resolve(self, kind, ref):
        if ref is None or (isinstance(ref, str) and not ref.strip()):
            return None
        o = self.model.objects.get(kind)
        if o is None:
            return super().resolve(kind, ref)
        s = str(ref).strip()
        if not o.refs:                                       # ids only
            return self._exists(kind, as_id(s))
        if s.isdigit():
            return self._exists(kind, as_id(s))
        for tier in o.refs:                                  # unique match, ambiguous → None (deny), never "first"
            sql, conv = self.c.find(kind, tier)
            rows = self._q(sql, tuple(f(s) for f in conv))
            if len(rows) == 1:
                return int(rows[0]["id"])
            if rows:
                return None
        return None

    # ------------------------------------------------------------------ ① ABAC constraints
    def _term(self, name, path, v, uid):
        if path.field is None:
            sql, _ = self.c.check(path)
            ok = bool(self._q(sql, (v, uid), one=True))
        else:
            sql, _ = self.c.check(path)
            ok = any(bool(r["v"]) for r in self._q(sql, (v,)))
        return not ok if path.negate else ok

    def constraint(self, name, principal, value, args):
        uid = principal["id"]
        if value is None:
            return False
        if name in self.PURE_CONSTRAINTS:
            return bool(self.PURE_CONSTRAINTS[name](value))
        v = as_id(value)
        if v is None:
            return False
        if name == "self":
            return v == int(uid)
        paths = self.model.constraints.get(name)
        if paths is None:
            raise KeyError(f"unknown constraint {name!r}")
        if self.functions:                                   # the database answers yes or no, nothing else
            q = self.c.d.q
            args_sql = "?, ?" if any(p.field is None for p in paths) else "?"
            params = (v, int(uid)) if args_sql == "?, ?" else (v,)
            r = self._q(f"SELECT {q(self.c.ns)}.{q('can_' + name)}({args_sql}) AS ok", params, one=True)
            return bool(r and r["ok"])
        return all(self._term(name, p, v, int(uid)) for p in paths)

    def scope_ids(self, name, uid) -> set:
        """The ids of the objects for which constraint `name` holds for this user (a single positive path)."""
        p = self.model.scoped(name)
        if p is None:
            raise KeyError(f"constraint {name!r} has no listable scope")
        if self.functions:
            q = self.c.d.q
            sql = f"SELECT id AS v FROM {q(self.c.ns)}.{q('scope_' + name)}(?)"
        else:
            sql = self.c.scope(p)
        return {int(r["v"]) for r in self._q(sql, (int(uid),)) if r["v"] is not None}

    def scope_values(self, name, uid, field_name) -> set:
        p = self.model.scoped(name)
        if p is None:
            raise KeyError(f"constraint {name!r} has no listable scope")
        if self.functions:
            ids = self.scope_ids(name, uid)
            o = self.model.objects[p.start]
            if not ids:
                return set()
            q = self.c.d.q
            sql = (f"SELECT {q(field_name)} AS v FROM {self.c.v(o.view)} WHERE {q('id')} IN "
                   f"({', '.join('?' for _ in ids)})")
            return {r["v"] for r in self._q(sql, tuple(sorted(ids)))}
        return {r["v"] for r in self._q(self.c.scope(p, label=field_name), (int(uid),))}

    def choices(self, constraint, principal):
        """The enum field (e.g. course codes) of the objects in the user's scope, offered to the model."""
        p = self.model.scoped(constraint)
        if p is None:
            return None
        o = self.model.objects[p.start]
        if not o.enum:
            return None
        try:
            vals = self.scope_values(constraint, principal["id"], o.enum)
        except Unverifiable:
            return None
        return sorted({str(v) for v in vals if v})

    def derive(self, name, args):
        spec = self.model.derive.get(name)
        if spec is None:
            return None
        arg, path = spec
        v = as_id((args or {}).get(arg))
        if v is None:
            return None
        try:
            if self.functions:
                q = self.c.d.q
                r = self._q(f"SELECT {q(self.c.ns)}.{q('derive_' + name)}(?) AS v", (v,), one=True)
                return int(r["v"]) if r and r["v"] is not None else None
            rows = self._q(self.c.follow(path), (v,))
        except Unverifiable:
            return None
        return int(rows[0]["v"]) if len(rows) == 1 and rows[0]["v"] is not None else None

    # ------------------------------------------------------------------ helpers for app adapters
    def follow(self, text, oid) -> list:
        """The ids reached from object `oid` along a relation path ("submission.student"). Not offered in the
        yes/no variant (the login cannot read relations): [] there."""
        oid = as_id(oid)
        if oid is None or self.functions:
            return []
        return [int(r["v"]) for r in self._q(self.c.follow(self._path(text)), (oid,)) if r["v"] is not None]

    def fields(self, kind, oid) -> dict | None:
        oid = as_id(oid)
        if oid is None:
            return None
        return self._q(self.c.get(kind), (oid,), one=True)

    def label(self, kind, oid) -> str:
        o = self.model.objects.get(kind)
        try:
            r = self.fields(kind, oid) if o is not None and o.label else None
        except Unverifiable:
            r = None
        return o.label.format(**{k: ("" if v is None else v) for k, v in r.items()}) if r else str(oid)

    def before(self, name, **keys):
        """A before-value for an approval card (prev_<name>), None when there is none, MISSING when the customer
        did not grant that view."""
        p = self.model.previews.get(name)
        if p is None or (self.available() and p.view not in self.available()):
            return MISSING
        sql, order = self.c.before(name)
        try:
            r = self._q(sql, tuple(keys.get(k) for k in order), one=True)
        except Unverifiable:
            return MISSING
        return r["v"] if r else None

    def catalog(self) -> dict:
        cat = super().catalog()
        if self.model is not None:
            cons = dict(cat.get("constraints") or {})
            for name, paths in self.model.constraints.items():
                cons.setdefault(name, {"label": " ∧ ".join(p.text for p in paths), "value": "id"})
            known = set(self.model.constraints) | set(self.PURE_CONSTRAINTS) | {"self"}
            cat["constraints"] = {k: v for k, v in cons.items() if k in known}
            labels = cat.get("ref_kinds") or {}
            cat["ref_kinds"] = {k: labels.get(k, k) for k in self.model.objects}
            cat["strict"] = True                         # the model's names are the complete list
        return cat


__all__ = ["ViewsAdapter", "MISSING", "Denied"]

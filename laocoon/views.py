"""Authorisation facts read live through views (`LAOCOON_AUTHZ_SOURCE=views`).

The customer's database administrator gives Laocoon a login that can read only a few views: one per object kind
(ids, names, codes, state) and one per relation (pairs of ids). The database enforces that limit; Laocoon asks it
live for every check, so a change made in the app applies to the next call. No sync, no tool calls, no app code.

The policy's `data_model` section says which tables and columns the views expose and what each constraint of
`tools.*.allow` means as a path over them (`taught_submission: submission.assignment.course.teacher`). This module
  - validates that model (`DataModel`),
  - writes the script the administrator reviews and runs (`setup_sql`: PostgreSQL, MySQL; `--functions` for the
    stricter variant where the login may only call yes/no functions),
  - compiles paths into joins over the views (`Compiler`), knowing only the views' naming convention, never the
    app's tables,
  - and connects (`SqliteViews`, `PostgresViews`).

View naming convention (what the compiler relies on):
    obj_<kind>(id, <field>...)              one row per object
    rel_<kind>_<name>(<kind>_id, <name>_id) one row per related pair; a `reverse` relation reads the same view
    prev_<name>(<key>_id..., value)         optional: before-values for approval cards (personal data)

SQLite has no permissions. `SqliteViews` opens the app's file read-only, creates the views as TEMP views in its own
connection (the file is not modified) and installs an authorizer that refuses every read not made through one of
them. That is Laocoon restraining itself, visibly, not the database stopping it. A real boundary on SQLite needs a
separate file holding only the views' rows (`export`), which lags by the copy interval.

CLI:  python -m laocoon.views sql [--dialect postgres|mysql|sqlite] [--previews] [--functions] [--policy P]
      python -m laocoon.views check (--db app.db | --dsn postgresql://…)      what the login can read
      python -m laocoon.views export --db app.db --out views.db [--every 5]   SQLite: a real boundary, slightly stale
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")      # tables and columns of the app
NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")             # kinds, relations, fields, constraints of the model
MATCHES = ("exact", "iexact", "contains", "upper_nospace")
DIALECTS = ("sqlite", "postgres", "mysql")


class ModelError(ValueError):
    def __init__(self, path, message):
        super().__init__(f"data_model.{'.'.join(str(p) for p in path)}: {message}" if path else message)
        self.path, self.message = list(path), message


def as_id(s) -> int | None:
    """An object id written by the model: a non-negative integer below 2**53, else None (`1e999`, `nan` or a
    25-digit number is "not found", never an exception)."""
    try:
        v = int(s) if isinstance(s, int) and not isinstance(s, bool) else int(float(str(s).strip()))
    except (TypeError, ValueError, OverflowError):
        return None
    return v if 0 <= v < 2 ** 53 else None


# ---------------------------------------------------------------------------------------------- the model
@dataclass
class Obj:
    kind: str
    table: str
    id_col: str = "id"
    fields: dict = field(default_factory=dict)          # model field -> app column
    refs: list = field(default_factory=list)            # [{field: match}], tiers in order
    label: str | None = None                            # "{name} ({username})"
    enum: str | None = None                             # the field offered to the model as an enum of the scope

    @property
    def view(self):
        return f"obj_{self.kind}"


@dataclass
class Rel:
    kind: str                                           # source kind
    name: str
    target: str                                         # target kind
    table: str | None = None
    src: str | None = None                              # app column holding the source id
    dst: str | None = None                              # app column holding the target id
    reverse_of: tuple | None = None                     # (kind, name) of the forward relation

    @property
    def view(self):
        k, n = self.reverse_of or (self.kind, self.name)
        return f"rel_{k}_{n}"

    @property
    def columns(self):
        """(column holding the source id, column holding the target id) in the view."""
        k, n = self.reverse_of or (self.kind, self.name)
        fwd = (f"{k}_id", f"{n}_id")
        return (fwd[1], fwd[0]) if self.reverse_of else fwd


@dataclass
class Path:
    text: str
    start: str                                          # kind of the argument's object
    hops: list                                          # [Rel]
    end: str                                            # kind reached by the last hop (start when no hops)
    field: str | None = None                            # terminal field of `end` (truthy test)
    negate: bool = False

    @property
    def to_principal(self):
        return self.field is None and bool(self.hops)


@dataclass
class Preview:
    name: str
    table: str
    keys: dict                                          # key name -> app column
    value: str

    @property
    def view(self):
        return f"prev_{self.name}"


class DataModel:
    def __init__(self, principal, objects, relations, constraints, derive, previews):
        self.principal = principal
        self.objects: dict[str, Obj] = objects
        self.relations: dict[tuple, Rel] = relations
        self.constraints: dict[str, list[Path]] = constraints
        self.derive: dict[str, tuple] = derive           # name -> (arg, Path)
        self.previews: dict[str, Preview] = previews

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_policy(cls, policy_data) -> "DataModel | None":
        dm = (policy_data or {}).get("data_model")
        return None if dm is None else cls.parse(dm)

    @classmethod
    def parse(cls, dm) -> "DataModel":
        if not isinstance(dm, dict):
            raise ModelError([], "data_model must be a mapping {principal, objects, relations, constraints, ...}")
        for k in dm:
            if k not in ("principal", "objects", "relations", "constraints", "derive", "previews"):
                raise ModelError([k], "unknown key (principal, objects, relations, constraints, derive, previews)")
        objects = {}
        for kind, spec in _mapping(dm.get("objects"), ["objects"]).items():
            objects[kind] = _obj(kind, spec)
        principal = dm.get("principal", "user")
        if principal not in objects:
            raise ModelError(["principal"], f"the principal kind {principal!r} is not an object")
        for need in ("username", "role"):
            if need not in objects[principal].fields:
                raise ModelError(["objects", principal, "fields"], f"the principal needs a field {need!r}")
        relations = {}
        raw = _mapping(dm.get("relations"), ["relations"])
        for key, spec in raw.items():                    # forward relations first, then reverses
            if not (isinstance(spec, dict) and "reverse" in spec):
                kind, name = _relkey(key, objects)
                relations[(kind, name)] = _rel(kind, name, spec, objects)
        for key, spec in raw.items():
            if isinstance(spec, dict) and "reverse" in spec:
                kind, name = _relkey(key, objects)
                if set(spec) != {"reverse"}:
                    raise ModelError(["relations", key], "a reverse relation has only `reverse`")
                fk, fn = _relkey(str(spec["reverse"]), objects, ["relations", key, "reverse"])
                fwd = relations.get((fk, fn))
                if fwd is None or fwd.reverse_of:
                    raise ModelError(["relations", key, "reverse"], f"{spec['reverse']!r} is not a forward relation")
                if fwd.target != kind:
                    raise ModelError(["relations", key], f"{spec['reverse']} leads to {fwd.target}, not {kind}")
                relations[(kind, name)] = Rel(kind, name, fk, reverse_of=(fk, fn))
        model = cls(principal, objects, relations, {}, {}, {})
        for name, spec in _mapping(dm.get("constraints"), ["constraints"]).items():
            if not NAME.match(str(name)):
                raise ModelError(["constraints", name], "not a valid name")
            terms = spec if isinstance(spec, list) else [spec]
            if not terms:
                raise ModelError(["constraints", name], "empty")
            paths = [model.path(t, ["constraints", name]) for t in terms]
            for p in paths:
                if p.field is None and p.end != principal:
                    raise ModelError(["constraints", name], f"{p.text!r} must end at the {principal} or at a field")
            model.constraints[name] = paths
        for name, spec in _mapping(dm.get("derive"), ["derive"]).items():
            if not (isinstance(spec, dict) and isinstance(spec.get("arg"), str) and isinstance(spec.get("path"), str)):
                raise ModelError(["derive", name], "needs {arg, path}")
            p = model.path(spec["path"], ["derive", name], follow=True)
            model.derive[name] = (spec["arg"], p)
        for name, spec in _mapping(dm.get("previews"), ["previews"]).items():
            model.previews[name] = _preview(name, spec)
        return model

    def path(self, text, where, follow=False) -> Path:
        """`kind.rel.rel[.field]`, `not ...`. follow=True: a path that only follows relations (derive, labels)."""
        if not isinstance(text, str) or not text.strip():
            raise ModelError(where, "a path is a string like course.teacher")
        s, negate = text.strip(), False
        if s.startswith("not "):
            if follow:
                raise ModelError(where, "`not` only in constraints")
            s, negate = s[4:].strip(), True
        parts = s.split(".")
        if parts[0] not in self.objects:
            raise ModelError(where, f"{text!r}: {parts[0]!r} is not an object kind")
        cur, hops, fld = parts[0], [], None
        for i, part in enumerate(parts[1:], 1):
            rel = self.relations.get((cur, part))
            if rel is not None:
                hops.append(rel)
                cur = rel.target
            elif part in self.objects[cur].fields and i == len(parts) - 1 and not follow:
                fld = part
            else:
                raise ModelError(where, f"{text!r}: {cur} has no relation {part!r}"
                                 + ("" if follow else " (nor a field, which can only come last)"))
        if follow and not hops:
            raise ModelError(where, f"{text!r} follows no relation")
        if not hops and fld is None:
            raise ModelError(where, f"{text!r} says nothing about the object")
        return Path(text.strip(), parts[0], hops, cur, fld, negate)

    # ------------------------------------------------------------------ views
    def views(self, previews=True) -> list:
        """[(view, table, [(view column, app column)], tier)] in a stable order."""
        out = []
        for o in self.objects.values():
            out.append((o.view, o.table, [("id", o.id_col)] + [(f, c) for f, c in o.fields.items()], "object"))
        for r in self.relations.values():
            if not r.reverse_of:
                a, b = r.columns
                out.append((r.view, r.table, [(a, r.src), (b, r.dst)], "relation"))
        if previews:
            for p in self.previews.values():
                out.append((p.view, p.table, [(f"{k}_id", c) for k, c in p.keys.items()] + [("value", p.value)],
                            "preview"))
        return out

    def required(self, functions=False) -> dict:
        """{view: {columns}} the compiler needs (previews are optional; with functions, relations are not read)."""
        return {v: {c for c, _ in cols} for v, _, cols, tier in self.views(previews=False)
                if not (functions and tier == "relation")}

    def scoped(self, name) -> Path | None:
        """The one path of a constraint whose set of objects can be listed for a user (scope, enum), or None."""
        paths = self.constraints.get(name) or []
        if len(paths) == 1 and paths[0].to_principal and not paths[0].negate:
            return paths[0]
        return None


def _mapping(v, where) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ModelError(where, "must be a mapping")
    return v


def _ident(v, where, what="column"):
    if not isinstance(v, str) or not IDENT.match(v):
        raise ModelError(where, f"{v!r} is not a valid {what} name")
    return v


def _obj(kind, spec) -> Obj:
    where = ["objects", kind]
    if not NAME.match(str(kind)):
        raise ModelError(where, "not a valid kind name")
    if not isinstance(spec, dict):
        raise ModelError(where, "needs {table, fields, ...}")
    for k in spec:
        if k not in ("table", "id", "fields", "refs", "label", "enum"):
            raise ModelError(where + [k], "unknown key (table, id, fields, refs, label, enum)")
    fields = {}
    for f, col in _mapping(spec.get("fields"), where + ["fields"]).items():
        if not NAME.match(str(f)) or f == "id":
            raise ModelError(where + ["fields", f], "not a valid field name")
        fields[f] = _ident(col, where + ["fields", f])
    refs = spec.get("refs") or []
    if not isinstance(refs, list) or not all(isinstance(t, dict) and t for t in refs):
        raise ModelError(where + ["refs"], "a list of tiers {field: exact|iexact|contains|upper_nospace}")
    for i, tier in enumerate(refs):
        for f, m in tier.items():
            if f not in fields:
                raise ModelError(where + ["refs", i, f], f"{kind} has no field {f!r}")
            if m not in MATCHES:
                raise ModelError(where + ["refs", i, f], f"match is one of {', '.join(MATCHES)}")
    label = spec.get("label")
    if label is not None:
        names = re.findall(r"\{([a-z_][a-z0-9_]*)\}", str(label))
        if not names or any(n not in fields for n in names):
            raise ModelError(where + ["label"], "a format of the object's fields, e.g. \"{code} {title}\"")
    enum = spec.get("enum")
    if enum is not None and enum not in fields:
        raise ModelError(where + ["enum"], f"{kind} has no field {enum!r}")
    return Obj(kind, _ident(spec.get("table"), where + ["table"], "table"),
               _ident(spec.get("id", "id"), where + ["id"]), fields, list(refs), label, enum)


def _relkey(key, objects, where=None):
    where = where or ["relations", key]
    parts = str(key).split(".")
    if len(parts) != 2 or not all(NAME.match(p) for p in parts):
        raise ModelError(where, "a relation is named kind.name")
    if parts[0] not in objects:
        raise ModelError(where, f"{parts[0]!r} is not an object kind")
    if parts[0] == parts[1]:
        raise ModelError(where, "a relation cannot be named after its own kind")
    return parts[0], parts[1]


def _rel(kind, name, spec, objects) -> Rel:
    where = ["relations", f"{kind}.{name}"]
    if not isinstance(spec, dict):
        raise ModelError(where, "needs {table, from, to, target}")
    for k in spec:
        if k not in ("table", "from", "to", "target"):
            raise ModelError(where + [k], "unknown key (table, from, to, target; or reverse)")
    target = spec.get("target")
    if target not in objects:
        raise ModelError(where + ["target"], f"{target!r} is not an object kind")
    return Rel(kind, name, target, _ident(spec.get("table"), where + ["table"], "table"),
               _ident(spec.get("from"), where + ["from"]), _ident(spec.get("to"), where + ["to"]))


def _preview(name, spec) -> Preview:
    where = ["previews", name]
    if not NAME.match(str(name)) or not isinstance(spec, dict):
        raise ModelError(where, "needs {table, key: {name: column}, value}")
    keys = _mapping(spec.get("key"), where + ["key"])
    if not keys or not all(NAME.match(str(k)) for k in keys):
        raise ModelError(where + ["key"], "at least one {name: column}")
    return Preview(name, _ident(spec.get("table"), where + ["table"], "table"),
                   {k: _ident(c, where + ["key", k]) for k, c in keys.items()}, _ident(spec.get("value"), where + ["value"]))


# ---------------------------------------------------------------------------------------------- dialects
class Dialect:
    name = "sqlite"
    ilike = "LIKE"                                      # SQLite's LIKE ignores ASCII case

    def q(self, ident):
        return '"' + ident + '"'


class Postgres(Dialect):
    name = "postgres"
    ilike = "ILIKE"


class Mysql(Dialect):
    name = "mysql"
    ilike = "LIKE"                                      # case-insensitive under the usual *_ci collations

    def q(self, ident):
        return "`" + ident + "`"


def dialect(name) -> Dialect:
    try:
        return {"sqlite": Dialect, "postgres": Postgres, "postgresql": Postgres, "mysql": Mysql,
                "mariadb": Mysql}[name]()
    except KeyError:
        raise ValueError(f"unknown dialect {name!r} ({', '.join(DIALECTS)})") from None


def like_pattern(s) -> str:
    """%s% with the reference's own wildcards escaped (ESCAPE '!' is the same in every dialect)."""
    return "%" + re.sub(r"([!%_])", r"!\1", s) + "%"


# ---------------------------------------------------------------------------------------------- the compiler
class Compiler:
    """Paths → SQL over the views. `ns` is the views' namespace as the runtime sees it (`temp` for SQLite's TEMP
    views, the schema elsewhere). Placeholders are `?`; the connector converts them."""

    def __init__(self, model: DataModel, d: Dialect, ns: str):
        self.m, self.d, self.ns = model, d, ns

    def v(self, view):
        return f"{self.d.q(self.ns)}.{self.d.q(view)}" if self.ns else self.d.q(view)

    def _chain(self, path: Path):
        """FROM ... JOIN ..., the expression of the start object's id, the expression of the end object's id."""
        q = self.d.q
        if not path.hops:
            o = self.m.objects[path.start]
            return f"{self.v(o.view)} o0", f"o0.{q('id')}", f"o0.{q('id')}"
        sql, prev = [], None
        for i, hop in enumerate(path.hops):
            src, dst = hop.columns
            a = f"r{i}"
            if i == 0:
                sql.append(f"{self.v(hop.view)} {a}")
                start = f"{a}.{q(src)}"
            else:
                sql.append(f"JOIN {self.v(hop.view)} {a} ON {a}.{q(src)} = {prev}")
            prev = f"{a}.{q(dst)}"
        return " ".join(sql), start, prev

    def check(self, path: Path):
        """SQL with two parameters (object id, user id) for a principal path, one (object id) for a field path."""
        frm, start, end = self._chain(path)
        if path.field is None:
            return f"SELECT 1 AS ok FROM {frm} WHERE {start} = ? AND {end} = ? LIMIT 1", 2
        o = self.m.objects[path.end]
        if path.hops:
            frm = f"{frm} JOIN {self.v(o.view)} t ON t.{self.d.q('id')} = {end}"
            col = f"t.{self.d.q(path.field)}"
        else:
            col = f"o0.{self.d.q(path.field)}"
        return f"SELECT {col} AS v FROM {frm} WHERE {start} = ?", 1

    def scope(self, path: Path, label=None):
        """The ids (or the `label` field) of the objects from which the path reaches the user: one parameter."""
        frm, start, end = self._chain(path)
        if label is None:
            return f"SELECT DISTINCT {start} AS v FROM {frm} WHERE {end} = ?"
        o = self.m.objects[path.start]
        return (f"SELECT DISTINCT s.{self.d.q(label)} AS v FROM {frm} JOIN {self.v(o.view)} s "
                f"ON s.{self.d.q('id')} = {start} WHERE {end} = ?")

    def follow(self, path: Path):
        frm, start, end = self._chain(path)
        return f"SELECT DISTINCT {end} AS v FROM {frm} WHERE {start} = ?"

    def get(self, kind, by="id"):
        o = self.m.objects[kind]
        cols = ", ".join(self.d.q(c) for c in ["id"] + list(o.fields))
        return f"SELECT {cols} FROM {self.v(o.view)} WHERE {self.d.q(by)} = ? LIMIT 2"

    def find(self, kind, tier):
        """One tier of a reference by name: (SQL, how to turn the reference into each parameter)."""
        o, q = self.m.objects[kind], self.d.q
        conds, conv = [], []
        for f, m in tier.items():
            if m == "exact":
                conds.append(f"{q(f)} = ?")
                conv.append(lambda s: s)
            elif m == "upper_nospace":
                conds.append(f"{q(f)} = ?")
                conv.append(lambda s: s.upper().replace(" ", ""))
            elif m == "iexact":
                conds.append(f"lower({q(f)}) = lower(?)")
                conv.append(lambda s: s)
            else:
                conds.append(f"{q(f)} {self.d.ilike} ? ESCAPE '!'")
                conv.append(like_pattern)
        return f"SELECT {q('id')} FROM {self.v(o.view)} WHERE " + " OR ".join(conds) + " LIMIT 2", conv

    def before(self, name):
        p = self.m.previews[name]
        where = " AND ".join(f"{self.d.q(k + '_id')} = ?" for k in p.keys)
        return f"SELECT {self.d.q('value')} AS v FROM {self.v(p.view)} WHERE {where}", list(p.keys)


# ---------------------------------------------------------------------------------------------- setup scripts
def setup_sql(model: DataModel, dialect_name="postgres", *, schema="laocoon", role="laocoon", app_schema=None,
              previews=False, functions=False, source="the policy's data_model") -> str:
    """The script the database administrator reviews and runs once (and again after migrations that touch these
    columns). `functions`: the login gets EXECUTE on yes/no functions instead of SELECT on the relation views."""
    d = dialect(dialect_name)
    if d.name == "sqlite":
        return _sqlite_sql(model, previews)
    if functions and d.name != "postgres":
        raise ValueError("--functions is written for PostgreSQL only")
    app_schema = app_schema or ("public" if d.name == "postgres" else None)
    if d.name == "mysql" and not app_schema:
        raise ValueError("MySQL needs --app-schema (the app's database name)")
    q = d.q
    views = model.views(previews=previews)
    out = [f"-- Laocoon: read-only views for authorisation, generated from {source}.",
           f"-- Review, then run once as the owner of the app's tables ({d.name}). Re-run it after migrations",
           "-- that change these columns. The login it creates can read these views and nothing else.", ""]
    tables = sorted({t for _, t, _, _ in views})
    out.append("-- App tables read (only the columns listed per view): " + ", ".join(tables))
    if d.name == "postgres":
        out += ["BEGIN;", f"CREATE SCHEMA IF NOT EXISTS {q(schema)};"]
    else:
        out += [f"CREATE DATABASE IF NOT EXISTS {q(schema)};"]
    labels = {"object": "-- objects: ids, names, codes and state the rules use (no personal data beyond names)",
              "relation": "-- relations: pairs of ids",
              "preview": "-- before-values for approval cards: PERSONAL DATA, grant only if the customer agrees"}
    last = None
    for view, table, cols, tier in views:
        if tier != last:
            out += ["", labels[tier]]
            last = tier
        select = _select(q, cols)
        src_table = f"{q(app_schema)}.{q(table)}"
        if d.name == "postgres":
            out.append(f"DROP VIEW IF EXISTS {q(schema)}.{q(view)};")
            out.append(f"CREATE VIEW {q(schema)}.{q(view)} AS SELECT {select} FROM {src_table};")
        else:
            out.append(f"CREATE OR REPLACE SQL SECURITY DEFINER VIEW {q(schema)}.{q(view)} AS "
                       f"SELECT {select} FROM {src_table};")
    granted = [v for v, _, _, tier in views if not (functions and tier == "relation")]
    if d.name == "postgres":
        if functions:
            out += [""] + _pg_functions(model, schema)
        out += ["", "-- the login (set its password separately: \\password " + role + ")",
                f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN "
                f"CREATE ROLE {q(role)} LOGIN; END IF; END $$;",
                f"ALTER ROLE {q(role)} SET default_transaction_read_only = on;",
                f"ALTER ROLE {q(role)} SET statement_timeout = '2s';",
                f"REVOKE ALL ON ALL TABLES IN SCHEMA {q(schema)} FROM {q(role)};     -- views of an older model",
                f"GRANT USAGE ON SCHEMA {q(schema)} TO {q(role)};"]
        out += [f"GRANT SELECT ON {q(schema)}.{q(v)} TO {q(role)};" for v in granted]
        if functions:
            out += [f"GRANT EXECUTE ON FUNCTION {q(schema)}.{q(f)}({a}) TO {q(role)};"
                    for f, a in _pg_function_names(model)]
        out += ["COMMIT;", "",
                "-- Check what it can read:  \\dp " + schema + ".*",
                f"--   SELECT table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee = '{role}';",
                "-- Nothing in the app's schema is granted. PostgreSQL 14 and older also let every role CREATE in schema",
                "-- public; consider REVOKE CREATE ON SCHEMA public FROM PUBLIC. Keep these views security_invoker = off",
                "-- (the default): they read with their owner's rights, which is what keeps the login narrow."]
    else:
        out += ["", f"CREATE USER IF NOT EXISTS '{role}'@'%' IDENTIFIED BY 'change-me';   -- set a real password"]
        out += [f"GRANT SELECT ON {q(schema)}.{q(v)} TO '{role}'@'%';" for v in granted]
        out += ["", f"-- Check what it can read:  SHOW GRANTS FOR '{role}'@'%';",
                "-- A MySQL view does not block the app's migrations: after one, a view whose column went away",
                "-- fails when queried (Laocoon then fails closed). Re-run this script after such a migration."]
    return "\n".join(out) + "\n"


def _sqlite_sql(model, previews):
    """TEMP views: what `SqliteViews` creates in its own read-only connection."""
    q = Dialect().q
    out = []
    for view, table, cols, _ in model.views(previews=previews):
        select = _select(q, cols)
        out.append(f"CREATE TEMP VIEW {q(view)} AS SELECT {select} FROM main.{q(table)};")
    return "\n".join(out) + "\n"


def _select(q, cols):
    return ", ".join(q(src) if src == name else f"{q(src)} AS {q(name)}" for name, src in cols)


def _pg_function_names(model):
    out = []
    for name, paths in model.constraints.items():
        principal = any(p.field is None for p in paths)
        out.append((f"can_{name}", "bigint, bigint" if principal else "bigint"))
    for name in model.constraints:
        if model.scoped(name) is not None:
            out.append((f"scope_{name}", "bigint"))
    for name, (_, p) in model.derive.items():
        out.append((f"derive_{name}", "bigint"))
    return out


def _pg_functions(model, schema):
    """Yes/no functions (and the user's own scope, which the filters and the scope enum need). They run with
    their owner's rights over the relation views, which the login itself cannot read."""
    c = Compiler(model, Postgres(), schema)
    q = c.d.q
    out = ["-- stricter: yes/no functions instead of SELECT on the relation views",
           "-- (SECURITY DEFINER, a fixed search_path, EXECUTE revoked from PUBLIC)"]

    def fn(name, args, returns, body):
        sig = ", ".join(f"{a} bigint" for a in args)
        out.extend([f"CREATE OR REPLACE FUNCTION {q(schema)}.{q(name)}({sig}) RETURNS {returns}",
                    f"LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ {body} $$;",
                    f"REVOKE ALL ON FUNCTION {q(schema)}.{q(name)}({', '.join('bigint' for _ in args)}) FROM PUBLIC;"])

    def numbered(sql, params):
        for i, p in enumerate(params, 1):
            sql = sql.replace("?", p, 1)
        return sql

    for name, paths in model.constraints.items():
        principal = any(p.field is None for p in paths)
        terms = []
        for p in paths:
            sql, n = c.check(p)
            sql = numbered(sql, ["p_object", "p_user"][:n])
            if p.field is None:
                t = f"EXISTS ({sql})"
            else:
                t = f"COALESCE((SELECT bool_or(x.v::text NOT IN ('0', 'false', 'f', '')) FROM ({sql}) x), false)"
            terms.append(f"NOT {t}" if p.negate else t)
        fn(f"can_{name}", ["p_object", "p_user"] if principal else ["p_object"], "boolean", "SELECT " + " AND ".join(terms))
    for name in model.constraints:
        p = model.scoped(name)
        if p is not None:
            fn(f"scope_{name}", ["p_user"], "TABLE(id bigint)",
               f"SELECT x.v::bigint FROM ({numbered(c.scope(p), ['p_user'])}) x")
    for name, (_, p) in model.derive.items():
        fn(f"derive_{name}", ["p_object"], "bigint",
           f"SELECT x.v::bigint FROM ({numbered(c.follow(p), ['p_object'])}) x LIMIT 1")
    return out


# ---------------------------------------------------------------------------------------------- connectors
class Denied(Exception):
    """The views connection refused a read (SQLite: Laocoon's own authorizer)."""


class SqliteViews:
    """SQLite has no permissions: anyone who can open the file can read everything. Laocoon therefore restrains
    itself, and makes that visible: the app's file is opened read-only, the views are TEMP views of Laocoon's own
    connection (the file is never modified), and an authorizer refuses every read that is not made through one of
    them, every function outside a short list and every statement that is not a SELECT. SQLite names the view
    behind each table read, which is what the authorizer checks.

    `exported=True`: the file holds only the views' rows (`export`), as tables named like the views; there is
    nothing else to read in it, which is a real boundary (stale by the copy interval)."""

    dialect = Dialect()
    FUNCTIONS = frozenset({"lower", "like"})

    def __init__(self, path, model: DataModel, previews=True, exported=None):
        self.path = str(path)
        self.model = model
        self.exported = self._is_export() if exported is None else exported
        self.ns = "main" if self.exported else "temp"
        self.ddl = [] if self.exported else _sqlite_sql(model, previews).strip().splitlines()
        self.allowed = {v for v, _, _, _ in model.views(previews=previews)}
        self.sources = {t for _, t, _, _ in model.views(previews=previews)}
        self.denials = 0
        self.last_denial = None
        self._lock = threading.Lock()

    def _is_export(self):
        try:
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5)
            try:
                names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            finally:
                conn.close()
        except sqlite3.Error:
            return False
        return bool(names) and all(n.startswith(("obj_", "rel_", "prev_", "laocoon_")) for n in names)

    def _authorize(self, action, a1, a2, db, inner):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            if self.exported:
                if db == "main" and a1 in self.allowed and a2:
                    return sqlite3.SQLITE_OK
            elif db == "temp" and a1 in self.allowed:          # a column of one of the views
                return sqlite3.SQLITE_OK
            elif db == "main" and inner in self.allowed and a2:  # an app table, read by one of the views
                return sqlite3.SQLITE_OK
            elif db == "main" and a2 == "" and a1 in self.sources:
                # a read that extracts no column: a view of the rowid alias alone (obj_submission), flattened, or
                # count(*) over a view. SQLite then names no view, so this is allowed only for tables behind a
                # view, and it shows only that rows exist, which that view shows anyway. A column read straight
                # from a table, even the id, is reported with its column and refused below.
                return sqlite3.SQLITE_OK
            # anything else: a column of an app table read straight from Laocoon's own SQL, any other table
        elif action == sqlite3.SQLITE_FUNCTION and a2 in self.FUNCTIONS:
            return sqlite3.SQLITE_OK
        with self._lock:
            self.denials += 1
            self.last_denial = (action, a1, a2, db, inner)
        return sqlite3.SQLITE_DENY

    def connect(self):
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        for stmt in self.ddl:                               # before the authorizer: the only statements not a SELECT
            conn.execute(stmt)
        conn.set_authorizer(self._authorize)
        return conn

    def query(self, sql, args=(), one=False):
        """One connection per call, like the db adapter's readonly_query (safe across threads, and the app may
        recreate its file at start-up)."""
        conn = self.connect()
        try:
            try:
                rows = [dict(r) for r in conn.execute(sql, tuple(args)).fetchall()]
            except sqlite3.DatabaseError as e:
                if "not authorized" in str(e) or "prohibited" in str(e):
                    raise Denied(f"{e}: {self.last_denial}") from None
                raise
        finally:
            conn.close()
        return (rows[0] if rows else None) if one else rows

    def available(self) -> dict:
        """{view: {columns}} this connection can read."""
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)
        try:
            for stmt in self.ddl:
                conn.execute(stmt)
            out = {}
            for v in sorted(self.allowed):
                cols = {r[1] for r in conn.execute(f"PRAGMA {self.ns}.table_info({Dialect().q(v)})")}
                if cols:
                    out[v] = cols
            return out
        finally:
            conn.close()

    def describe(self):
        return ("SQLite, self-imposed: the file is opened read-only, the views are TEMP views of Laocoon's own "
                "connection and an authorizer refuses any read not made through them" if not self.exported else
                "SQLite export: a separate file holding only the views' rows (as fresh as the last copy)")


class PostgresViews:
    """A login that can read only the views (or call the functions): the database enforces the boundary.
    Needs `psycopg` (pip install "psycopg[binary]"). One connection per thread, autocommit, reconnect on error."""

    dialect = Postgres()

    def __init__(self, dsn, schema="laocoon", functions=False, connect_timeout=3):
        import importlib.util
        if importlib.util.find_spec("psycopg") is None:  # pragma: no cover - depends on the deployment
            raise RuntimeError('LAOCOON_VIEWS_DSN needs psycopg: pip install -r requirements-pg.txt')
        self.dsn, self.ns, self.functions = dsn, schema, functions
        self.connect_timeout = connect_timeout
        self._local = threading.local()

    def _conn(self):
        import psycopg
        from psycopg.rows import dict_row
        c = getattr(self._local, "conn", None)
        if c is None or c.closed:
            c = psycopg.connect(self.dsn, autocommit=True, row_factory=dict_row, connect_timeout=self.connect_timeout)
            self._local.conn = c
        return c

    def query(self, sql, args=(), one=False):
        import psycopg
        sql = sql.replace("%", "%%").replace("?", "%s")
        for attempt in (0, 1):
            try:
                with self._conn().cursor() as cur:
                    cur.execute(sql, tuple(args))
                    rows = list(cur.fetchall()) if cur.description else []
                break
            except psycopg.errors.InsufficientPrivilege as e:
                raise Denied(str(e).strip()) from None
            except psycopg.OperationalError:
                c = getattr(self._local, "conn", None)
                if c is not None:
                    c.close()
                self._local.conn = None
                if attempt:
                    raise
        return (rows[0] if rows else None) if one else rows

    def available(self) -> dict:
        out = {}
        for r in self.query("SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = ?",
                            (self.ns,)):
            out.setdefault(r["table_name"], set()).add(r["column_name"])
        return out

    def routines(self) -> set:
        return {r["routine_name"] for r in self.query(
            "SELECT routine_name FROM information_schema.routines WHERE routine_schema = ?", (self.ns,))}

    def describe(self):
        return f"PostgreSQL, enforced by the database: schema {self.ns}" + (" (functions)" if self.functions else "")


def connect_from_env(model: DataModel, env=os.environ.get):
    """LAOCOON_VIEWS_DSN=postgresql://… (the database enforces it) or LAOCOON_VIEWS_DB / LAOCOON_ECLASS_DB, an
    SQLite file (self-imposed, or an export). LAOCOON_VIEWS_PREVIEWS=off leaves the before-values out."""
    previews = (env("LAOCOON_VIEWS_PREVIEWS") or "on").strip().lower() not in ("0", "off", "false", "no")
    dsn = env("LAOCOON_VIEWS_DSN")
    if dsn:
        return PostgresViews(dsn, env("LAOCOON_VIEWS_SCHEMA") or "laocoon",
                             functions=(env("LAOCOON_VIEWS_FUNCTIONS") or "").strip().lower() in ("1", "on", "true"))
    path = env("LAOCOON_VIEWS_DB") or env("LAOCOON_ECLASS_DB") or "/eclass-data/eclass.db"
    return SqliteViews(path, model, previews=previews)


# ---------------------------------------------------------------------------------------------- export (SQLite)
def export(model: DataModel, src, out, previews=False):
    """Copy the views' rows into a separate SQLite file (written to a temporary name, then renamed into place).
    Run it on the customer's side, every few seconds; give Laocoon only `out`."""
    tmp = f"{out}.tmp-{os.getpid()}"
    for p in (tmp, tmp + "-journal"):
        if os.path.exists(p):
            os.remove(p)
    conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=10)
    try:
        for stmt in _sqlite_sql(model, previews).strip().splitlines():
            conn.execute(stmt)
        conn.execute("ATTACH DATABASE ? AS out", (tmp,))
        for view, _, _, _ in model.views(previews=previews):
            conn.execute(f'CREATE TABLE out."{view}" AS SELECT * FROM temp."{view}"')
        conn.commit()
        conn.execute("DETACH DATABASE out")
    finally:
        conn.close()
    os.replace(tmp, out)


# ---------------------------------------------------------------------------------------------- CLI
def _main(argv=None):
    import argparse
    import sys
    import time

    from .config import DEFAULT_POLICY, load_policy

    p = argparse.ArgumentParser(prog="python -m laocoon.views", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sql", help="the setup script for the database administrator")
    s.add_argument("--dialect", default="postgres", choices=["postgres", "mysql", "sqlite"])
    s.add_argument("--schema", default="laocoon", help="where the views go (MySQL: a database)")
    s.add_argument("--role", default="laocoon", help="the login Laocoon uses")
    s.add_argument("--app-schema", default=None, help="the schema (MySQL: database) of the app's tables")
    s.add_argument("--previews", action="store_true", help="also the before-values for approval cards (personal data)")
    s.add_argument("--functions", action="store_true", help="PostgreSQL: yes/no functions instead of relation views")
    c = sub.add_parser("check", help="what the login can read, compared with what the model needs")
    c.add_argument("--db", help="SQLite file")
    c.add_argument("--dsn", help="postgresql://…")
    c.add_argument("--schema", default="laocoon")
    c.add_argument("--functions", action="store_true", help="PostgreSQL: the login calls functions, reads no relations")
    e = sub.add_parser("export", help="SQLite: copy the views' rows into a separate file")
    e.add_argument("--db", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--previews", action="store_true")
    e.add_argument("--every", type=float, default=0, help="repeat every N seconds")
    for x in (s, c, e):
        x.add_argument("--policy", default=os.environ.get("LAOCOON_POLICY") or str(DEFAULT_POLICY))
    a = p.parse_args(argv)
    model = DataModel.from_policy(load_policy(a.policy))
    if model is None:
        sys.exit(f"{a.policy} has no data_model section")
    if a.cmd == "sql":
        sys.stdout.write(setup_sql(model, a.dialect, schema=a.schema, role=a.role, app_schema=a.app_schema,
                                   previews=a.previews, functions=a.functions,
                                   source=f"{os.path.basename(a.policy)} (data_model)"))
    elif a.cmd == "check":
        if not (a.db or a.dsn):
            sys.exit("--db or --dsn")
        db = PostgresViews(a.dsn, a.schema, functions=a.functions) if a.dsn else SqliteViews(a.db, model)
        have, need = db.available(), model.required(functions=a.functions)
        print(db.describe())
        for v in sorted(set(have) | set(need)):
            cols = have.get(v, set())
            missing = sorted(need.get(v, set()) - cols)
            state = "MISSING" if v not in have else ("missing " + ", ".join(missing) if missing else "ok")
            print(f"  {v:28} {state:12} {', '.join(sorted(cols))}")
        bad = [v for v in need if not need[v] <= have.get(v, set())]
        sys.exit(1 if bad else 0)
    else:
        while True:
            t = time.monotonic()
            export(model, a.db, a.out, previews=a.previews)
            print(f"exported {len(model.views(a.previews))} views to {a.out} in {time.monotonic() - t:.2f}s",
                  flush=True)
            if not a.every:
                break
            time.sleep(max(0.0, a.every - (time.monotonic() - t)))


if __name__ == "__main__":
    _main()

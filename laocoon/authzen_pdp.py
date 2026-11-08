"""A reference AuthZEN 1.0 policy decision point for Laocoon's data model (demo, tests, a starting point).

Customers normally run their own PDP. This one shows the contract end to end. It answers the AuthZEN APIs from a
store, and the rules are the policy's `data_model` paths:
  - GraphStore: a JSON document of objects and relation pairs. No SQL at all: export it from any database,
    document store or directory (`export` writes one from the views, for the demo).
  - ViewsStore: live, through the data_model's views of an SQLite or PostgreSQL database.

Actions it understands (the AuthZEN `action.name`):
    <constraint>     each data_model constraint, on a resource of the kind its paths start at
    <kind>.<name>    each relation: is the subject reached from the resource through it?
    identity         subject.properties {username, role} match the subject's own record (resource: that user)
    list             any existing resource (resource search: the directory, with properties)
Resource and subject types are the data_model's kind names. Search results carry the objects' fields as
`properties`, and a resource search honours `context.laocoon.reference` as a hint to narrow its results.

    python -m laocoon.authzen_pdp serve --graph graph.json [--port 8484] [--token T] [--policy P]
    python -m laocoon.authzen_pdp serve --db eclass.db             (live, through the views)
    python -m laocoon.authzen_pdp export --db eclass.db --out graph.json
"""
from __future__ import annotations

import hmac
import json

from flask import Flask, jsonify, request

from .facts import Unverifiable
from .views import DataModel, as_id

IDENTITY, LIST = "identity", "list"
MAX_LIMIT = 1000


def _nid(v):
    """Ids as the store keeps them: integers when they are written as integers, otherwise strings."""
    if v is None or isinstance(v, bool):
        return None
    s = str(v).strip()
    return int(s) if s.isdigit() else s


def _cf(s) -> str:
    return " ".join(str(s or "").casefold().split())


def _nospace(s) -> str:
    return str(s or "").upper().replace(" ", "")


# ---------------------------------------------------------------------------------------------- stores
class GraphStore:
    """{"objects": {kind: {id: {field: value}}}, "relations": {"kind.name": [[from_id, to_id], ...]}}"""

    def __init__(self, model: DataModel, graph: dict):
        self.model = model
        self.objects = {k: {_nid(i): dict(f or {}) for i, f in (graph.get("objects", {}).get(k) or {}).items()}
                        for k in model.objects}
        self.fwd, self.rev = {}, {}
        for key, pairs in (graph.get("relations") or {}).items():
            kind, name = key.split(".")
            for a, b in pairs or []:
                if a is None or b is None:
                    continue
                a, b = _nid(a), _nid(b)
                self.fwd.setdefault((kind, name), {}).setdefault(a, set()).add(b)
                self.rev.setdefault((kind, name), {}).setdefault(b, set()).add(a)

    def get(self, kind, oid):
        return self.objects.get(kind, {}).get(oid)

    def items(self, kind) -> dict:
        return self.objects.get(kind, {})

    def reach(self, path, oid) -> set:
        if not path.hops:
            return {oid} if oid in self.objects.get(path.start, {}) else set()
        cur = {oid}
        for hop in path.hops:
            if hop.reverse_of:
                idx = self.rev.get(hop.reverse_of, {})
            else:
                idx = self.fwd.get((hop.kind, hop.name), {})
            nxt = set()
            for x in cur:
                nxt |= idx.get(x, set())
            cur = nxt
        return cur

    def term(self, path, oid, uid) -> bool:
        reached = self.reach(path, oid)
        if path.field is None:
            ok = uid in reached
        else:
            objs = self.objects.get(path.end, {})
            ok = any(bool((objs.get(x) or {}).get(path.field)) for x in reached)
        return not ok if path.negate else ok

    def holds(self, name, uid, oid) -> bool:
        return all(self.term(p, oid, uid) for p in self.model.constraints[name])


class ViewsStore:
    """Live, through the views (SqliteViews or PostgresViews), reusing Laocoon's own views adapter."""

    def __init__(self, model: DataModel, db):
        from .adapters.views import ViewsAdapter
        self.model, self.db = model, db
        self.v = ViewsAdapter(db, model)

    def get(self, kind, oid):
        r = self.v.fields(kind, oid) if isinstance(oid, int) else None
        return {k: x for k, x in r.items() if k != "id"} if r else None

    def items(self, kind) -> dict:
        o = self.model.objects[kind]
        q = self.v.c.d.q
        cols = ", ".join(q(c) for c in ["id"] + list(o.fields))
        rows = self.v._q(f"SELECT {cols} FROM {self.v.c.v(o.view)}")
        return {r["id"]: {k: x for k, x in r.items() if k != "id"} for r in rows}

    def reach(self, path, oid) -> set:
        return set(self.v.follow(path.text, oid)) if path.hops else ({oid} if self.get(path.start, oid) else set())

    def holds(self, name, uid, oid) -> bool:
        return bool(self.v.constraint(name, {"id": uid}, oid, {}))

    def scope(self, name, uid) -> set:
        return self.v.scope_ids(name, uid)

    def relations(self) -> dict:
        out = {}
        for (kind, name), rel in self.model.relations.items():
            if rel.reverse_of:
                continue
            a, b = rel.columns
            q = self.v.c.d.q
            rows = self.v._q(f"SELECT {q(a)} AS a, {q(b)} AS b FROM {self.v.c.v(rel.view)}")
            out[f"{kind}.{name}"] = sorted([r["a"], r["b"]] for r in rows if r["a"] is not None and r["b"] is not None)
        return out


def export_graph(model: DataModel, db) -> dict:
    """The views' rows as a JSON graph (objects with their fields, relation pairs): the GraphStore's input."""
    st = ViewsStore(model, db)
    return {"objects": {k: {str(i): f for i, f in sorted(st.items(k).items(), key=lambda x: str(x[0]))}
                        for k in model.objects},
            "relations": st.relations()}


# ---------------------------------------------------------------------------------------------- the PDP
class Pdp:
    def __init__(self, model: DataModel, store):
        self.model, self.store = model, store
        self.user = model.principal

    def _path_of(self, name):
        """A relation key (kind.name) as a path to the user, or None."""
        parts = str(name).split(".")
        if len(parts) == 2 and tuple(parts) in self.model.relations:
            try:
                return self.model.path(name, ["(pdp)"], follow=True)
            except Exception:
                return None
        return None

    def decide(self, subject, action, resource) -> bool:
        if subject.get("type") != self.user:
            return False
        uid = as_id(subject.get("id"))
        name, kind = action.get("name"), resource.get("type")
        if uid is None or kind not in self.model.objects:
            return False
        oid = _nid(resource.get("id"))
        if name == IDENTITY:
            props = subject.get("properties") or {}
            me = self.store.get(self.user, uid)
            return (kind == self.user and oid == uid and bool(me) and props.get("username") == me.get("username")
                    and props.get("role") == me.get("role"))
        if name == LIST:
            return self.store.get(kind, oid) is not None
        paths = self.model.constraints.get(name)
        if paths is not None:
            return all(p.start == kind for p in paths) and self.store.holds(name, uid, oid)
        path = self._path_of(name)
        if path is not None and path.start == kind and path.end == self.user:
            return uid in self.store.reach(path, oid)
        return False

    def resources(self, subject, action, kind, hint=None) -> list:
        uid = as_id(subject.get("id")) if subject.get("type") == self.user else None
        name = action.get("name")
        if uid is None or kind not in self.model.objects:
            return []
        items = self.store.items(kind)
        if name == LIST:
            ids = list(items)
            if hint:
                h = str(hint)
                hid = _nid(h)
                ids = [i for i in ids if i == hid or any(
                    _cf(h) in _cf(v) or _nospace(h) in _nospace(v) for v in items[i].values() if v is not None)]
        elif name in self.model.constraints:
            if not all(p.start == kind for p in self.model.constraints[name]):
                return []
            if self.model.scoped(name) is not None and hasattr(self.store, "scope"):
                ids = [i for i in self.store.scope(name, uid) if i in items]
            else:
                ids = [i for i in items if self.store.holds(name, uid, i)]
        else:
            path = self._path_of(name)
            if path is None or path.start != kind:
                return []
            ids = [i for i in items if uid in self.store.reach(path, i)]
        return [{"type": kind, "id": str(i), "properties": items.get(i) or {}}
                for i in sorted(ids, key=lambda x: (isinstance(x, str), x))]

    def subjects(self, action, kind, oid) -> list:
        name = action.get("name")
        oid = _nid(oid)
        paths = self.model.constraints.get(name)
        path = paths[0] if paths and len(paths) == 1 and paths[0].to_principal and not paths[0].negate \
            else self._path_of(name)
        if path is not None and path.start == kind and path.end == self.user:
            ids = self.store.reach(path, oid)
        elif paths is not None:
            ids = [u for u in self.store.items(self.user) if self.store.holds(name, u, oid)]
        else:
            ids = []
        users = self.store.items(self.user)
        return [{"type": self.user, "id": str(u), "properties": users.get(u) or {}} for u in sorted(ids)]

    def actions(self, subject, kind, oid) -> list:
        names = [n for n, ps in self.model.constraints.items() if all(p.start == kind for p in ps)]
        names += [f"{k}.{n}" for (k, n), r in self.model.relations.items() if k == kind and r.target == self.user]
        res = {"type": kind, "id": str(oid)}
        return [{"name": n} for n in names if self.decide(subject, {"name": n}, res)]


def create_pdp(model: DataModel, store, *, token=None, pdp_id=None) -> Flask:
    app = Flask("laocoon-authzen-pdp")
    pdp = Pdp(model, store)
    paths = {"access_evaluation_endpoint": "/access/v1/evaluation",
             "access_evaluations_endpoint": "/access/v1/evaluations",
             "search_subject_endpoint": "/access/v1/search/subject",
             "search_resource_endpoint": "/access/v1/search/resource",
             "search_action_endpoint": "/access/v1/search/action"}

    def base():
        return (pdp_id or request.host_url).rstrip("/")

    @app.after_request
    def echo(resp):
        rid = request.headers.get("X-Request-ID")
        if rid:
            resp.headers["X-Request-ID"] = rid
        return resp

    @app.before_request
    def auth():
        if request.path.startswith("/.well-known/"):
            return None
        if token and not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {token}"):
            r = jsonify(message="unauthorized")
            r.status_code, r.headers["WWW-Authenticate"] = 401, 'Bearer realm="authzen"'
            return r
        return None

    def bad(msg):
        r = jsonify(message=msg)
        r.status_code = 400
        return r

    def entity(d, need_id=True, key="type"):
        return isinstance(d, dict) and isinstance(d.get(key), str) and (not need_id or isinstance(d.get("id"), str))

    def body():
        b = request.get_json(silent=True)
        return b if isinstance(b, dict) else None

    def evaluate(b):
        s, a, r = b.get("subject"), b.get("action"), b.get("resource")
        if not (entity(s) and entity(a, False, "name") and entity(r)):
            return None
        try:
            return {"decision": bool(pdp.decide(s, a, r))}
        except Unverifiable as e:                   # the store cannot answer: closed, with the reason
            return {"decision": False, "context": {"error": {"status": 500, "message": str(e)}}}

    @app.get("/.well-known/authzen-configuration")
    def metadata():
        return jsonify(policy_decision_point=base(), **{k: base() + v for k, v in paths.items()})

    @app.post(paths["access_evaluation_endpoint"])
    def evaluation():
        b = body()
        out = evaluate(b) if b else None
        return jsonify(out) if out else bad("subject {type, id}, action {name} and resource {type, id} are required")

    @app.post(paths["access_evaluations_endpoint"])
    def evaluations():
        b = body()
        if b is None:
            return bad("a JSON object is required")
        items = b.get("evaluations") or []
        if not items:
            out = evaluate(b)
            return jsonify(out) if out else bad("subject, action and resource are required")
        sem = (b.get("options") or {}).get("evaluations_semantic", "execute_all")
        if sem not in ("execute_all", "deny_on_first_deny", "permit_on_first_permit"):
            return bad("unknown evaluations_semantic")
        out = []
        for e in items:
            if not isinstance(e, dict):
                return bad("each evaluation is an object")
            merged = {k: e.get(k, b.get(k)) for k in ("subject", "action", "resource", "context")}
            d = evaluate(merged)
            if d is None:
                return bad("each evaluation needs subject, action and resource (or a default)")
            out.append(d)
            if (sem == "deny_on_first_deny" and not d["decision"]) or (sem == "permit_on_first_permit" and d["decision"]):
                break
        return jsonify(evaluations=out)

    def paged(results):
        page = (body() or {}).get("page") or {}
        try:
            start = int(page.get("token") or 0)
            limit = min(int(page.get("limit") or 50), MAX_LIMIT) or 50
        except (TypeError, ValueError):
            return bad("invalid page")
        chunk = results[start:start + limit]
        nxt = str(start + limit) if start + limit < len(results) else ""
        return jsonify(results=chunk, page={"next_token": nxt, "count": len(chunk), "total": len(results)})

    @app.post(paths["search_resource_endpoint"])
    def search_resource():
        b = body()
        if not (b and entity(b.get("subject")) and entity(b.get("action"), False, "name")
                and entity(b.get("resource"), False)):
            return bad("subject {type, id}, action {name} and resource {type} are required")
        hint = (((b.get("context") or {}).get("laocoon") or {}).get("reference"))
        try:
            return paged(pdp.resources(b["subject"], b["action"], b["resource"]["type"], hint))
        except Unverifiable as e:
            return jsonify(message=str(e)), 500

    @app.post(paths["search_subject_endpoint"])
    def search_subject():
        b = body()
        if not (b and entity(b.get("subject"), False) and entity(b.get("action"), False, "name")
                and entity(b.get("resource"))):
            return bad("subject {type}, action {name} and resource {type, id} are required")
        if b["subject"]["type"] != pdp.user:
            return paged([])
        try:
            return paged(pdp.subjects(b["action"], b["resource"]["type"], b["resource"]["id"]))
        except Unverifiable as e:
            return jsonify(message=str(e)), 500

    @app.post(paths["search_action_endpoint"])
    def search_action():
        b = body()
        if not (b and entity(b.get("subject")) and entity(b.get("resource"))):
            return bad("subject {type, id} and resource {type, id} are required")
        try:
            return paged(pdp.actions(b["subject"], b["resource"]["type"], b["resource"]["id"]))
        except Unverifiable as e:
            return jsonify(message=str(e)), 500

    app.config["laocoon_pdp"] = pdp
    return app


# ---------------------------------------------------------------------------------------------- CLI
def _main(argv=None):
    import argparse
    import os
    import sys

    from .config import DEFAULT_POLICY, load_policy
    from .views import PostgresViews, SqliteViews

    p = argparse.ArgumentParser(prog="python -m laocoon.authzen_pdp", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="answer AuthZEN 1.0 requests")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--graph", help="a JSON graph (no database)")
    src.add_argument("--db", help="SQLite file, live through the views")
    src.add_argument("--dsn", help="postgresql://… live through the views (the laocoon login)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8484)
    s.add_argument("--token", default=os.environ.get("LAOCOON_AUTHZEN_TOKEN"), help="require this bearer token")
    e = sub.add_parser("export", help="write the JSON graph of a database, through the views")
    e.add_argument("--db", required=True)
    e.add_argument("--out", required=True)
    for x in (s, e):
        x.add_argument("--policy", default=os.environ.get("LAOCOON_POLICY") or str(DEFAULT_POLICY))
    a = p.parse_args(argv)
    model = DataModel.from_policy(load_policy(a.policy))
    if model is None:
        sys.exit(f"{a.policy} has no data_model section")
    if a.cmd == "export":
        graph = export_graph(model, SqliteViews(a.db, model, previews=False))
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(graph, f, ensure_ascii=False, indent=1)
        print(f"wrote {a.out}: {sum(len(v) for v in graph['objects'].values())} objects, "
              f"{sum(len(v) for v in graph['relations'].values())} relation pairs")
        return
    if a.graph:
        with open(a.graph, encoding="utf-8") as f:
            store = GraphStore(model, json.load(f))
    elif a.db:
        store = ViewsStore(model, SqliteViews(a.db, model, previews=False))
    else:
        store = ViewsStore(model, PostgresViews(a.dsn))
    create_pdp(model, store, token=a.token).run(host=a.host, port=a.port)


if __name__ == "__main__":
    _main()

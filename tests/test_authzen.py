"""LAOCOON_AUTHZ_SOURCE=authzen: Laocoon as an AuthZEN 1.0 enforcement point, asking a policy decision point.

The reference PDP (laocoon/authzen_pdp.py) serves the seeded eClass from a JSON graph (no SQL in the decision
path). Parity with `db` mode is checked exhaustively; the wire behaviour (discovery, X-Request-ID, batching,
pagination, failures) against a scripted PDP.
"""
import json
import shutil
import sqlite3

import pytest

from app.tools import DECLARATIONS
from laocoon import proxy as PX
from laocoon import studio
from laocoon.adapters.eclass import EclassAdapter, readonly_query
from laocoon.adapters.eclass_authzen import EclassAuthzenAdapter
from laocoon.authzen import MAX_PAGES, AuthzenClient, AuthzenConfig, AuthzenError, ConfigError
from laocoon.authzen_pdp import GraphStore, ViewsStore, create_pdp, export_graph
from laocoon.config import DEFAULT_POLICY, load_policy
from laocoon.facts import Unverifiable
from laocoon.views import DataModel, SqliteViews

POLICY = load_policy(DEFAULT_POLICY)
MODEL = DataModel.from_policy(POLICY)
CONFIG = AuthzenConfig.from_policy(POLICY)
PDP = "http://pdp.test"
HTTPS_PDP = "https://pdp.test"                 # what a deployment must use outside localhost
TABLE = {"user": "users", "course": "courses", "assignment": "assignments", "submission": "submissions",
         "exercise": "exercises"}
KIND_OF = {"self": "user", "taught": "course", "enrolled": "course", "student_of_taught": "user",
           "enrolled_assignment": "assignment", "taught_assignment": "assignment", "enrolled_exercise": "exercise",
           "taught_exercise": "exercise", "open_enrolled_exercise": "exercise", "taught_submission": "submission",
           "not_attempted": "exercise"}


def flask_transport(app, log=None):
    """The AuthzenClient transport over a Flask test client (no network)."""
    c = app.test_client()

    def transport(method, url, body, headers, timeout, verify):
        path = url.split("://", 1)[1]
        path = path[path.index("/"):]
        if log is not None:
            log.append((method, path, body, dict(headers)))
        r = c.open(path, method=method, json=body, headers=headers)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.get_json(silent=True)
    return transport


@pytest.fixture
def eclass_db(template_db, tmp_path):
    db = tmp_path / "eclass.db"
    shutil.copy(template_db, db)
    return str(db)


@pytest.fixture
def graph(eclass_db):
    """The seeded eClass as a JSON graph: objects with their fields, relation pairs. Round-tripped through JSON."""
    return json.loads(json.dumps(export_graph(MODEL, SqliteViews(eclass_db, MODEL, previews=False))))


@pytest.fixture
def pair(eclass_db, graph):
    app = create_pdp(MODEL, GraphStore(MODEL, graph), token="t0k", pdp_id=PDP)
    client = AuthzenClient(PDP, token="t0k", transport=flask_transport(app), cache_ttl=0)
    return EclassAdapter(readonly_query(eclass_db)), EclassAuthzenAdapter(client, CONFIG), readonly_query(eclass_db)


def _ids(q, kind):
    return [r["id"] for r in q(f"SELECT id FROM {TABLE[kind]}")] + [0, 9999]


# ---------------------------------------------------------------------------------------------- the mapping
def test_the_shipped_mapping_covers_every_data_constraint():
    assert set(CONFIG.constraints) == set(EclassAdapter.CONSTRAINTS) - {"self", "read_only_sql"}
    assert CONFIG.identity_action == "identity" and CONFIG.subject == "user"
    assert CONFIG.constraints["taught_submission"].kind == "submission"
    assert CONFIG.relations["course.teacher"].action == "taught"


BAD = [
    ({"surprise": 1}, "unknown key"),
    ({"constraints": {"taught": {"resource": "room"}}}, "'room' is not in authzen.resources"),
    ({"constraints": {"self": {"resource": "user"}}}, "`self` is built in"),
    ({"resources": {"course": {"type": "course", "refs": [{"code": "exact"}]}}}, "references by name need `search`"),
    ({"resources": {"course": {"type": "course", "search": "list", "refs": [{"code": "regex"}]}}}, "match is one of"),
    ({"resources": {"course": {"type": "course", "id": "uuid"}}}, "int or string"),
    ({"resources": {"course": {"type": "course; drop"}}}, "not a valid resource type"),
    ({"derive": {"owner": {"arg": "x", "relation": "nope.nope"}}}, "needs {arg, relation}"),
]


@pytest.mark.parametrize("patch,message", BAD)
def test_mapping_errors_name_the_place(patch, message):
    a = json.loads(json.dumps(POLICY["authzen"]))
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            a[k].update(v)
        else:
            a[k] = v
    with pytest.raises(ConfigError) as e:
        AuthzenConfig.parse(a)
    assert message in str(e.value)


# ---------------------------------------------------------------------------------------------- parity with db
def test_constraints_scope_and_identity_match_db_mode(pair):
    A, Z, q = pair
    n = 0
    for u in q("SELECT id FROM users"):
        P = A.principal_by_id(u["id"])
        assert Z.verify_identity(P)
        assert not Z.verify_identity(dict(P, role="admin" if P["role"] != "admin" else "student"))
        assert not Z.verify_identity(dict(P, username="someone-else"))
        for name, kind in KIND_OF.items():
            for v in _ids(q, kind) + ["x", None, "1e999", -1]:
                assert Z.constraint(name, P, v, {}) == A.constraint(name, P, v, {}), (name, u["id"], v)
                n += 1
            assert Z.choices(name, P) == A.choices(name, P), (name, u["id"])
        for v in _ids(q, "exercise"):                     # an all-of list: one batch
            assert Z.all_of(["open_enrolled_exercise", "not_attempted"], P, v) == \
                (A.constraint("open_enrolled_exercise", P, v, {}) and A.constraint("not_attempted", P, v, {}))
    assert n > 1500 and Z.client.errors == 0 and Z.client.missing_request_id == 0


def test_references_filters_attribution_and_derive_match_db_mode(pair):
    A, Z, q = pair
    admin = A.principal_by_username("admin")
    users, courses = q("SELECT username, full_name FROM users"), q("SELECT code, title FROM courses")
    refs = {"user": [r["username"] for r in users] + [r["full_name"] for r in users]
                    + [r["full_name"].upper() for r in users] + [r["full_name"][:3] for r in users] + ["1", "9999", "%"],
            "course": [r["code"] for r in courses] + [r["code"].lower() for r in courses]
                      + [r["code"][:2] + " " + r["code"][2:] for r in courses] + [r["title"].split()[0] for r in courses]
                      + ["1", "99", "%"],
            "assignment": ["1", "6.0", "99", "x"], "submission": ["1", "6", "99"], "exercise": ["1", "2", "99"]}
    for kind, values in refs.items():
        for r in values:
            assert Z.resolve(kind, r, principal=admin) == A.resolve(kind, r), (kind, r)
    catalogue = [dict(r) for r in q("SELECT id, code, title FROM courses")]
    for u in q("SELECT id FROM users"):
        P = A.principal_by_id(u["id"])
        for f in ("my_courses", "taught_rows", "own_rows", "drop_password_hash"):
            rows = [dict(r, student_id=u["id"], username=P["username"]) for r in catalogue]
            assert Z.apply_filter(f, P, "list_courses", rows, {}) == A.apply_filter(f, P, "list_courses", rows, {})
    for cid in _ids(q, "course"):
        a = A.authors_of("get_course", {"course_ref": cid}, [], "course_teacher")
        z = Z.authors_of("get_course", {"course_ref": cid}, [], "course_teacher", principal=admin)
        assert [(x["id"], x["username"], x["ref"]) for x in a] == [(x["id"], x["username"], x["ref"]) for x in z]
    for sid in _ids(q, "submission"):
        assert Z.derive("submission_owner", {"submission_id": sid}) == A.derive("submission_owner", {"submission_id": sid})
    assert Z.catalog()["constraints"].keys() == A.catalog()["constraints"].keys()


def test_bound_identity_arguments_are_compared_never_looked_up(pair):
    A, Z, _ = pair
    student = A.principal_by_username("sdi2400005")
    assert Z.resolve("user", "sdi2400005", principal=student, bound=True) == student["id"]
    assert Z.resolve("user", str(student["id"]), principal=student, bound=True) == student["id"]
    calls = Z.client.calls
    assert not Z.resolve("user", "sdi2400001", principal=student, bound=True)     # someone else: denied
    assert Z.client.calls == calls                                                # and no question was asked


def test_approval_cards_use_the_directory_and_ask_for_no_values(pair):
    A, Z, _ = pair
    teacher = A.principal_by_username("kpapadopoulos")
    card = Z.preview("set_final_grade", {"course_ref": 1, "student_ref": 5, "grade": 9}, teacher)
    assert card == {"title": "Αλλαγή τελικού βαθμού", "rows": [
        ["Φοιτητής", A._user_label(5)], ["Μάθημα", A._course_label(1)], ["Βαθμός", "— → 9"]]}


# ---------------------------------------------------------------------------------------------- a non-SQL store
def test_a_document_store_with_string_ids(tmp_path):
    """Resources with string ids (as a document store has) and a graph that never came from SQL."""
    model = DataModel.parse({
        "objects": {"user": {"table": "u", "fields": {"username": "u", "role": "r"}},
                    "ticket": {"table": "t", "fields": {"subject": "s"}}},
        "relations": {"ticket.owner": {"table": "t", "from": "id", "to": "o", "target": "user"}},
        "constraints": {"own_ticket": "ticket.owner"}})
    graph = {"objects": {"user": {"7": {"username": "ana", "role": "customer"}},
                         "ticket": {"65f1c0a2e4b0d1": {"subject": "Printer"}, "65f1c0a2e4b0d2": {"subject": "VPN"}}},
             "relations": {"ticket.owner": [["65f1c0a2e4b0d1", 7]]}}
    cfg = AuthzenConfig.parse({"identity": {"action": "identity"},
                               "resources": {"ticket": {"id": "string", "search": "list", "refs": [{"subject": "iexact"}],
                                                        "label": "{subject}"}},
                               "constraints": {"own_ticket": {"resource": "ticket"}}})
    app = create_pdp(model, GraphStore(model, graph), pdp_id=PDP)
    Z = EclassAuthzenAdapter(AuthzenClient(PDP, transport=flask_transport(app), cache_ttl=0), cfg)
    ana = {"id": 7, "username": "ana", "role": "customer", "attrs": {}}
    assert Z.verify_identity(ana)
    assert Z.constraint("own_ticket", ana, "65f1c0a2e4b0d1", {}) and not Z.constraint("own_ticket", ana, "65f1c0a2e4b0d2", {})
    assert Z.resolve("ticket", "printer", principal=ana) == "65f1c0a2e4b0d1"
    assert Z.resolve("ticket", "65f1c0a2e4b0d2", principal=ana) == "65f1c0a2e4b0d2"
    assert Z.scope_ids("own_ticket", ana) == {"65f1c0a2e4b0d1"}
    assert not Z.constraint("own_ticket", ana, "not an id!", {})


# ---------------------------------------------------------------------------------------------- the wire
class FakePdp:
    """A scripted PDP: `answers[path]` is a list of (status, headers, body) or a callable(body, headers)."""

    def __init__(self, metadata=True, echo=True):
        self.log, self.answers, self.echo = [], {}, echo
        self.metadata = {"policy_decision_point": PDP,
                         "access_evaluation_endpoint": PDP + "/access/v1/evaluation",
                         "access_evaluations_endpoint": PDP + "/access/v1/evaluations",
                         "search_resource_endpoint": PDP + "/access/v1/search/resource",
                         "search_subject_endpoint": PDP + "/access/v1/search/subject"} if metadata else None

    def __call__(self, method, url, body, headers, timeout, verify):
        path = url[len(PDP):]
        self.log.append((method, path, body, dict(headers)))
        if path == "/.well-known/authzen-configuration":
            return (200, {}, self.metadata) if self.metadata else (404, {}, None)
        a = self.answers[path]
        status, h, b = a(body, headers) if callable(a) else a.pop(0)
        h = dict(h)
        if self.echo and "x-request-id" not in h:
            h["x-request-id"] = headers.get("X-Request-ID")
        return status, h, b


def test_the_client_sends_standard_requests_with_a_request_id_and_the_token():
    pdp = FakePdp()
    pdp.answers["/access/v1/evaluation"] = [(200, {}, {"decision": True})]
    c = AuthzenClient(PDP, token="tok", transport=pdp)
    assert c.evaluate({"type": "user", "id": "9"}, {"name": "enrolled"}, {"type": "course", "id": "1"})
    method, path, body, headers = pdp.log[-1]
    assert (method, path) == ("POST", "/access/v1/evaluation")
    assert body == {"subject": {"type": "user", "id": "9"}, "action": {"name": "enrolled"},
                    "resource": {"type": "course", "id": "1"}}
    assert headers["Authorization"] == "Bearer tok" and len(headers["X-Request-ID"]) == 32


@pytest.mark.parametrize("answer", [{"decision": "true"}, {"decision": 1}, {}, {"decision": None},
                                    {"decision": False, "context": {"reason": "no"}}])
def test_anything_but_decision_true_is_a_deny(answer):
    pdp = FakePdp()
    pdp.answers["/access/v1/evaluation"] = [(200, {}, answer)]
    assert AuthzenClient(PDP, transport=pdp).evaluate({"type": "user", "id": "9"}, {"name": "x"},
                                                      {"type": "course", "id": "1"}) is False


def test_metadata_naming_another_pdp_is_refused():
    pdp = FakePdp()
    pdp.metadata["policy_decision_point"] = "https://evil.example"
    with pytest.raises(AuthzenError, match="does not match"):
        AuthzenClient(PDP, transport=pdp).evaluate({"type": "user", "id": "9"}, {"name": "x"}, {"type": "c", "id": "1"})


def test_a_mismatched_request_id_is_rejected_and_a_missing_one_counted():
    pdp = FakePdp(echo=False)
    pdp.answers["/access/v1/evaluation"] = [(200, {"x-request-id": "someone-elses"}, {"decision": True}),
                                            (200, {}, {"decision": True})]
    c = AuthzenClient(PDP, transport=pdp)
    with pytest.raises(AuthzenError, match="another X-Request-ID"):
        c.evaluate({"type": "user", "id": "9"}, {"name": "x"}, {"type": "c", "id": "1"})
    assert c.evaluate({"type": "user", "id": "9"}, {"name": "x"}, {"type": "c", "id": "1"})
    assert c.missing_request_id == 1 and c.errors == 1


@pytest.mark.parametrize("status", [400, 401, 403, 500, 502])
def test_http_errors_are_errors_not_denials(status):
    pdp = FakePdp()
    pdp.answers["/access/v1/evaluation"] = [(status, {}, {"message": "nope"})]
    with pytest.raises(AuthzenError, match=f"HTTP {status}"):
        AuthzenClient(PDP, transport=pdp).evaluate({"type": "user", "id": "9"}, {"name": "x"}, {"type": "c", "id": "1"})


def test_all_of_is_one_batch_that_stops_at_the_first_deny():
    pdp = FakePdp()
    pdp.answers["/access/v1/evaluations"] = [(200, {}, {"evaluations": [{"decision": True}, {"decision": False}]}),
                                             (200, {}, {"evaluations": [{"decision": True}]})]
    c = AuthzenClient(PDP, transport=pdp)
    items = [({"name": "a"}, {"type": "c", "id": "1"}), ({"name": "b"}, {"type": "c", "id": "1"}),
             ({"name": "c"}, {"type": "c", "id": "1"})]
    assert c.evaluate_all({"type": "user", "id": "9"}, items) is False
    assert pdp.log[-1][2]["options"] == {"evaluations_semantic": "deny_on_first_deny"}
    assert c.evaluate_all({"type": "user", "id": "9"}, items) is False          # a short answer is not a permit


def test_without_metadata_the_standard_paths_are_used_and_no_batch():
    pdp = FakePdp(metadata=False)
    pdp.answers["/access/v1/evaluation"] = [(200, {}, {"decision": True}), (200, {}, {"decision": True})]
    c = AuthzenClient(PDP, transport=pdp)
    assert c.evaluate_all({"type": "user", "id": "9"}, [({"name": "a"}, {"type": "c", "id": "1"}),
                                                        ({"name": "b"}, {"type": "c", "id": "1"})])
    assert [p for _, p, _, _ in pdp.log] == ["/.well-known/authzen-configuration", "/access/v1/evaluation",
                                             "/access/v1/evaluation"]


def test_searches_follow_pages_and_a_runaway_search_fails_closed():
    pdp = FakePdp()
    pages = iter([{"results": [{"type": "course", "id": "1"}], "page": {"next_token": "a"}},
                  {"results": [{"type": "course", "id": "2"}, {"type": "user", "id": "3"}], "page": {"next_token": "b"}},
                  {"results": [{"type": "course", "id": "4", "properties": {"code": "X"}}], "page": {"next_token": ""}}])
    pdp.answers["/access/v1/search/resource"] = lambda body, h: (200, {}, next(pages))
    c = AuthzenClient(PDP, transport=pdp, cache_ttl=0)
    out = c.search_resources({"type": "user", "id": "9"}, {"name": "enrolled"}, "course")
    assert [r["id"] for r in out] == ["1", "2", "4"] and out[2]["properties"] == {"code": "X"}   # wrong type skipped
    assert [b["page"].get("token") for _, p, b, _ in pdp.log if p.endswith("resource")] == [None, "a", "b"]
    pdp.answers["/access/v1/search/resource"] = lambda body, h: (200, {}, {"results": [], "page": {"next_token": "more"}})
    with pytest.raises(AuthzenError, match=f"more than {MAX_PAGES} pages"):
        c.search_resources({"type": "user", "id": "9"}, {"name": "enrolled"}, "course")


def test_searches_are_cached_briefly_and_evaluations_never():
    pdp = FakePdp()
    pdp.answers["/access/v1/search/resource"] = lambda b, h: (200, {}, {"results": [], "page": {"next_token": ""}})
    pdp.answers["/access/v1/evaluation"] = lambda b, h: (200, {}, {"decision": True})
    c = AuthzenClient(PDP, transport=pdp, cache_ttl=60)
    for _ in range(3):
        c.search_resources({"type": "user", "id": "9"}, {"name": "x"}, "course")
        c.evaluate({"type": "user", "id": "9"}, {"name": "x"}, {"type": "c", "id": "1"})
    paths = [p for _, p, _, _ in pdp.log]
    assert paths.count("/access/v1/search/resource") == 1 and paths.count("/access/v1/evaluation") == 3


# ---------------------------------------------------------------------------------------------- the reference PDP
def test_the_reference_pdp_follows_the_http_binding(graph):
    c = create_pdp(MODEL, GraphStore(MODEL, graph), token="t0k", pdp_id=PDP).test_client()
    auth = {"Authorization": "Bearer t0k", "X-Request-ID": "r-1"}
    meta = c.get("/.well-known/authzen-configuration").get_json()
    assert meta["policy_decision_point"] == PDP and meta["access_evaluations_endpoint"].startswith(PDP)
    r = c.post("/access/v1/evaluation", json={"subject": {"type": "user", "id": "9"}})
    assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
    r = c.post("/access/v1/evaluation", json={"subject": {"type": "user", "id": "9"}}, headers=auth)
    assert r.status_code == 400 and r.headers["X-Request-ID"] == "r-1"
    ev = {"subject": {"type": "user", "id": "9"}, "action": {"name": "enrolled"}}
    one = lambda cid: dict(resource={"type": "course", "id": str(cid)})
    r = c.post("/access/v1/evaluations", headers=auth, json=dict(ev, evaluations=[one(4), one(1), one(4)]))
    assert [d["decision"] for d in r.get_json()["evaluations"]] == [False, True, False]
    for sem, n in (("deny_on_first_deny", 1), ("permit_on_first_permit", 2)):
        r = c.post("/access/v1/evaluations", headers=auth,
                   json=dict(ev, evaluations=[one(4), one(1), one(4)], options={"evaluations_semantic": sem}))
        assert len(r.get_json()["evaluations"]) == n
    r = c.post("/access/v1/search/resource", headers=auth,
               json=dict(ev, resource={"type": "course"}, page={"limit": 2}))
    body = r.get_json()
    assert len(body["results"]) == 2 and body["page"]["next_token"] == "2" and body["results"][0]["properties"]["code"]
    r = c.post("/access/v1/search/action", headers=auth,
               json={"subject": {"type": "user", "id": "9"}, "resource": {"type": "course", "id": "1"}})
    assert {"name": "enrolled"} in r.get_json()["results"]


def test_the_reference_pdp_can_decide_live_through_the_views(eclass_db, pair):
    A, _, q = pair
    store = ViewsStore(MODEL, SqliteViews(eclass_db, MODEL, previews=False))
    Z = EclassAuthzenAdapter(AuthzenClient(PDP, transport=flask_transport(create_pdp(MODEL, store, pdp_id=PDP)),
                                           cache_ttl=0), CONFIG)
    student = A.principal_by_username("sdi2400005")
    cid = next(r["id"] for r in q("SELECT id FROM courses")
               if not q("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?", (student["id"], r["id"])))
    assert not Z.constraint("enrolled", student, cid, {})
    con = sqlite3.connect(eclass_db)
    con.execute("INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)", (student["id"], cid))
    con.commit()
    con.close()
    assert Z.constraint("enrolled", student, cid, {})                    # the PDP is live, and nothing is cached


# ---------------------------------------------------------------------------------------------- failing closed
def test_an_unreachable_pdp_fails_closed():
    from laocoon.policy import Policy

    def down(*a, **kw):
        raise AuthzenError("ConnectionError: refused")
    Z = EclassAuthzenAdapter(AuthzenClient(PDP, transport=down), CONFIG)
    student = {"id": 9, "username": "sdi2400005", "role": "student", "attrs": {}}
    with pytest.raises(Unverifiable):
        Z.constraint("enrolled", student, 1, {})
    assert not Z.verify_identity(student) and Z.choices("enrolled", student) is None
    assert Z.apply_filter("my_courses", student, "list_courses", [{"id": 1}], {}) == []
    assert Z.constraint("self", student, 9, {}) and Z.constraint("read_only_sql", student, "SELECT 1", {})
    d, _, _ = Policy(POLICY, Z).evaluate(student, "read_forum", {"course_ref": "1"})
    assert (d.action, d.rule, d.severity) == ("deny", "abac_unverifiable", "medium")


def test_a_pdp_without_properties_degrades_to_ids(graph):
    """A PDP that answers only type and id (all AuthZEN requires): references by id still work, names do not,
    there is no enum, and filters that need labels drop their rows."""
    app = create_pdp(MODEL, GraphStore(MODEL, graph), pdp_id=PDP)
    inner = flask_transport(app)

    def bare(method, url, body, headers, timeout, verify):
        status, h, data = inner(method, url, body, headers, timeout, verify)
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            data = dict(data, results=[{k: v for k, v in r.items() if k != "properties"} for r in data["results"]])
        return status, h, data
    Z = EclassAuthzenAdapter(AuthzenClient(PDP, transport=bare, cache_ttl=0), CONFIG)
    teacher = {"id": 2, "username": "kpapadopoulos", "role": "teacher", "attrs": {}}
    assert Z.resolve("course", "1", principal=teacher) == 1 and Z.resolve("course", "CS101", principal=teacher) is None
    assert Z.choices("taught", teacher) is None
    assert Z.apply_filter("taught_rows", teacher, "get_grades", [{"code": "CS101"}], {}) == []
    assert Z.apply_filter("my_courses", teacher, "list_courses", [{"id": 1}, {"id": 4}], {}) == [{"id": 1}]


# ---------------------------------------------------------------------------------------------- the proxy
SYSTEM = ("You are Athena.\n- User id: {id}\n- Username: {username}\n- Name: {full_name}\n- Role: {role}\n")


@pytest.fixture
def authzen_proxy(eclass_db, graph, tmp_path, monkeypatch):
    for k, v in {"LAOCOON_DB": str(tmp_path / "lcn.db"), "LAOCOON_POLICY": str(DEFAULT_POLICY),
                 "LAOCOON_SECRET": "test-secret", "LAOCOON_GUARD_BACKEND": "off", "LAOCOON_AUTHZ_SOURCE": "authzen",
                 "LAOCOON_IDENTITY": "system_prompt", "LAOCOON_UPSTREAM_BASE_URL": "http://upstream.test/v1",
                 "LAOCOON_ECLASS_DB": str(tmp_path / "nowhere" / "eclass.db"), "LAOCOON_AUTHZEN_PDP": HTTPS_PDP,
                 "LAOCOON_AUTHZEN_TOKEN": "t0k"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("LAOCOON_APP_KEY", raising=False)
    users = {r["username"]: r for r in readonly_query(eclass_db)("SELECT id, username, full_name, role FROM users")}
    pdp_app = create_pdp(MODEL, GraphStore(MODEL, graph), token="t0k", pdp_id=HTTPS_PDP)
    import laocoon.authzen as AZ
    monkeypatch.setattr(AZ, "_requests_transport", lambda: flask_transport(pdp_app))
    real_connect = sqlite3.connect

    def guarded(path, *a, **kw):                          # the proxy never opens the app's database
        assert str(eclass_db) not in str(path), "the proxy opened the eClass database"
        return real_connect(path, *a, **kw)
    monkeypatch.setattr(sqlite3, "connect", guarded)
    from test_views import Upstream
    up = Upstream()
    monkeypatch.setattr(PX.requests, "post", up)
    app = PX.create_app()
    client = app.test_client()

    def chat(who, text, calls=None, **forge):
        if calls:
            up.queue.append({"role": "assistant", "content": "", "tool_calls": [
                {"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}
                for i, (n, a) in enumerate(calls)]})
        system = SYSTEM.format(**{**users[who], **forge})
        return client.post("/v1/chat/completions", json={"model": "m", "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": text}],
            "tools": [{"type": "function", "function": d} for d in DECLARATIONS]})
    return chat, up, app


def test_the_proxy_decides_through_the_pdp_without_a_database(authzen_proxy):
    chat, up, app = authzen_proxy
    r = chat("sdi2400005", "Read the CS101 forum", [("read_forum", {"course_ref": "CS101"})])
    msg = r.get_json()["choices"][0]["message"]
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"course_ref": 1}
    forum = next(t["function"] for t in up.calls[-1]["tools"] if t["function"]["name"] == "read_forum")
    assert forum["parameters"]["properties"]["course_ref"]["enum"] == ["CS101", "CS220", "CS340"]
    msg = chat("sdi2400005", "Read the CS450 forum", [("read_forum", {"course_ref": "CS450"})]).get_json()
    assert not msg["choices"][0]["message"].get("tool_calls")
    msg = chat("kpapadopoulos", "Grade 1", [("grade_submission", {"submission_id": 1, "grade": 9})]).get_json()
    assert "ap_" in msg["choices"][0]["message"]["content"]
    st = app.config["laocoon_state"]["guard"].adapter.status()
    assert st["errors"] == 0 and st["calls"] > 0


def test_the_pdp_confirms_the_identity_block(authzen_proxy):
    chat, _, _ = authzen_proxy
    assert chat("sdi2400005", "hi").status_code == 200
    assert chat("sdi2400005", "hi", role="admin").status_code == 401              # the PDP says student
    assert chat("sdi2400005", "hi", username="admin").status_code == 401


def test_system_prompt_identity_needs_an_identity_action(monkeypatch, tmp_path):
    import yaml
    data = yaml.safe_load(DEFAULT_POLICY.read_text(encoding="utf-8"))
    data["authzen"].pop("identity")
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    for k, v in {"LAOCOON_DB": str(tmp_path / "lcn.db"), "LAOCOON_POLICY": str(p), "LAOCOON_SECRET": "test-secret",
                 "LAOCOON_GUARD_BACKEND": "off", "LAOCOON_AUTHZ_SOURCE": "authzen", "LAOCOON_AUTHZEN_PDP": HTTPS_PDP,
                 "LAOCOON_IDENTITY": "system_prompt"}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError, match="identity.action"):
        PX.build_guard(PX.ProxyConfig())


def test_the_pdp_address_must_be_https_outside_localhost(monkeypatch):
    from laocoon.authzen import client_from_env
    env = {"LAOCOON_AUTHZEN_PDP": "http://pdp.example.com"}.get
    with pytest.raises(ValueError, match="https"):
        client_from_env(env)
    assert client_from_env({"LAOCOON_AUTHZEN_PDP": "https://pdp.example.com/"}.get).pdp == "https://pdp.example.com"


def test_a_real_http_round_trip(graph):
    from eval.mockllm import ServerThread
    srv = ServerThread(create_pdp(MODEL, GraphStore(MODEL, graph), token="t0k"))
    srv.start()
    try:
        c = AuthzenClient(srv.url, token="t0k")
        assert c.evaluate({"type": "user", "id": "9"}, {"name": "enrolled"}, {"type": "course", "id": "1"})
        assert c.metadata["policy_decision_point"] == srv.url and c.missing_request_id == 0
    finally:
        srv.stop()


# ---------------------------------------------------------------------------------------------- the studio
def test_the_studio_checks_the_authzen_mapping(pair):
    _, Z, _ = pair
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    res = studio.analyse(Z, text=text)
    assert res["ok"], [i for i in res["issues"] if i["level"] == "error"]
    import yaml                                     # the form's canonical layout keeps entries with only defaults
    assert studio.analyse(Z, data=yaml.safe_load(text))["ok"]                   # (submission.student: {})
    bad = text.replace("taught_submission:      {resource: submission}", "taught_submission:      {resource: room}")
    res = studio.analyse(Z, text=bad)
    assert not res["ok"] and any("'room' is not in authzen.resources" in i["message"] for i in res["issues"])
    missing = text.replace("    not_attempted:          {resource: exercise}\n", "")
    res = studio.analyse(Z, text=missing)
    assert any("not_attempted" in i["message"] and i["level"] == "warning" for i in res["issues"])
    assert not any("search" in i["message"] for i in studio.analyse(Z, text=text)["issues"])  # every kind has one


HELPDESK = """
version: 2
roles: [agent, admin]
refs: {ticket_id: ticket}
authzen:
  resources:
    ticket: {type: ticket, id: string%s}
  constraints:
    team_ticket: {resource: ticket}
tools:
  get_ticket: {effect: read, allow: {agent: {ticket_id: team_ticket}, admin: true}}
"""


def test_an_id_without_a_search_is_checked_only_by_constraints():
    """A kind without `search` cannot be asked whether an id exists. Constraints still ask the PDP; a rule of
    `true` sends the id on as written, and the studio names each such tool and role."""
    import yaml
    from laocoon.adapters.authzen import AuthzenAdapter
    from laocoon.config import normalise_policy
    from laocoon.policy import Policy

    res = studio.analyse(AuthzenAdapter(config=AuthzenConfig.parse(yaml.safe_load(HELPDESK % "")["authzen"])),
                         text=HELPDESK % "")
    warn = [i for i in res["issues"] if i["level"] == "warning" and "search" in i["message"]]
    assert res["ok"] and len(warn) == 1 and "get_ticket/admin" in warn[0]["message"] and warn[0]["line"] == 7

    class Pdp:
        tickets = {"t1": {}}

        def __call__(self, method, url, body, headers, timeout, verify):
            rid = {"x-request-id": headers.get("X-Request-ID")}
            if url.endswith("/access/v1/evaluation"):
                return 200, rid, {"decision": body["resource"]["id"] in self.tickets}
            if url.endswith("/access/v1/search/resource"):
                return 200, rid, {"results": [{"type": "ticket", "id": i} for i in self.tickets], "page": {"next_token": ""}}
            return 404, rid, None

    admin, agent = {"id": 1, "role": "admin", "username": "root"}, {"id": 2, "role": "agent", "username": "ana"}
    for search, unknown_for_admin in (("", "allow"), (", search: view", "deny")):
        data = normalise_policy(yaml.safe_load(HELPDESK % search))
        pol = Policy(data, AuthzenAdapter(AuthzenClient(HTTPS_PDP, transport=Pdp(), cache_ttl=0),
                                          AuthzenConfig.from_policy(data)))
        assert pol.evaluate(agent, "get_ticket", {"ticket_id": "t1"})[0] is None
        assert pol.evaluate(agent, "get_ticket", {"ticket_id": "nope"})[0].rule == "abac"   # the PDP denies it
        d = pol.evaluate(admin, "get_ticket", {"ticket_id": "nope"})[0]
        assert ("allow" if d is None else "deny") == unknown_for_admin
        assert pol.evaluate(admin, "get_ticket", {"ticket_id": "t1"})[0] is None

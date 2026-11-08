"""LAOCOON_AUTHZ_SOURCE=views: a database login that can read only the views of the policy's data_model.

On SQLite the boundary is Laocoon's own (TEMP views + an authorizer); the PostgreSQL tests, where the database
enforces it, are in test_views_pg.py. Parity with `db` mode is checked exhaustively on the seeded eClass: every
constraint for every user and every object, references, scope enums, filters, attribution, derive.
"""
import hashlib
import json
import shutil
import sqlite3

import pytest

from app.tools import DECLARATIONS
from laocoon import proxy as PX
from laocoon import studio
from laocoon.adapters.eclass import EclassAdapter, readonly_query
from laocoon.adapters.eclass_views import EclassViewsAdapter
from laocoon.config import DEFAULT_POLICY, load_policy
from laocoon.facts import Unverifiable
from laocoon.views import DataModel, Denied, ModelError, SqliteViews, export, setup_sql

POLICY = load_policy(DEFAULT_POLICY)
MODEL = DataModel.from_policy(POLICY)
TABLE = {"user": "users", "course": "courses", "assignment": "assignments", "submission": "submissions",
         "exercise": "exercises"}
KIND_OF = {"self": "user", "taught": "course", "enrolled": "course", "student_of_taught": "user",
           "enrolled_assignment": "assignment", "taught_assignment": "assignment", "enrolled_exercise": "exercise",
           "taught_exercise": "exercise", "open_enrolled_exercise": "exercise", "taught_submission": "submission",
           "not_attempted": "exercise"}
JUNK = ["abc", None, "1e999", -1, "nan", 2 ** 60, True]


@pytest.fixture
def eclass_db(template_db, tmp_path):
    db = tmp_path / "eclass.db"
    shutil.copy(template_db, db)
    return str(db)


@pytest.fixture
def pair(eclass_db):
    """(the db adapter, the views adapter, the raw query) on the same database file."""
    return EclassAdapter(readonly_query(eclass_db)), EclassViewsAdapter(SqliteViews(eclass_db, MODEL), MODEL), \
        readonly_query(eclass_db)


def _ids(q, kind):
    return [r["id"] for r in q(f"SELECT id FROM {TABLE[kind]}")] + [0, 9999]


# ---------------------------------------------------------------------------------------------- the model
def test_the_shipped_model_covers_every_data_constraint_of_the_policy():
    data_constraints = set(EclassAdapter.CONSTRAINTS) - {"self", "read_only_sql"}
    assert set(MODEL.constraints) == data_constraints
    views = {v for v, _, _, _ in MODEL.views(previews=False)}
    assert views == {"obj_user", "obj_course", "obj_assignment", "obj_submission", "obj_exercise",
                     "rel_course_teacher", "rel_course_member", "rel_assignment_course", "rel_submission_assignment",
                     "rel_submission_student", "rel_exercise_course", "rel_exercise_attempted_by"}
    read = {(t, c) for _, t, cols, _ in MODEL.views(previews=False) for _, c in cols}
    for pii in ("password_hash", "amka", "iban", "id_card", "phone", "address", "admin_notes", "email", "grade"):
        assert not any(c == pii for _, c in read), pii
    assert ("users", "full_name") in read and ("exercises", "is_open") in read


BAD = [
    ({"objects": {"user": {"table": "users; DROP TABLE x", "fields": {"username": "u", "role": "r"}}}},
     "not a valid table name"),
    ({"objects": {"user": {"table": "users", "fields": {"username": "u"}}}}, "needs a field 'role'"),
    ({"constraints": {"taught": "course.boss"}}, "course has no relation 'boss'"),
    ({"constraints": {"taught": "course.code"}}, None),                         # a field test is allowed
    ({"constraints": {"taught": "course.code.teacher"}}, "nor a field, which can only come last"),
    ({"constraints": {"x": "assignment.course"}}, "must end at the user or at a field"),
    ({"relations": {"user.courses": {"reverse": "course.nothing"}}}, "is not a forward relation"),
    ({"relations": {"course.teacher": {"table": "courses", "from": "id", "to": "teacher_id", "target": "room"}}},
     "'room' is not an object kind"),
    ({"objects": {"course": {"table": "courses", "fields": {"code": "code"}, "refs": [{"code": "regex"}]}}},
     "match is one of"),
    ({"surprise": 1}, "unknown key"),
]


@pytest.mark.parametrize("patch,message", BAD)
def test_model_errors_name_the_place(patch, message):
    dm = json.loads(json.dumps(POLICY["data_model"]))
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(dm.get(k), dict):
            dm[k].update(v)
        else:
            dm[k] = v
    if message is None:
        DataModel.parse(dm)
        return
    with pytest.raises(ModelError) as e:
        DataModel.parse(dm)
    assert message in str(e.value)


def test_paths_compile_to_joins_over_views_only():
    from laocoon.views import Compiler, Dialect
    c = Compiler(MODEL, Dialect(), "temp")
    sql, n = c.check(MODEL.constraints["taught_submission"][0])
    assert n == 2 and sql == (
        'SELECT 1 AS ok FROM "temp"."rel_submission_assignment" r0 '
        'JOIN "temp"."rel_assignment_course" r1 ON r1."assignment_id" = r0."assignment_id" '
        'JOIN "temp"."rel_course_teacher" r2 ON r2."course_id" = r1."course_id" '
        'WHERE r0."submission_id" = ? AND r2."teacher_id" = ? LIMIT 1')
    for name, paths in MODEL.constraints.items():
        for p in paths:
            sql, _ = c.check(p)
            for table in TABLE.values():
                assert f'"{table}"' not in sql, (name, sql)          # never an app table


# ---------------------------------------------------------------------------------------------- setup scripts
def test_postgres_script_grants_the_views_and_nothing_else():
    sql = setup_sql(MODEL, "postgres")
    grants = [line for line in sql.splitlines() if line.startswith("GRANT")]
    assert grants[0] == 'GRANT USAGE ON SCHEMA "laocoon" TO "laocoon";'
    assert all(g.startswith('GRANT SELECT ON "laocoon".') for g in grants[1:]) and len(grants) == 13
    assert '"public"' not in " ".join(grants) and "amka" not in sql and "final_grades" not in sql
    assert "default_transaction_read_only = on" in sql and "PASSWORD" not in sql
    assert sql.count("CREATE VIEW") == 12 and "BEGIN;" in sql and sql.rstrip().endswith("narrow.")
    with_previews = setup_sql(MODEL, "postgres", previews=True)
    assert 'GRANT SELECT ON "laocoon"."prev_final_grade"' in with_previews and "PERSONAL DATA" in with_previews


def test_functions_script_grants_execute_instead_of_relations():
    sql = setup_sql(MODEL, "postgres", functions=True)
    assert 'GRANT SELECT ON "laocoon"."rel_' not in sql and 'GRANT SELECT ON "laocoon"."obj_user"' in sql
    for name in MODEL.constraints:
        assert f'"can_{name}"' in sql
    assert sql.count("SECURITY DEFINER SET search_path = pg_catalog, pg_temp") == sql.count("REVOKE ALL ON FUNCTION")
    assert '"scope_taught"' in sql and '"scope_enrolled"' in sql and '"derive_submission_owner"' in sql
    with pytest.raises(ValueError):
        setup_sql(MODEL, "mysql", functions=True)


def test_mysql_script_uses_definer_views():
    with pytest.raises(ValueError):
        setup_sql(MODEL, "mysql")                                     # the app's database must be named
    sql = setup_sql(MODEL, "mysql", app_schema="eclass")
    assert sql.count("CREATE OR REPLACE SQL SECURITY DEFINER VIEW `laocoon`.") == 12
    assert "FROM `eclass`.`users`" in sql and "GRANT SELECT ON `laocoon`.`obj_user` TO 'laocoon'@'%';" in sql


# ---------------------------------------------------------------------------------------------- SQLite boundary
def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


@pytest.mark.parametrize("sql", [
    "SELECT amka FROM users",
    "SELECT u.password_hash FROM obj_user o JOIN users u ON u.id = o.id",
    "SELECT 1 FROM users WHERE iban LIKE 'GR%'",
    "SELECT count(*) FROM messages",
    "SELECT body FROM messages",
    "SELECT * FROM sqlite_master",
    "PRAGMA table_info(users)",
    "ATTACH DATABASE ':memory:' AS x",
    "CREATE TEMP TABLE t (x)",
    "INSERT INTO users (username) VALUES ('x')",
    "SELECT load_extension('x')",
    "SELECT group_concat(name) FROM obj_user",
])
def test_the_authorizer_refuses_anything_but_the_views(eclass_db, sql):
    before = _sha(eclass_db)
    db = SqliteViews(eclass_db, MODEL)
    with pytest.raises((Denied, sqlite3.DatabaseError)):
        db.query(sql)
    assert db.denials >= 1 and _sha(eclass_db) == before


def test_a_read_without_columns_is_allowed_only_on_tables_behind_a_view(eclass_db):
    """A view of the rowid alias alone (obj_submission is `id`) is flattened by SQLite into a read with no column and
    no view name. The authorizer lets such reads through for tables behind a view: they show only that rows exist,
    which the view shows anyway. Any column read straight from a table, even the id, is refused."""
    db = SqliteViews(eclass_db, MODEL)
    assert db.query('SELECT "id" FROM "temp"."obj_submission" WHERE "id" = 1', one=True) == {"id": 1}
    rows = db.query("SELECT 1 AS x FROM main.users")                  # existence only: the same count obj_user shows
    assert len(rows) == len(db.query('SELECT "id" FROM "temp"."obj_user"'))
    for sql in ("SELECT id FROM users", "SELECT rowid FROM users", "SELECT 1 AS x FROM main.messages",
                "SELECT 1 AS x FROM main.users WHERE amka > ''"):
        with pytest.raises(Denied):
            db.query(sql)


def test_the_views_read_and_the_file_is_never_modified(eclass_db):
    before = _sha(eclass_db)
    db = SqliteViews(eclass_db, MODEL)
    rows = db.query('SELECT * FROM "temp"."obj_user"')
    assert rows and set(rows[0]) == {"id", "username", "name", "role"}
    assert db.query('SELECT "id" FROM "temp"."obj_submission" WHERE "id" = ?', (1,), one=True) == {"id": 1}
    assert set(db.available()) == {v for v, _, _, _ in MODEL.views()}
    assert db.denials == 0 and _sha(eclass_db) == before
    con = sqlite3.connect(eclass_db)                                 # the TEMP views lived only in Laocoon's connection
    assert con.execute("SELECT count(*) FROM sqlite_master WHERE type = 'view'").fetchone()[0] == 0
    con.close()


# ---------------------------------------------------------------------------------------------- parity with db
def test_constraints_match_db_mode_for_every_user_and_object(pair):
    A, V, q = pair
    n = 0
    for u in q("SELECT id FROM users"):
        P = A.principal_by_id(u["id"])
        assert V.principal_by_id(u["id"]) == P
        for name, kind in KIND_OF.items():
            for v in _ids(q, kind) + JUNK:
                assert V.constraint(name, P, v, {}) == A.constraint(name, P, v, {}), (name, u["id"], v)
                n += 1
            assert V.choices(name, P) == A.choices(name, P), (name, u["id"])
    assert n > 2000 and V.db.denials == 0
    assert V.constraint("read_only_sql", P, "SELECT 1", {}) and not V.constraint("read_only_sql", P, "DROP x", {})


def test_references_match_db_mode(pair):
    A, V, q = pair
    users = q("SELECT username, full_name FROM users")
    courses = q("SELECT code, title FROM courses")
    refs = {"user": [r["username"] for r in users] + [r["full_name"] for r in users]
                    + [r["full_name"].upper() for r in users] + [r["full_name"].split()[-1] for r in users]
                    + [r["full_name"][:3] for r in users] + ["1", "2", "9999", " 7 ", "6.0", "", "zz", "%", "_"],
            "course": [r["code"] for r in courses] + [r["code"].lower() for r in courses]
                      + [r["code"][:2] + " " + r["code"][2:] for r in courses] + [r["title"] for r in courses]
                      + [r["title"].split()[0] for r in courses] + ["1", "99", "Intro", "%"],
            "assignment": ["1", "2", "6.0", "99", "x", " 3"], "submission": ["1", "6", "99"],
            "exercise": ["1", "2", "99", "1e3"]}
    for kind, values in refs.items():
        for r in values:
            assert V.resolve(kind, r) == A.resolve(kind, r), (kind, r)
    assert V.db.denials == 0


def test_filters_attribution_and_derive_match_db_mode(pair):
    A, V, q = pair
    catalogue = q("SELECT id, code, title, teacher_id FROM courses")
    for u in q("SELECT id FROM users"):
        P = A.principal_by_id(u["id"])
        for f in ("my_courses", "taught_rows", "own_rows", "public_profile", "drop_password_hash"):
            rows = [dict(r, student_id=u["id"], username=P["username"]) for r in catalogue]
            assert V.apply_filter(f, P, "list_courses", rows, {}) == A.apply_filter(f, P, "list_courses", rows, {})
    for cid in _ids(q, "course"):
        assert V.authors_of("read_forum", {"course_ref": cid}, [], "course_teacher") == \
            A.authors_of("read_forum", {"course_ref": cid}, [], "course_teacher")
    for sid in _ids(q, "submission") + ["x"]:
        assert V.derive("submission_owner", {"submission_id": sid}) == A.derive("submission_owner", {"submission_id": sid})
    assert V.catalog()["constraints"].keys() == A.catalog()["constraints"].keys()
    assert V.db.denials == 0


def test_approval_cards_show_before_values_only_from_granted_views(eclass_db, pair):
    A, V, q = pair
    teacher = A.principal_by_username("kpapadopoulos")
    sid = q("SELECT s.id FROM submissions s WHERE s.grade IS NOT NULL LIMIT 1", one=True)["id"]
    fg = q("SELECT course_id, student_id, grade FROM final_grades WHERE grade IS NOT NULL LIMIT 1", one=True)
    cases = [("set_final_grade", {"course_ref": fg["course_id"], "student_ref": fg["student_id"], "grade": 9}),
             ("grade_submission", {"submission_id": sid, "grade": 8, "feedback": "ok"}),
             ("send_message", {"to": 5, "subject": "s", "body": "b"}), ("enroll_user", {"user_ref": 5, "course_ref": 1}),
             ("update_user", {"user_ref": 5, "role": "teacher"}), ("post_forum", {"course_ref": 1, "title": "t", "body": "b"})]
    for tool, args in cases:                                             # with prev_* granted: the same card
        assert V.preview(tool, args, teacher) == A.preview(tool, args, teacher), tool
    bare = EclassViewsAdapter(SqliteViews(eclass_db, MODEL, previews=False), MODEL)
    card = bare.preview("set_final_grade", cases[0][1], teacher)
    assert card["rows"][-1] == ["Βαθμός", "— → 9"]                       # before-value not granted: not read
    assert bare.preview("grade_submission", cases[1][1], teacher)["rows"][2][1].startswith("— → 8")
    assert bare.preview("set_component_grade", {"course_ref": 1, "student_ref": 5, "component": "Mid", "grade": 7},
                        teacher)["rows"][-1] == ["Βαθμός", "— → 7"]
    assert V.db.denials == 0 and bare.db.denials == 0


# ---------------------------------------------------------------------------------------------- live, fail closed
def test_a_change_in_the_app_applies_to_the_next_check(pair, eclass_db):
    A, V, q = pair
    student = V.principal_by_username("sdi2400005")
    cid = next(r["id"] for r in q("SELECT id FROM courses")
               if not q("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?", (student["id"], r["id"])))
    assert not V.constraint("enrolled", student, cid, {})
    con = sqlite3.connect(eclass_db)                                     # the app enrolls them (web UI)
    con.execute("INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)", (student["id"], cid))
    con.commit()
    assert V.constraint("enrolled", student, cid, {})                     # no cache, no sync
    con.execute("DELETE FROM enrollments WHERE user_id = ? AND course_id = ?", (student["id"], cid))
    con.commit()
    con.close()
    assert not V.constraint("enrolled", student, cid, {})


def test_an_unreachable_database_fails_closed(tmp_path):
    from laocoon.policy import Policy
    V = EclassViewsAdapter(SqliteViews(tmp_path / "gone" / "eclass.db", MODEL), MODEL)
    student = {"id": 9, "username": "sdi2400005", "role": "student", "attrs": {}}
    with pytest.raises(Unverifiable):
        V.constraint("enrolled", student, 1, {})
    assert V.principal_by_id(9) is None and V.choices("enrolled", student) is None
    assert V.apply_filter("my_courses", student, "list_courses", [{"id": 1}], {}) == []
    assert V.constraint("self", student, 9, {})                           # needs no data
    d, _, _ = Policy(POLICY, V).evaluate(student, "read_forum", {"course_ref": "1"})
    assert (d.action, d.rule, d.severity) == ("deny", "abac_unverifiable", "medium")
    assert V.errors >= 1 and V.status()["missing"]


# ---------------------------------------------------------------------------------------------- export
def test_an_export_holds_only_the_views(eclass_db, tmp_path, pair):
    A, _, q = pair
    out = tmp_path / "laocoon-views.db"
    export(MODEL, eclass_db, out)
    blob = open(out, "rb").read()
    for r in q("SELECT amka, iban, password_hash FROM users WHERE amka IS NOT NULL"):
        assert r["amka"].encode() not in blob and r["iban"].encode() not in blob
    V = EclassViewsAdapter(SqliteViews(out, MODEL), MODEL)
    assert V.db.exported and V.db.ns == "main"
    for u in q("SELECT id FROM users"):
        P = A.principal_by_id(u["id"])
        for name, kind in KIND_OF.items():
            for v in _ids(q, kind):
                assert V.constraint(name, P, v, {}) == A.constraint(name, P, v, {}), (name, u["id"], v)
    with pytest.raises(Denied):
        V.db.query("SELECT * FROM sqlite_master")


# ---------------------------------------------------------------------------------------------- the proxy
SYSTEM = "You are Athena.\n- User id: {id}\n- Username: {username}\n- Role: {role}\n"
TOOLS = [{"type": "function", "function": d} for d in DECLARATIONS]


class Upstream:
    def __init__(self):
        self.calls, self.queue = [], []

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.calls.append(json)
        msg = self.queue.pop(0) if self.queue else {"role": "assistant", "content": "OK."}
        payload = {"id": "up", "object": "chat.completion", "model": "m",
                   "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}]}

        class R:
            status_code = 200
            content = b"{}"

            def json(self):
                return payload
        return R()


@pytest.fixture
def views_proxy(eclass_db, tmp_path, monkeypatch):
    for k, v in {"LAOCOON_DB": str(tmp_path / "lcn.db"), "LAOCOON_POLICY": str(DEFAULT_POLICY),
                 "LAOCOON_SECRET": "test-secret", "LAOCOON_GUARD_BACKEND": "off", "LAOCOON_AUTHZ_SOURCE": "views",
                 "LAOCOON_IDENTITY": "system_prompt", "LAOCOON_UPSTREAM_BASE_URL": "http://upstream.test/v1",
                 "LAOCOON_ECLASS_DB": eclass_db}.items():
        monkeypatch.setenv(k, v)
    for k in ("LAOCOON_APP_KEY", "LAOCOON_VIEWS_DSN", "LAOCOON_VIEWS_DB", "LAOCOON_GUARD_API_KEY", "TYPESAFE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    up = Upstream()
    monkeypatch.setattr(PX.requests, "post", up)
    app = PX.create_app()
    client = app.test_client()
    q = readonly_query(eclass_db)

    def chat(username, text, calls=None, system=None):
        u = q("SELECT id, username, role FROM users WHERE username = ?", (username,), one=True)
        if calls:
            up.queue.append({"role": "assistant", "content": "", "tool_calls": [
                {"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": json.dumps(a)}}
                for i, (n, a) in enumerate(calls)]})
        r = client.post("/v1/chat/completions", json={"model": "m", "tools": TOOLS, "messages": [
            {"role": "system", "content": system or SYSTEM.format(**u)}, {"role": "user", "content": text}]})
        return r
    return chat, up, app


def test_the_proxy_decides_through_the_views(views_proxy):
    chat, up, app = views_proxy
    r = chat("sdi2400005", "Read the CS101 forum", [("read_forum", {"course_ref": "CS101"})])
    guard = app.config["laocoon_state"]["guard"]                         # built on the first request
    assert isinstance(guard.adapter, EclassViewsAdapter)
    msg = r.get_json()["choices"][0]["message"]
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"course_ref": 1}     # resolved, allowed
    forum = next(t["function"] for t in up.calls[-1]["tools"] if t["function"]["name"] == "read_forum")
    assert forum["parameters"]["properties"]["course_ref"]["enum"] == ["CS101", "CS220", "CS340"]   # scope enum
    r = chat("sdi2400005", "Read the CS450 forum", [("read_forum", {"course_ref": "CS450"})])
    msg = r.get_json()["choices"][0]["message"]
    assert not msg.get("tool_calls") and "CS450" in msg["content"]                           # not enrolled: denied
    r = chat("kpapadopoulos", "Grade submission 1", [("grade_submission", {"submission_id": 1, "grade": 9})])
    msg = r.get_json()["choices"][0]["message"]
    assert "ap_" in msg["content"] and "→ 9" in msg["content"]                               # taught: approval card
    assert guard.adapter.db.denials == 0 and guard.adapter.errors == 0


def test_the_proxy_cross_checks_identity_through_the_views(views_proxy):
    chat, up, app = views_proxy
    forged = SYSTEM.format(id=9, username="sdi2400005", role="admin")
    assert chat("sdi2400005", "hi", system=forged).status_code == 401                      # the views say student
    assert chat("sdi2400005", "hi").status_code == 200


# ---------------------------------------------------------------------------------------------- the studio
def test_the_studio_checks_the_data_model(pair):
    _, V, _ = pair
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    res = studio.analyse(V, text=text)
    assert res["ok"], [i for i in res["issues"] if i["level"] == "error"]
    assert not any("data_model" in i["message"] and "Άγνωστο" in i["message"] for i in res["issues"])
    bad = text.replace("fields: {username: username, name: full_name, role: role}",
                       "fields: {username: username, name: full_name, role: role, amka: amka}")
    res = studio.analyse(V, text=bad)
    assert not res["ok"] and any("users.amka" in i["message"] for i in res["issues"])
    broken = text.replace("taught_submission:      submission.assignment.course.teacher",
                          "taught_submission:      submission.course.teacher")
    res = studio.analyse(V, text=broken)
    assert not res["ok"] and any("submission has no relation 'course'" in i["message"] for i in res["issues"])

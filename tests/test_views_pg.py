"""LAOCOON_AUTHZ_SOURCE=views on PostgreSQL, where the database itself enforces the boundary.

The seeded eClass is loaded into a real PostgreSQL, the generated setup script is run as the tables' owner, and
Laocoon connects as the login it creates. Skipped unless `psycopg` and a server are available: either
LAOCOON_TEST_PG_DSN (a superuser DSN of a server to create a throwaway database on) or the `pgserver` package
(pip install -r requirements-pg.txt), which bundles PostgreSQL.
"""
import os
import sqlite3

import pytest

psycopg = pytest.importorskip("psycopg")

from app import seed                                             # noqa: E402  the organisers' eClass (read-only use)
from laocoon.adapters.eclass import EclassAdapter, readonly_query  # noqa: E402
from laocoon.adapters.eclass_views import EclassViewsAdapter      # noqa: E402
from laocoon.config import DEFAULT_POLICY, load_policy            # noqa: E402
from laocoon.facts import Unverifiable                            # noqa: E402
from laocoon.views import DataModel, Denied, PostgresViews, setup_sql  # noqa: E402

MODEL = DataModel.from_policy(load_policy(DEFAULT_POLICY))
KIND_TABLE = {"taught": "courses", "enrolled": "courses", "student_of_taught": "users",
              "enrolled_assignment": "assignments", "taught_assignment": "assignments",
              "enrolled_exercise": "exercises", "taught_exercise": "exercises", "open_enrolled_exercise": "exercises",
              "taught_submission": "submissions", "not_attempted": "exercises"}


def _with_db(dsn, name):
    """The same DSN, another database (URI or key=value form)."""
    if dsn.startswith(("postgresql://", "postgres://")):
        head, _, tail = dsn.partition("?")
        base = head.rsplit("/", 1)[0] if head.count("/") > 2 else head
        return f"{base}/{name}" + (f"?{tail}" if tail else "")
    return f"{dsn} dbname={name}"


@pytest.fixture(scope="module")
def pg(template_db, tmp_path_factory):
    admin = os.environ.get("LAOCOON_TEST_PG_DSN")
    srv = None
    if not admin:
        pgserver = pytest.importorskip("pgserver")
        srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
        admin = srv.get_uri()
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS laocoon_views_test")
        c.execute("CREATE DATABASE laocoon_views_test")
        c.execute("DROP ROLE IF EXISTS laocoon_t")
    owner = _with_db(admin, "laocoon_views_test")
    src = sqlite3.connect(template_db)
    src.row_factory = sqlite3.Row
    with psycopg.connect(owner, autocommit=True) as c:          # eClass's own DDL runs on PostgreSQL as it is
        c.execute(seed.SCHEMA)
        c.execute("SET session_replication_role = replica")     # rows in any order (no FK triggers)
        for (t,) in src.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"):
            rows = src.execute(f"SELECT * FROM {t}").fetchall()
            if rows:
                cols = list(rows[0].keys())
                with c.cursor() as cur:
                    cur.executemany(f"INSERT INTO {t} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})",
                                    [tuple(r) for r in rows])
    src.close()

    def install(functions=False, previews=True):
        with psycopg.connect(owner, autocommit=True) as c:
            c.execute("DROP SCHEMA IF EXISTS laocoon CASCADE")
            c.execute(setup_sql(MODEL, "postgres", role="laocoon_t", previews=previews, functions=functions))
            c.execute("ALTER ROLE laocoon_t PASSWORD 'pw-test'")
        user_dsn = owner.replace("postgres:@", "laocoon_t:pw-test@") if "postgres:@" in owner else \
            psycopg.conninfo.make_conninfo(owner, user="laocoon_t", password="pw-test")
        return user_dsn

    yield {"owner": owner, "install": install, "sqlite": str(template_db)}
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS laocoon_views_test WITH (FORCE)")
        c.execute("DROP ROLE IF EXISTS laocoon_t")


def _parity(A, V, q):
    n = 0
    for u in q("SELECT id FROM users"):
        P = A.principal_by_id(u["id"])
        assert V.principal_by_id(u["id"]) == P
        for name, table in KIND_TABLE.items():
            for v in [r["id"] for r in q(f"SELECT id FROM {table}")] + [0, 9999, "x"]:
                assert V.constraint(name, P, v, {}) == A.constraint(name, P, v, {}), (name, u["id"], v)
                n += 1
            assert V.choices(name, P) == A.choices(name, P), (name, u["id"])
    for kind, refs in {"user": ["admin", "Eleni Papadaki", "eleni papadaki", "Papad", "maria", "%", "_", "9", "x"],
                       "course": ["CS101", "cs 101", "Intro", "Security", "1", "99", "%"]}.items():
        for r in refs:
            assert V.resolve(kind, r) == A.resolve(kind, r), (kind, r)
    return n


@pytest.mark.parametrize("functions", [False, True], ids=["views", "functions"])
def test_postgres_gives_the_same_decisions_as_db_mode(pg, functions):
    dsn = pg["install"](functions=functions)
    V = EclassViewsAdapter(PostgresViews(dsn, "laocoon", functions=functions), MODEL)
    A = EclassAdapter(readonly_query(pg["sqlite"]))
    assert _parity(A, V, readonly_query(pg["sqlite"])) > 1000
    st = V.status()
    assert st["missing"] == {} and st["previews"] == ["prev_final_grade", "prev_submission_grade"]
    teacher = A.principal_by_username("kpapadopoulos")
    fg = readonly_query(pg["sqlite"])("SELECT course_id, student_id, grade FROM final_grades WHERE grade IS NOT NULL",
                                      one=True)
    args = {"course_ref": fg["course_id"], "student_ref": fg["student_id"], "grade": 9}
    assert V.preview("set_final_grade", args, teacher) == A.preview("set_final_grade", args, teacher)
    assert V.errors == 0


def test_the_login_can_read_the_views_and_nothing_else(pg):
    dsn = pg["install"]()
    db = PostgresViews(dsn, "laocoon")
    assert db.query('SELECT count(*) AS n FROM "laocoon"."obj_user"', one=True)["n"] > 0
    for sql in ("SELECT amka FROM public.users", "SELECT body FROM public.messages",
                "SELECT * FROM public.final_grades"):
        with pytest.raises(Denied):
            db.query(sql)
    with psycopg.connect(dsn, autocommit=True) as c:
        for sql in ("INSERT INTO laocoon.obj_course (id, code, title) VALUES (99, 'X', 'Y')",
                    "UPDATE public.users SET role = 'admin'", "CREATE TABLE laocoon.t (x int)"):
            with pytest.raises(psycopg.Error):                   # read-only transactions, and no grant anyway
                c.execute(sql)
        cols = {r[0] for r in c.execute("SELECT column_name FROM information_schema.columns "
                                        "WHERE table_schema = 'public'")}
        assert cols == set()                                     # the app's schema is invisible to the login


def test_functions_answer_yes_or_no_and_the_relations_stay_closed(pg):
    dsn = pg["install"](functions=True)
    db = PostgresViews(dsn, "laocoon", functions=True)
    with pytest.raises(Denied):
        db.query('SELECT * FROM "laocoon"."rel_course_member"')
    assert db.query('SELECT "laocoon"."can_taught"(1, 2) AS ok', one=True)["ok"] in (True, False)
    V = EclassViewsAdapter(db, MODEL)
    assert V.follow("course.teacher", 1) == []                    # relations are not readable: attribution degrades


def test_the_views_block_the_migrations_the_message_warned_about(pg):
    pg["install"]()
    with psycopg.connect(pg["owner"]) as c:                       # each in a transaction, rolled back
        for sql, blocked in (("ALTER TABLE users ALTER COLUMN role TYPE varchar(20)", True),
                             ("DROP TABLE exercise_attempts", True),
                             ("ALTER TABLE users RENAME COLUMN full_name TO display_name", False),
                             ("ALTER TABLE users DROP COLUMN amka", False)):
            try:
                c.execute(sql)
                ok = True
            except psycopg.Error:
                ok = False
            c.rollback()
            assert ok is not blocked, sql


def test_an_unreachable_postgres_fails_closed():
    V = EclassViewsAdapter(PostgresViews("postgresql://nobody:x@127.0.0.1:1/none", connect_timeout=1), MODEL)
    student = {"id": 9, "username": "sdi2400005", "role": "student", "attrs": {}}
    with pytest.raises(Unverifiable):
        V.constraint("enrolled", student, 1, {})
    assert V.principal_by_id(9) is None

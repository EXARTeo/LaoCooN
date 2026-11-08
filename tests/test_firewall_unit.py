"""① Deputy Firewall unit tests: policy.py, firewall.py, adapters, config (no Guard, no classifier)."""
import copy
import dataclasses
import json
import shutil
from pathlib import Path

import pytest

from app.tools import DECLARATIONS                      # the organisers' Gemini-style declarations (read-only use)
from laocoon.adapters.eclass import EclassAdapter, is_read_only_sql, readonly_query
from laocoon.config import Settings, load_policy, normalise_policy
from laocoon.firewall import MAX_ENUM, ToolConfig, build_toolset
from laocoon.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "eclass.yaml"

LOCKED = {"grade_submission", "set_final_grade", "set_component_grade", "publish_grades", "update_user",
          "reset_password", "create_user", "delete_user", "enroll_user", "post_announcement", "add_material", "run_sql"}
CLEARABLE = {"post_forum", "send_message", "submit_assignment", "submit_exercise"}


def openai_style(decls):
    return [{"type": "function", "function": copy.deepcopy(d)} for d in decls]


def by_name(decls):
    return {(d["function"] if "function" in d else d)["name"]: (d["function"] if "function" in d else d) for d in decls}


@pytest.fixture
def db(template_db, tmp_path):
    path = tmp_path / "eclass.db"
    shutil.copy(template_db, path)
    return str(path)


@pytest.fixture
def adapter(db):
    return EclassAdapter(readonly_query(db))


@pytest.fixture
def policy(adapter):
    return Policy(load_policy(POLICY_PATH), adapter)


@pytest.fixture
def P(adapter):
    return lambda username: adapter.principal_by_username(username)


def policy_with(policy, change):
    """A Policy over a modified copy of the eClass policy data."""
    data = copy.deepcopy(policy.data)
    change(data)
    return Policy(data, policy.adapter)


# ------------------------------------------------------------------ ToolConfig
@pytest.mark.parametrize("raw", [
    None, "", "   ", "not json", "[1, 2]", "42", 42, 3.5, [], ["read_forum"], b"\xff\xfe",
    {"enabled": 7, "disabled": None, "approvals": [1], "read_only": "maybe"},
    {"enabled": [1, None, "", "  "], "approvals": {"post_forum": "no", 3: True, "": True, "x": None}},
])
def test_toolconfig_parse_junk_is_the_role_baseline(raw):
    assert ToolConfig.parse(raw) == ToolConfig()


def test_toolconfig_parse_dict_json_and_brief_shape_agree():
    d = {"enabled": [" read_forum ", "get_grades"], "disabled": ["get_grades"],
         "approvals": {"post_forum": False, "send_message": True, "run_sql": "false"}, "read_only": "true"}
    cfg = ToolConfig.parse(d)
    assert cfg.enabled == {"read_forum", "get_grades"} and cfg.disabled == {"get_grades"}
    assert dict(cfg.approvals) == {"post_forum": False, "send_message": True}       # junk choice = no opinion
    assert cfg.read_only is True
    assert ToolConfig.parse(json.dumps(d)) == cfg
    assert ToolConfig.parse(json.dumps(d).encode()) == cfg
    brief = {"user_id": "u_42", "role": "admin", "read_only": False, "tool_config": dict(d, read_only=False)}
    assert ToolConfig.parse(brief) == dataclasses.replace(cfg, read_only=False)
    assert ToolConfig.parse(cfg.to_dict()) == cfg
    assert ToolConfig.parse("read_forum") == ToolConfig()                            # a bare string is not a config
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.read_only = False
    with pytest.raises(TypeError):
        cfg.approvals["post_forum"] = True


# ------------------------------------------------------------------ the tool set of a run
def test_toolset_defaults_to_the_role_tools(policy, adapter, P):
    ts = build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS)
    assert ts.names == set(policy.allowed_tools("student"))
    assert "get_grades" in ts and "set_final_grade" not in ts and "run_sql" not in ts and "fetch_url" not in ts
    assert [d["name"] for d in ts.declarations()] == [d["name"] for d in DECLARATIONS if d["name"] in ts.names]
    assert ts.denial_rule("set_final_grade") == "rbac" and ts.denial_rule("get_grades") is None
    assert len(ts) == len(ts.names) and list(ts) == sorted(ts.names)


def test_toolset_is_role_intersect_enabled_minus_disabled(policy, adapter, P):
    cfg = ToolConfig.parse({"enabled": ["read_forum", "get_grades", "set_final_grade", "no_such_tool"],
                            "disabled": ["get_grades"]})
    ts = build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS, cfg)
    assert ts.names == {"read_forum"}
    assert ts.denial_rule("get_grades") == "tool_config"            # the client switched it off
    assert ts.denial_rule("set_final_grade") == "rbac"              # the role never had it
    assert ts.denial_rule("no_such_tool") == "rbac"
    assert [d["name"] for d in ts.declarations()] == ["read_forum"]


def test_enabling_a_tool_the_role_lacks_does_not_add_it(policy, adapter, P):
    ts = build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS, ToolConfig.parse({"enabled": ["run_sql"]}))
    assert ts.names == frozenset() and ts.declarations() == []
    ts = build_toolset(policy, adapter, P("kpapadopoulos"), DECLARATIONS,
                       ToolConfig.parse({"enabled": ["reset_password", "get_gradebook"]}))
    assert ts.names == {"get_gradebook"}


def test_read_only_drops_every_side_effect(policy, adapter, P):
    ts = build_toolset(policy, adapter, P("kpapadopoulos"), DECLARATIONS, ToolConfig(read_only=True))
    assert ts.names and not any(policy.is_side_effect(n) for n in ts.names)
    assert {"post_forum", "set_final_grade", "send_message"}.isdisjoint(ts.names) and "read_forum" in ts
    ts = build_toolset(policy, adapter, P("admin"), DECLARATIONS, ToolConfig(read_only=True))
    assert "run_sql" in ts and "delete_user" not in ts                 # run_sql is SELECT-only: a read


def test_declarations_hide_bound_args_and_offer_enrolled_codes(policy, adapter, P):
    before = copy.deepcopy(DECLARATIONS)
    ts = build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS)
    assert DECLARATIONS == before                                      # never mutate the input
    fns = by_name(ts.declarations())
    assert "student_ref" not in fns["get_grades"]["parameters"]["properties"]
    assert "from_user" not in fns["send_message"]["parameters"]["properties"]
    assert fns["send_message"]["parameters"]["required"] == ["to", "subject", "body"]
    assert "user_ref" not in fns["get_user"]["parameters"]["properties"]
    assert fns["get_user"]["parameters"]["required"] == []
    course = fns["get_course"]["parameters"]["properties"]["course_ref"]
    assert course["enum"] == ["CS101", "CS220", "CS340"] and course["type"] == "STRING"
    assert course["description"].endswith("Allowed: CS101, CS220, CS340.")
    assert fns["read_forum"]["parameters"]["properties"]["course_ref"]["enum"] == ["CS101", "CS220", "CS340"]
    assert "enum" not in fns["get_submissions"]["parameters"]["properties"]["assignment_id"]   # no closed answer
    assert "enum" not in fns["submit_exercise"]["parameters"]["properties"]["exercise_id"]     # list constraint


def test_declarations_openai_style(policy, adapter, P):
    decls = openai_style(DECLARATIONS)
    before = copy.deepcopy(decls)
    ts = build_toolset(policy, adapter, P("sdi2400005"), decls)
    assert decls == before
    out = ts.declarations()
    assert all(d["type"] == "function" and set(d) == {"type", "function"} for d in out)
    fns = by_name(out)
    assert "student_ref" not in fns["get_grades"]["parameters"]["properties"]
    assert fns["get_course"]["parameters"]["properties"]["course_ref"]["enum"] == ["CS101", "CS220", "CS340"]
    assert "set_final_grade" not in fns


def test_declarations_teacher_gets_taught_codes_admin_gets_none(policy, adapter, P):
    fns = by_name(build_toolset(policy, adapter, P("kpapadopoulos"), DECLARATIONS).declarations())
    assert fns["get_course"]["parameters"]["properties"]["course_ref"]["enum"] == ["CS101", "CS340"]
    assert fns["set_final_grade"]["parameters"]["properties"]["course_ref"]["enum"] == ["CS101", "CS340"]
    assert "student_ref" in fns["get_grades"]["parameters"]["properties"]        # bound for students only
    assert "user_ref" in fns["get_user"]["parameters"]["properties"]
    assert "enum" not in fns["get_user"]["parameters"]["properties"]["user_ref"]   # "self|student_of_taught": open
    fns = by_name(build_toolset(policy, adapter, P("admin"), DECLARATIONS).declarations())
    assert "enum" not in fns["get_course"]["parameters"]["properties"]["course_ref"]
    assert "sql" in fns["run_sql"]["parameters"]["properties"] and "enum" not in fns["run_sql"]["parameters"]["properties"]["sql"]
    assert "fetch_url" not in fns and "list_users" in fns


def test_scope_enum_opt_out_and_size_limit(policy, adapter, P, monkeypatch):
    pol = policy_with(policy, lambda d: d["tools"]["get_course"].update(scope_enum=False))
    fns = by_name(build_toolset(pol, adapter, P("sdi2400005"), DECLARATIONS).declarations())
    assert "enum" not in fns["get_course"]["parameters"]["properties"]["course_ref"]
    assert fns["read_forum"]["parameters"]["properties"]["course_ref"]["enum"]     # the others still get it
    monkeypatch.setattr(adapter, "choices", lambda c, p: [f"C{i}" for i in range(MAX_ENUM + 1)])
    fns = by_name(build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS).declarations())
    assert "enum" not in fns["get_course"]["parameters"]["properties"]["course_ref"]
    monkeypatch.setattr(adapter, "choices", lambda c, p: [f"C{i}" for i in range(MAX_ENUM)])
    fns = by_name(build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS).declarations())
    assert len(fns["get_course"]["parameters"]["properties"]["course_ref"]["enum"]) == MAX_ENUM
    monkeypatch.setattr(adapter, "choices", lambda c, p: [])
    fns = by_name(build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS).declarations())
    assert "enum" not in fns["get_course"]["parameters"]["properties"]["course_ref"]


def test_declarations_tolerate_odd_input(policy, adapter, P):
    decls = [{"name": "get_grades"}, {"name": "read_forum", "parameters": "junk"}, "junk", None, {"function": 3},
             {"name": "read_forum"}, {"type": "function", "function": {"name": "get_course", "parameters": {"type": "OBJECT"}}}]
    ts = build_toolset(policy, adapter, P("sdi2400005"), decls)
    out = ts.declarations()
    assert [(d["function"] if "function" in d else d)["name"] for d in out] == ["get_grades", "read_forum", "get_course"]
    assert out[1] == {"name": "read_forum", "parameters": "junk"}
    assert build_toolset(policy, adapter, P("sdi2400005"), None).declarations() == []


def test_toolset_declarations_are_a_copy(policy, adapter, P):
    ts = build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS)
    out = ts.declarations()
    out[0]["name"] = "hacked"
    out[1]["parameters"]["properties"]["evil"] = {}
    assert ts.declarations() == build_toolset(policy, adapter, P("sdi2400005"), DECLARATIONS).declarations()


# ------------------------------------------------------------------ approval merge: defaults → tool → role → user → locked
def test_approval_defaults_follow_the_effect(policy):
    assert policy.approval_required("read_forum", "student", {}) == (False, "default")
    assert policy.approval_required("post_forum", "student", {}) == (True, "default")
    assert policy.approval_required("submit_assignment", "student", None) == (True, "default")
    assert policy.approval_required("fetch_url", "admin", {}) == (True, "default")      # external
    pol = policy_with(policy, lambda d: d["approvals"].update(defaults={}))
    assert pol.approval_required("post_forum", "student", {}) == (True, "default")      # side effect → True
    assert pol.approval_required("read_forum", "student", {}) == (False, "default")
    pol = Policy({"tools": {"x": {"effect": "write", "allow": {"admin": True}}}}, None)   # no approvals section at all
    assert pol.approval_required("x", "admin") == (True, "default")


def test_user_clears_a_non_locked_gate_but_not_a_locked_one(policy, adapter, P):
    assert policy.approval_required("post_forum", "student", {"post_forum": False}) == (False, "user")
    assert policy.approval_required("read_forum", "student", {"read_forum": True}) == (True, "user")
    for tool in LOCKED:
        assert policy.is_locked(tool)
        assert policy.approval_required(tool, "admin", {tool: False}) == (True, "locked"), tool
    for tool in CLEARABLE:
        assert not policy.is_locked(tool)
        assert policy.approval_required(tool, "student", {tool: False}) == (False, "user"), tool
    cfg = ToolConfig.parse({"approvals": {"post_forum": False, "grade_submission": False}})
    ts = build_toolset(policy, adapter, P("kpapadopoulos"), DECLARATIONS, cfg)
    assert ts.approval("post_forum") == (False, "user")
    assert ts.approval("grade_submission") == (True, "locked")
    assert ts.approval("get_gradebook") == (False, "default")


def test_role_and_tool_layers(policy):
    pol = policy_with(policy, lambda d: d["approvals"].update(roles={"student": {"post_forum": False, "read_forum": True}}))
    assert pol.approval_required("post_forum", "student", {}) == (False, "role")
    assert pol.approval_required("read_forum", "student", {}) == (True, "role")
    assert pol.approval_required("post_forum", "teacher", {}) == (True, "default")
    assert pol.approval_required("post_forum", "student", {"post_forum": True}) == (True, "user")   # user beats role
    pol = policy_with(policy, lambda d: d["tools"]["post_forum"].update(approval=False))
    assert pol.approval_required("post_forum", "student", {}) == (False, "tool")
    assert pol.approval_required("post_forum", "student", {"post_forum": True}) == (True, "user")
    pol = policy_with(policy, lambda d: d["tools"]["read_forum"].update(approval=True))
    assert pol.approval_required("read_forum", "student", {}) == (True, "tool")
    pol = policy_with(policy, lambda d: d["tools"]["grade_submission"].update(approval=False))     # locked wins
    assert pol.approval_required("grade_submission", "teacher", {"grade_submission": False}) == (True, "locked")
    assert policy.approval_required("run_sql", "admin", {"run_sql": False}) == (True, "locked")
    assert policy.approval_required("no_such_tool", "admin", {}) == (True, "default")            # unknown = write


# ------------------------------------------------------------------ evaluate(): deterministic fill
def test_missing_bound_arg_is_filled_with_the_caller(policy, P):
    d, nargs, meta = policy.evaluate(P("sdi2400005"), "get_grades", {})
    assert d is None and nargs == {"student_ref": 9} and meta["filled"] == ["student_ref"]
    d, nargs, meta = policy.evaluate(P("sdi2400005"), "read_messages", {"user_ref": "  "})
    assert d is None and nargs == {"user_ref": 9} and meta["filled"] == ["user_ref"]
    d, nargs, _ = policy.evaluate(P("sdi2400005"), "send_message", {"to": "kpapadopoulos", "subject": "a", "body": "b"})
    assert d is None and nargs == {"to": 2, "subject": "a", "body": "b", "from_user": 9}
    d, nargs, meta = policy.evaluate(P("sdi2400005"), "get_grades", {"student_ref": "sdi2400005", "course_ref": "cs101"})
    assert d is None and nargs == {"student_ref": 9, "course_ref": 1} and meta["filled"] == []
    d, nargs, _ = policy.evaluate(P("admin"), "read_messages", {"user_ref": 1})
    assert d is None and nargs == {"user_ref": 1}


def test_another_user_in_a_bound_arg_is_denied_identity(policy, P):
    d, _, _ = policy.evaluate(P("sdi2400005"), "get_grades", {"student_ref": "sdi2400001"})
    assert (d.action, d.rule, d.severity) == ("deny", "identity", "high") and "άλλον χρήστη" in d.reason
    d, _, _ = policy.evaluate(P("sdi2400005"), "send_message", {"to": "sdi2400001", "subject": "a", "body": "b",
                                                                "from_user": "admin"})
    assert (d.action, d.rule) == ("deny", "identity")
    d, _, _ = policy.evaluate(P("sdi2400005"), "read_messages", {"user_ref": 2})
    assert (d.action, d.rule) == ("deny", "identity")
    d, _, _ = policy.evaluate(P("kpapadopoulos"), "update_user", {"user_ref": "Petros Vlachos", "phone": "1"})
    assert (d.action, d.rule) == ("deny", "identity")


def test_bound_arg_outside_refs_is_read_as_a_user(policy, P):
    pol = policy_with(policy, lambda d: d["refs"].pop("student_ref"))
    d, nargs, _ = pol.evaluate(P("sdi2400005"), "get_grades", {"student_ref": "sdi2400005"})
    assert d is None and nargs["student_ref"] == 9
    d, _, _ = pol.evaluate(P("sdi2400005"), "get_grades", {"student_ref": "sdi2400002"})
    assert (d.action, d.rule) == ("deny", "identity")
    d, _, _ = pol.evaluate(P("sdi2400005"), "get_grades", {"student_ref": "nobody-here"})
    assert (d.action, d.rule) == ("deny", "identity")


def test_ambiguous_or_unknown_reference_is_denied_not_guessed(policy, P):
    d, _, _ = policy.evaluate(P("admin"), "get_user", {"user_ref": "Konstantin"})        # 2 people via LIKE
    assert (d.action, d.rule, d.severity) == ("deny", "abac", "low")
    d, _, _ = policy.evaluate(P("admin"), "get_user", {"user_ref": "nobody-here"})
    assert (d.action, d.rule) == ("deny", "abac")
    d, _, _ = policy.evaluate(P("sdi2400005"), "read_forum", {"course_ref": "Nope"})
    assert (d.action, d.rule) == ("deny", "abac")


def test_rbac_deny_args_fields_and_abac(policy, P):
    d, _, _ = policy.evaluate(P("sdi2400005"), "set_final_grade", {"student_ref": "sdi2400005", "course_ref": "CS101", "grade": 10})
    assert (d.action, d.rule) == ("deny", "rbac") and "ρόλο" in d.reason
    d, _, _ = policy.evaluate(P("admin"), "no_such_tool", {})
    assert (d.action, d.rule) == ("deny", "rbac") and "δεν υπάρχει" in d.reason
    d, _, _ = policy.evaluate(P("admin"), "fetch_url", {"url": "http://x"})
    assert (d.action, d.rule) == ("deny", "rbac")
    pol = policy_with(policy, lambda d: d["tools"]["send_message"].update(deny_args=["from_user"]))
    d, _, _ = pol.evaluate(P("sdi2400005"), "send_message", {"to": "admin", "subject": "a", "body": "b", "from_user": "admin"})
    assert (d.action, d.rule) == ("deny", "identity") and "πλαστοπροσωπία" in d.reason
    d, _, _ = policy.evaluate(P("sdi2400005"), "update_user", {"role": "admin"})
    assert (d.action, d.rule) == ("deny", "abac") and "πεδία" in d.reason
    d, nargs, _ = policy.evaluate(P("sdi2400005"), "update_user", {"phone": "123", "address": ""})
    assert d is None and nargs == {"phone": "123", "user_ref": 9}
    d, _, _ = policy.evaluate(P("kpapadopoulos"), "get_gradebook", {"course_ref": "CS220"})     # not his course
    assert (d.action, d.rule) == ("deny", "abac")
    d, nargs, _ = policy.evaluate(P("kpapadopoulos"), "get_gradebook", {"course_ref": "CS101"})
    assert d is None and nargs == {"course_ref": 1}
    d, _, _ = policy.evaluate(P("kpapadopoulos"), "get_gradebook", {})
    assert (d.action, d.rule, d.severity) == ("deny", "abac", "medium")


def test_removed_policy_helpers_are_gone(policy):
    for name in ("target_of", "approval_needed", "tools_for", "match_args", "trust"):
        assert not hasattr(policy, name), name
    assert policy.bind_self("get_grades", "student") == ["student_ref"] == policy.bound_args("get_grades", "student")
    assert policy.bound_args("get_grades", "teacher") == []
    assert Policy({"tools": {"t": {"bind_self": {"student": ["x"]}, "allow": {"student": True}}}}, None).bound_args("t", "student") == ["x"]


# ------------------------------------------------------------------ read-only SQL (the app COMMITS everything else)
@pytest.mark.parametrize("sql", [
    "SELECT * FROM users",
    "select id, username from users where role = 'student'",
    "SELECT *\nFROM users\nWHERE id = 1",
    "  SELECT count(*) FROM courses;  ",
    "WITH x AS (SELECT 1 AS n) SELECT n FROM x",
    "with x as (select id from users)\nselect * from x",
    "SELECT(1)",
])
def test_read_only_sql_accepts_select_and_with(sql):
    assert is_read_only_sql(sql)


@pytest.mark.parametrize("sql", [
    None, 42, "", "   ", ";", ";;",
    "INSERT INTO users (username) VALUES ('x')",
    "UPDATE users SET role = 'admin' WHERE id = 9",
    "DELETE FROM users",
    "DROP TABLE users",
    "WITH x AS (SELECT 1) DELETE FROM users",
    "WITH x AS (SELECT 1) UPDATE users SET role = 'admin'",
    "REPLACE INTO users (id, username) VALUES (1, 'x')",
    "CREATE TABLE t (x)",
    "ALTER TABLE users ADD COLUMN x",
    "TRUNCATE TABLE users",
    "SELECT 1 -- comment",
    "SELECT /* c */ 1",
    "SELECT 1 */",
    "SEL/**/ECT 1",
    "SELECT 1; DROP TABLE users",
    "SELECT 1;;",
    "ATTACH DATABASE '/tmp/x.db' AS y",
    "DETACH DATABASE y",
    "PRAGMA table_info(users)",
    "pragma writable_schema = 1",
    "SELECT load_extension('evil')",
    "SELECT writefile('/tmp/x', 'y')",
    "SELECT readfile('/etc/passwd')",
    "VACUUM", "REINDEX", "ANALYZE",
    "EXPLAIN SELECT 1",
    "SELECT * FROM users WHERE delete = 1",          # false positives by design: tokens are scanned everywhere,
    "SELECT 'insert' AS word",                      # string literals included (no SQL parser; mAgenticX does the same)
    "select * from users\nunion all\nselect * from users; attach database 'x' as y",
])
def test_read_only_sql_rejects_writes_comments_and_extras(sql):
    assert not is_read_only_sql(sql)


def test_read_only_sql_through_the_policy_and_the_constraint(policy, adapter, P):
    d, nargs, _ = policy.evaluate(P("admin"), "run_sql", {"sql": "SELECT username FROM users"})
    assert d is None and nargs == {"sql": "SELECT username FROM users"}
    d, _, _ = policy.evaluate(P("admin"), "run_sql", {"sql": "DROP TABLE users"})
    assert (d.action, d.rule, d.severity) == ("deny", "abac", "high")
    d, _, _ = policy.evaluate(P("admin"), "run_sql", {"sql": "SELECT 1; " + "x" * 300})
    assert d.action == "deny" and len(d.reason) < 220                 # long statements are shortened on the card
    d, _, _ = policy.evaluate(P("admin"), "run_sql", {})
    assert (d.action, d.rule) == ("deny", "abac")
    d, _, _ = policy.evaluate(P("kpapadopoulos"), "run_sql", {"sql": "SELECT 1"})
    assert (d.action, d.rule) == ("deny", "rbac")
    p = P("admin")
    assert adapter.constraint("read_only_sql", p, "select 1", {}) and not adapter.constraint("read_only_sql", p, "delete from x", {})
    assert not adapter.constraint("read_only_sql", p, None, {})
    assert not adapter.constraint("enrolled", P("sdi2400005"), "CS101", {})           # not an id: False, no crash
    assert adapter.constraint("enrolled", P("sdi2400005"), "1", {})


def test_adapter_choices(adapter, P):
    assert adapter.choices("enrolled", P("sdi2400005")) == ["CS101", "CS220", "CS340"]
    assert adapter.choices("enrolled", P("sdi2400001")) == ["CS101", "CS340", "MATH110"]
    assert adapter.choices("taught", P("kpapadopoulos")) == ["CS101", "CS340"]
    assert adapter.choices("taught", P("mgeorgiou")) == ["CS220"]
    assert adapter.choices("enrolled", P("kpapadopoulos")) == [] and adapter.choices("taught", P("admin")) == []
    assert adapter.choices("self", P("admin")) is None and adapter.choices("read_only_sql", P("admin")) is None
    assert not hasattr(adapter, "text_fields")


# ------------------------------------------------------------------ config: policy v2 loading, guard settings
def test_load_policy_maps_v1_aliases_and_drops_removed_keys(tmp_path):
    (tmp_path / "p.yaml").write_text("""
version: 1
trust: {admin: high}
match_args: [role]
dlp_fields: [amka]
canaries: ["13579135791", 42]
tools:
  get_grades:
    bind_self: {student: [student_ref]}
    allow: {student: true}
    approval: {admin: always}
    beneficiary: student_ref
  send_message: {effect: communicate, recipient: to, bind_self: {student: [from_user]}, bind: {teacher: [from_user]},
                 allow: {student: true, teacher: true}, approval: {admin: {when_args: [role]}}}
  run_sql: {effect: read, allow: {admin: {sql: read_only_sql}}, approval: true, locked: 1}
  empty:
""", encoding="utf-8")
    data = load_policy(tmp_path / "p.yaml")
    assert data["honey_records"] == {"values": ["13579135791", "42"], "visible_to": []} and "canaries" not in data
    assert data["approvals"] == {"defaults": {"read": False, "write": True, "communicate": True, "external": True}, "roles": {}}
    assert data["guard"] == {} and data["default"] == "deny" and data["refs"] == {}
    assert not any(k in data for k in ("trust", "match_args", "dlp_fields"))
    g = data["tools"]["get_grades"]
    assert g["bind"] == {"student": ["student_ref"]} and "bind_self" not in g and "beneficiary" not in g
    assert "approval" not in g and g["effect"] == "read"                       # role-keyed v1 approval: dropped
    s = data["tools"]["send_message"]
    assert s["bind"] == {"student": ["from_user"], "teacher": ["from_user"]} and "recipient" not in s and "approval" not in s
    r = data["tools"]["run_sql"]
    assert r["approval"] is True and r["locked"] is True
    assert data["tools"]["empty"] == {"effect": "read", "allow": {}}
    pol = Policy(data, None)
    assert pol.approval_required("get_grades", "student", {}) == (False, "default")
    assert pol.approval_required("send_message", "student", {"send_message": False}) == (False, "user")
    assert pol.approval_required("run_sql", "admin", {"run_sql": False}) == (True, "locked")
    assert normalise_policy({"honey_records": ["a"]})["honey_records"] == {"values": ["a"], "visible_to": []}
    assert normalise_policy({"honey_records": {"values": ["a"]}, "canaries": ["b"]})["honey_records"]["values"] == ["a"]


def test_eclass_policy_v2_decisions(policy):
    data = policy.data
    assert data["version"] == 2 and data["honey_records"] == {"values": ["13579135791", "GR0000000000000000013579135"],
                                                              "visible_to": ["admin"]}
    assert data["approvals"]["defaults"] == {"read": False, "write": True, "communicate": True, "external": True}
    assert {c["name"] for c in data["guard"]["classes"]} == {"instruction_injection", "privilege_escalation",
                                                             "data_exfiltration", "tool_hijack", "benign"}
    assert data["guard"]["thresholds"] == {"block": 0.85, "hitl": 0.5} and data["guard"]["policy"]["tool_hijack"]["G2b"] == "hitl"
    assert {t for t in data["tools"] if data["tools"][t].get("locked")} == LOCKED
    assert all(policy.is_side_effect(t) for t in CLEARABLE) and not any(policy.is_locked(t) for t in CLEARABLE)
    assert not any(k in data for k in ("trust", "match_args", "dlp_fields", "canaries"))
    for name, spec in data["tools"].items():
        assert not any(k in spec for k in ("bind_self", "beneficiary", "recipient", "risk")), name
        assert isinstance(spec.get("approval", True), bool), name
    assert data["tools"]["run_sql"] == {"effect": "read", "allow": {"admin": {"sql": "read_only_sql"}}, "approval": True, "locked": True}
    assert policy.allowed_tools("admin") and "fetch_url" not in policy.allowed_tools("admin")
    assert "run_sql" not in policy.allowed_tools("teacher") and "run_sql" in policy.allowed_tools("admin")
    assert policy.bound_args("read_messages", "admin") == ["user_ref"] and policy.bound_args("send_message", "teacher") == ["from_user"]
    assert policy.bound_args("get_user", "student") == ["user_ref"] and policy.bound_args("submit_exercise", "student") == ["student_ref"]
    assert data["tools"]["get_course"]["untrusted_output"] == "course_teacher"
    assert data["tools"]["read_forum"]["untrusted_output"] == {"author_field": "author", "ref": "forum_post"}
    assert policy.filters("get_user", "teacher") == ["public_profile"]


def test_settings_guard_env(monkeypatch):
    for k in ("LAOCOON_GUARD_BACKEND", "LAOCOON_GUARD_MODEL", "GUARD_MODEL", "LAOCOON_GUARD_BASE_URL",
              "LAOCOON_GUARD_API_KEY", "TYPESAFE_API_KEY", "LAOCOON_GUARD_TIMEOUT", "LAOCOON_PLANNER"):
        monkeypatch.delenv(k, raising=False)
    s = Settings.from_env()
    assert (s.guard_backend, s.guard_model, s.guard_base_url, s.guard_api_key, s.guard_timeout) == \
           ("off", "", "", "", None)                       # "" / None = the backend's own defaults
    assert s.planner_backend == "off"                      # the plan-commitment planner is opt-in
    assert not any(hasattr(s, k) for k in ("llm_base_url", "llm_api_key", "llm_model", "planner_enabled"))
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts-key")
    monkeypatch.setenv("GUARD_MODEL", "jev-2")
    s = Settings.from_env()
    assert (s.guard_backend, s.guard_api_key, s.guard_model) == ("jev", "ts-key", "jev-2")
    monkeypatch.setenv("LAOCOON_GUARD_API_KEY", "lcn-key")
    monkeypatch.setenv("LAOCOON_GUARD_MODEL", "jev-3")
    monkeypatch.setenv("LAOCOON_GUARD_BACKEND", " OFF ")
    monkeypatch.setenv("LAOCOON_GUARD_BASE_URL", "http://localhost:8000/")
    monkeypatch.setenv("LAOCOON_GUARD_TIMEOUT", "1.5")
    s = Settings.from_env(guard_timeout=9.0)
    assert (s.guard_backend, s.guard_api_key, s.guard_model, s.guard_base_url, s.guard_timeout) == \
           ("off", "lcn-key", "jev-3", "http://localhost:8000", 9.0)
    assert s.persist_threshold == 5 and s.approval_ttl == 300

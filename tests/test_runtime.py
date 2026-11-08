"""Runtime settings (laocoon/runtime.py): the console's mitigation switches. Defaults are the start-up configuration;
each switch takes effect on the next request, lives in the store (shared by every worker), is audited, and can be
locked with LAOCOON_RUNTIME_SETTINGS=off."""
import json

import pytest

from app.tools import DECLARATIONS                       # the organisers' declarations (read-only use)
from conftest import PD_SECRET
from laocoon import Guard, proxy as PX, runtime as RT
from laocoon.adapters.eclass import EclassAdapter, readonly_query
from laocoon.guard import REASON_G2B, SWITCHED_OFF_NOTE, WITHDRAWN_CANARY, WITHDRAWN_HONEY
from test_pipeline import HONEY_AMKA, INJECTION, SYSTEM, TOOLS, StubUpstream, forum_rows, tool_call

TOKEN = "rt-console-token"
H = {"X-Laocoon-Token": TOKEN}
API = "/laocoon/api/settings"
KEYS = ["laocoon.enabled", "firewall.rbac", "firewall.abac", "firewall.identity", "firewall.filters",
        "guard.enabled", "guard.points.G1", "guard.points.G2", "guard.points.G2b", "guard.points.G3",
        "canary.system_prompt", "canary.honey", "canary.dlp", "approvals.enabled", "approvals.ttl",
        "persist.enabled", "persist.threshold", "persist.window", "persist.ttl", "private_data.enabled"]
FIELDS = {"key", "group", "type", "value", "default", "source", "env", "min", "max", "step", "unit", "choices",
          "weakens_when", "available", "note"}
MSG_TO_TEACHER = {"to": "kpapadopoulos", "subject": "Late", "body": "10 minutes late tomorrow."}


def by_key(payload):
    return {s["key"]: s for s in payload["settings"]}


def console_events(guard):
    return [e for e in guard.events(0, 1000) if e["stage"] == "console" and e["action"] == "setting"]


@pytest.fixture(autouse=True)
def _unlocked(monkeypatch):
    monkeypatch.delenv("LAOCOON_RUNTIME_SETTINGS", raising=False)
    monkeypatch.delenv("LAOCOON_ENABLED", raising=False)


def make_app(guard, monkeypatch, stub=None):
    monkeypatch.setenv("LAOCOON_CONSOLE_TOKEN", TOKEN)
    monkeypatch.delenv("LAOCOON_CONSOLE_USERS", raising=False)
    monkeypatch.setenv("LAOCOON_ECLASS_DB", guard.db_path)
    monkeypatch.setenv("LAOCOON_IDENTITY", "system_prompt")
    monkeypatch.setenv("LAOCOON_UPSTREAM_BASE_URL", "http://upstream.test/v1")
    monkeypatch.setenv("LAOCOON_AUTHZ_SOURCE", "db")
    monkeypatch.delenv("LAOCOON_APP_KEY", raising=False)
    if stub is not None:
        monkeypatch.setattr(PX.requests, "post", stub)
    return PX.create_app(PX.ProxyConfig(), guard).test_client()


@pytest.fixture
def px(guard_static, monkeypatch):
    """(client, chat, stub, guard): the proxy with its console API, a stub upstream and the static classifier."""
    stub = StubUpstream()
    client = make_app(guard_static, monkeypatch, stub)

    def chat(messages):
        r = client.post("/v1/chat/completions", json={"model": "m", "messages": messages, "tools": TOOLS})
        assert r.status_code == 200, r.data
        return r.get_json()["choices"][0]["message"]
    return client, chat, stub, guard_static


def put(client, **values):
    return client.put(API, json={"values": values}, headers=H)


# ------------------------------------------------------------------ defaults = today's start-up configuration
def test_defaults_are_the_start_up_configuration(guard):
    rt = guard.runtime
    payload = rt.payload()
    assert [s["key"] for s in payload["settings"]] == KEYS                       # the documented order
    assert payload == {"locked": False, "weakened": [], "settings": payload["settings"]}
    s = by_key(payload)
    assert all(set(x) == FIELDS for x in payload["settings"])
    assert all(x["source"] in ("env", "default") and x["value"] == x["default"] for x in payload["settings"])
    assert s["laocoon.enabled"]["value"] is True and s["laocoon.enabled"]["env"] == "LAOCOON_ENABLED"
    assert all(s[k]["value"] is True for k in KEYS[1:5] + KEYS[10:14] + ["persist.enabled"])
    assert s["approvals.ttl"] | {"value": 300, "min": 30, "max": 3600, "unit": "s", "weakens_when": "higher"} == s["approvals.ttl"]
    assert (s["persist.threshold"]["value"], s["persist.window"]["value"], s["persist.ttl"]["value"]) == (5, 600, 900)
    assert s["persist.window"]["env"] is None and s["persist.window"]["source"] == "default"
    # no classifier backend (fixture `guard`): the classifier switches are shown but unavailable
    assert s["guard.enabled"] | {"value": False, "default": False, "available": False} == s["guard.enabled"]
    assert not any(s[f"guard.points.{p}"]["available"] for p in RT.POINTS)
    # LAOCOON_PRIVATE_DATA=off (conftest) and a short secret: private data cannot be switched on
    assert s["private_data.enabled"] | {"value": False, "available": False, "source": "env"} == s["private_data.enabled"]
    assert "LAOCOON_SECRET" in s["private_data.enabled"]["note"]
    assert guard.store.query("SELECT COUNT(*) AS n FROM settings", one=True)["n"] == 0


def test_defaults_follow_the_environment(guard, monkeypatch):
    monkeypatch.setenv("LAOCOON_APPROVAL_TTL", "120")
    monkeypatch.setenv("LAOCOON_PERSIST_THRESHOLD", "3")
    monkeypatch.setenv("LAOCOON_GUARD_BACKEND", "openai")
    monkeypatch.setenv("LAOCOON_GUARD_MODEL", "judge")
    monkeypatch.setenv("LAOCOON_GUARD_POINTS", "G2,G2b")
    monkeypatch.setenv("LAOCOON_ENABLED", "false")
    g = Guard.from_env(EclassAdapter(readonly_query(guard.db_path)))
    s = by_key(g.runtime.payload())
    assert s["approvals.ttl"]["value"] == 120 and s["approvals.ttl"]["source"] == "env"
    assert s["persist.threshold"]["value"] == 3 and s["laocoon.enabled"]["value"] is False
    assert s["guard.enabled"]["value"] is True and s["guard.enabled"]["available"]
    assert [p for p in RT.POINTS if s[f"guard.points.{p}"]["value"]] == ["G2", "G2b"]
    assert g.runtime.weakened() == []


# ------------------------------------------------------------------ the API
def test_api_needs_the_console_token(px):
    client = px[0]
    assert client.get(API).status_code == 401
    assert client.put(API, json={"values": {"approvals.enabled": False}}).status_code == 401
    assert client.delete(API + "/approvals.enabled").status_code == 401
    assert client.get("/laocoon/api/state").status_code == 401
    r = client.get(API, headers=H)
    assert r.status_code == 200 and [s["key"] for s in r.get_json()["settings"]] == KEYS


def test_put_validates_everything_before_writing_anything(px):
    client, _, _, guard = px
    bad = [{"nope.key": True}, {"approvals.enabled": "false"}, {"approvals.enabled": 0}, {"approvals.ttl": 10},
           {"approvals.ttl": 3601}, {"approvals.ttl": 60.5}, {"approvals.ttl": "60"}, {"persist.threshold": True},
           {"approvals.enabled": False, "approvals.ttl": 5}, {"private_data.enabled": True}]
    for values in bad:
        r = client.put(API, json={"values": values}, headers=H)
        assert r.status_code == 400 and isinstance(r.get_json()["error"], str), values
    for body in ({}, {"values": []}, {"values": "x"}):
        assert client.put(API, json=body, headers=H).status_code == 400
    assert client.delete(API + "/nope.key", headers=H).status_code == 400
    assert guard.store.query("SELECT COUNT(*) AS n FROM settings", one=True)["n"] == 0
    assert console_events(guard) == []
    r = put(client, **{"approvals.ttl": 60.0})                                   # an integral float is an int
    assert r.status_code == 200 and by_key(r.get_json())["approvals.ttl"]["value"] == 60


def test_unavailable_switches_cannot_be_set(guard, monkeypatch):
    client = make_app(guard, monkeypatch)
    for key in ("guard.enabled", "guard.points.G1", "private_data.enabled"):
        r = client.put(API, json={"values": {key: True}}, headers=H)
        assert r.status_code == 400 and key in r.get_json()["error"]


def test_changes_are_audited_and_reported(px):
    client, _, _, guard = px
    r = put(client, **{"approvals.enabled": False, "persist.threshold": 8, "canary.dlp": True})
    p = r.get_json()
    assert r.status_code == 200 and p["weakened"] == ["approvals.enabled", "persist.threshold"]
    s = by_key(p)
    assert s["approvals.enabled"]["source"] == "runtime" and s["approvals.enabled"]["value"] is False
    assert s["canary.dlp"]["source"] == "default"                               # = the default: no override stored
    ev = console_events(guard)
    assert [(e["username"], e["rule"], e["severity"]) for e in ev] == [("token", "runtime", "high")] * 2
    assert "approvals.enabled" in ev[0]["reason"] and "ενεργό → ανενεργό" in ev[0]["reason"]
    assert "persist.threshold" in ev[1]["reason"] and "5 → 8" in ev[1]["reason"] and "«token»" in ev[1]["reason"]
    state = client.get("/laocoon/api/state", headers=H).get_json()
    assert state["runtime"] == {"weakened": ["approvals.enabled", "persist.threshold"], "locked": False}
    put(client, **{"persist.threshold": 3})                                      # stricter than before: info
    assert console_events(guard)[-1]["severity"] == "info" and "8 → 3" in console_events(guard)[-1]["reason"]
    r = client.delete(API + "/approvals.enabled", headers=H)
    assert r.status_code == 200 and by_key(r.get_json())["approvals.enabled"]["source"] == "default"
    assert r.get_json()["weakened"] == []                                        # 3 < 5 is stronger
    last = console_events(guard)[-1]
    assert last["severity"] == "info" and "επαναφορά" in last["reason"] and "ανενεργό → ενεργό" in last["reason"]
    n = len(console_events(guard))
    client.delete(API + "/approvals.enabled", headers=H)                         # nothing to reset: no event
    put(client, **{"persist.threshold": 3})                                      # unchanged: no event
    assert len(console_events(guard)) == n
    assert guard.verify_chain()["ok"]


def test_lock_makes_the_api_read_only_and_ignores_saved_values(px, monkeypatch):
    client, _, _, guard = px
    put(client, **{"approvals.enabled": False})
    monkeypatch.setenv("LAOCOON_RUNTIME_SETTINGS", "off")
    p = client.get(API, headers=H).get_json()
    assert p["locked"] is True and p["weakened"] == [] and by_key(p)["approvals.enabled"]["value"] is True
    for r in (put(client, **{"canary.dlp": False}), client.delete(API + "/approvals.enabled", headers=H)):
        assert r.status_code == 409 and "LAOCOON_RUNTIME_SETTINGS" in r.get_json()["error"]
    assert client.get("/laocoon/api/state", headers=H).get_json()["runtime"] == {"weakened": [], "locked": True}
    t = guard.begin_turn(guard.adapter.principal_by_username("sdi2400005"), "x")
    assert t.check_call("send_message", dict(MSG_TO_TEACHER)).action == "ask"   # the environment decides
    monkeypatch.setenv("LAOCOON_RUNTIME_SETTINGS", "on")
    assert client.get(API, headers=H).get_json()["weakened"] == ["approvals.enabled"]


# ------------------------------------------------------------------ every worker sees the same values
def test_values_live_in_the_store_and_reach_a_second_instance(px, monkeypatch):
    client, _, _, guard = px
    other = Guard.from_env(EclassAdapter(readonly_query(guard.db_path)))          # a second worker: same database
    other.db_path = guard.db_path
    assert other.settings.db_path == guard.settings.db_path
    assert other.runtime.value("approvals.enabled") is True                      # read (and cached) before the change
    clock = [1000.0]
    monkeypatch.setattr(RT.time, "monotonic", lambda: clock[0])
    other.runtime.invalidate()
    assert other.runtime.on("approvals.enabled")
    put(client, **{"approvals.enabled": False, "approvals.ttl": 90})
    assert other.runtime.on("approvals.enabled")                                 # still within its cache
    clock[0] += RT.CACHE_SECONDS
    assert not other.runtime.on("approvals.enabled")                             # within a second
    t = other.begin_turn(other.adapter.principal_by_username("sdi2400005"), "x")
    assert t.check_call("send_message", dict(MSG_TO_TEACHER)).action == "allow"
    second = make_app(other, monkeypatch).get(API, headers=H).get_json()
    assert by_key(second)["approvals.ttl"] | {"value": 90, "source": "runtime"} == by_key(second)["approvals.ttl"]
    row = guard.store.query("SELECT value, updated_by FROM settings WHERE key = 'approvals.ttl'", one=True)
    assert row == {"value": "90", "updated_by": "token"}


def test_an_invalid_stored_value_is_ignored(guard):
    guard.store.execute("INSERT INTO settings (key, value, updated_at) VALUES ('approvals.ttl', '5', 0), "
                        "('canary.dlp', '\"no\"', 0), ('unknown.key', 'false', 0)")
    guard.runtime.invalidate()
    assert guard.runtime.value("approvals.ttl") == 300 and guard.runtime.on("canary.dlp")
    assert guard.runtime.weakened() == []


# ------------------------------------------------------------------ each switch, on the next request
def test_laocoon_off_passes_requests_through(px):
    client, chat, stub, guard = px
    assert chat([{"role": "system", "content": SYSTEM}, {"role": "user", "content": INJECTION}])["content"] \
        .startswith("[Laocoon]") and stub.calls == []                            # G1 blocks it
    put(client, **{"laocoon.enabled": False})
    body = {"model": "m", "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": INJECTION}]}
    r = client.post("/v1/chat/completions", json=body)
    assert r.status_code == 200 and stub.calls == [dict(body, stream=False)]    # forwarded untouched, no canary
    assert client.get("/health").get_json()["enabled"] is False
    client.delete(API + "/laocoon.enabled", headers=H)
    assert client.get("/health").get_json()["enabled"] is True


def test_approvals_off_runs_a_write_without_asking(px):
    client, chat, stub, guard = px
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "Tell kpapadopoulos I am late."}]
    stub.answer(tool_call("send_message", MSG_TO_TEACHER), "tool_calls")
    assert "χρειάζεται έγκριση" in chat(messages)["content"]
    put(client, **{"approvals.enabled": False})
    stub.answer(tool_call("send_message", MSG_TO_TEACHER), "tool_calls")
    msg = chat(messages)
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {**MSG_TO_TEACHER, "to": 2, "from_user": 9}
    # locked tools too; the G2b fail-safe after untrusted content is the classifier's and stays
    t = guard.begin_turn(guard.adapter.principal_by_username("admin"), "x")
    assert t.check_call("run_sql", {"sql": "SELECT 1"}).action == "allow"
    s = guard.begin_turn(guard.adapter.principal_by_username("sdi2400001"), "x")
    s.label_result("read_forum", {"course_ref": 1}, forum_rows(guard))          # forum_post:3 is an injection
    assert s.check_call("send_message", dict(MSG_TO_TEACHER)).rule == "g2b"


def test_approval_ttl(guard):
    guard.runtime.set_many({"approvals.ttl": 60}, "op")
    d = guard.begin_turn(guard.adapter.principal_by_username("sdi2400005"), "x") \
        .check_call("send_message", dict(MSG_TO_TEACHER))
    row = guard.store.query("SELECT created_at, expires_at FROM pending WHERE id = ?", (d.approval_id,), one=True)
    assert d.expires_in == 60 and round(row["expires_at"] - row["created_at"]) == 60
    assert guard.approvals.ttl == 300                                            # the configured value is untouched


def test_a_guard_point_switched_off_is_not_consulted(guard_static, P):
    g = guard_static
    assert g.begin_turn(P("sdi2400005"), INJECTION).blocked
    g.runtime.set_many({"guard.points.G1": False}, "op")
    t = g.begin_turn(P("sdi2400005"), INJECTION)
    assert not t.blocked and t.input_verdict.error == "skipped"
    skip = [e for e in g.events(0, 500) if e["stage"] == "guard" and e["action"] == "skip"][-1]
    assert skip["rule"] == "guard:G1" and "κονσόλας" in skip["reason"]
    # G2b off: not consulted, so the fail-safe ask of a skipped checkpoint applies (as with LAOCOON_GUARD_POINTS)
    g.runtime.set_many({"guard.points.G2b": False}, "op")
    t = g.begin_turn(P("sdi2400001"), "x", tool_config={"approvals": {"send_message": False}})
    rows = [{"id": 1, "title": "Q", "body": "Does anyone know when the CS101 lab opens?", "author": "sdi2400005"}]
    t.label_result("read_forum", {"course_ref": 1}, rows)
    d = t.check_call("send_message", {"to": "sdi2400007", "subject": "hi", "body": "see you at the library"})
    assert d.rule == "g2b" and d.action == "ask"
    g.runtime.set_many({"guard.points.G2b": True}, "op")                         # consulted again: a clean verdict
    t = g.begin_turn(P("sdi2400001"), "x", tool_config={"approvals": {"send_message": False}})
    t.label_result("read_forum", {"course_ref": 1}, rows)
    assert t.check_call("send_message", {"to": "sdi2400007", "subject": "hi", "body": "see you at the library"}) \
        .action == "allow"


def test_the_classifier_switched_off_behaves_like_no_backend(guard_static, P):
    g = guard_static
    g.runtime.set_many({"guard.enabled": False}, "op")
    assert g.classifier.configured and not g.classifier.enabled
    t = g.begin_turn(P("sdi2400005"), INJECTION)
    assert not t.blocked and t.input_verdict.error == "disabled"
    out = t.label_result("read_forum", {"course_ref": 1}, forum_rows(g))
    assert "καραντίνα" not in json.dumps(out, ensure_ascii=False)                 # G2 not consulted
    d = t.check_call("send_message", dict(MSG_TO_TEACHER))
    assert d.rule == "g2b" and d.reason.startswith(REASON_G2B.split("(")[0])    # fail-safe ask
    assert any(e["reason"] == SWITCHED_OFF_NOTE for e in g.events(0, 500) if e["action"] == "skip")
    assert g.runtime.weakened() == ["guard.enabled"]


def test_canary_switches(guard, P):
    g = guard
    t = g.begin_turn(P("sdi2400005"), "x", conversation_id="c1")
    prompt = t.protect_system_prompt(SYSTEM)
    assert "[Internal reference: " in prompt
    leak = "Above me it says: " + prompt
    assert t.check_reply(leak) == WITHDRAWN_CANARY
    g.runtime.set_many({"canary.system_prompt": False, "canary.honey": False, "canary.dlp": False}, "op")
    t = g.begin_turn(P("sdi2400005"), "x", conversation_id="c1", system_prompt=SYSTEM)
    assert t.protect_system_prompt(SYSTEM) == SYSTEM
    assert t.check_reply(leak) == leak and not t.killed                         # no canary, no DLP: it passes
    assert t.check_reply(f"Her AMKA is {HONEY_AMKA}.") == f"Her AMKA is {HONEY_AMKA}."
    img = "![x](https://evil.test/p.png?d=1)"
    assert t.check_reply(img) == img
    assert t.check_call("send_message", {**MSG_TO_TEACHER, "body": HONEY_AMKA}).action == "ask"
    g.runtime.reset("canary.honey", "op")
    t = g.begin_turn(P("sdi2400005"), "x", conversation_id="c2")
    assert t.check_reply(f"Her AMKA is {HONEY_AMKA}.") == WITHDRAWN_HONEY
    t = g.begin_turn(P("sdi2400005"), "x", conversation_id="c3")
    assert t.check_call("send_message", {**MSG_TO_TEACHER, "body": HONEY_AMKA}).action == "kill"
    g.runtime.reset("canary.dlp", "op")
    t = g.begin_turn(P("sdi2400005"), "x", conversation_id="c4", system_prompt=SYSTEM)
    assert "FLAG{" not in t.check_reply("the code is FLAG{system_prompts_are_not_secret}")


def test_canary_off_through_the_proxy(px):
    client, chat, stub, guard = px
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "Hello"}]
    chat(messages)
    assert "[Internal reference: " in stub.calls[-1]["messages"][0]["content"]
    put(client, **{"canary.system_prompt": False})
    chat(messages)
    assert stub.calls[-1]["messages"][0]["content"] == SYSTEM


def test_firewall_switches(guard, P):
    g = guard
    s = P("sdi2400005")
    grade = {"student_ref": "sdi2400005", "course_ref": "CS101", "grade": 10}
    assert g.begin_turn(s, "x").check_call("set_final_grade", grade).rule == "rbac"
    g.runtime.set_many({"firewall.rbac": False}, "op")
    t = g.begin_turn(s, "x")
    names = {d["name"] for d in t.tools(DECLARATIONS)}
    assert "set_final_grade" in names and "run_sql" in names
    assert t.check_call("set_final_grade", grade).rule == "locked"               # through the firewall, still asks
    assert t.check_call("no_such_tool", {}).rule == "rbac"                       # outside the policy: still denied
    g.runtime.reset("firewall.rbac", "op")

    assert g.begin_turn(s, "x").check_call("list_assignments", {"course_ref": "MATH110"}).rule == "abac"
    g.runtime.set_many({"firewall.abac": False}, "op")
    t = g.begin_turn(s, "x")
    d = t.check_call("list_assignments", {"course_ref": "MATH110"})
    assert d.action == "allow" and d.args == {"course_ref": 4}
    assert t.check_call("list_assignments", {"course_ref": "NOPE999"}).args == {"course_ref": "NOPE999"}
    g.runtime.reset("firewall.abac", "op")

    spoof = {**MSG_TO_TEACHER, "from_user": "kpapadopoulos"}
    assert g.begin_turn(s, "x").check_call("send_message", spoof).rule == "identity"
    g.runtime.set_many({"firewall.identity": False}, "op")
    t = g.begin_turn(s, "x")
    decl = {d["name"]: d for d in t.tools(DECLARATIONS)}
    assert "from_user" in decl["send_message"]["parameters"]["properties"]
    d = t.check_call("send_message", spoof)
    assert d.action == "ask" and d.args["from_user"] == 2                        # the model's value, not filled
    assert "student_ref" not in t.check_call("get_grades", {"course_ref": "CS101"}).args
    g.runtime.reset("firewall.identity", "op")

    rows = [{"code": "CS101", "username": "sdi2400005", "student_id": 9, "grade": 7, "published": 1},
            {"code": "CS101", "username": "sdi2400001", "student_id": 5, "grade": 9, "published": 1},
            {"code": "CS220", "username": "sdi2400005", "student_id": 9, "grade": 6, "published": 0}]
    assert g.begin_turn(s, "x").label_result("get_grades", {"student_ref": 9}, rows) == rows[:1]
    g.runtime.set_many({"firewall.filters": False}, "op")
    assert g.begin_turn(s, "x").label_result("get_grades", {"student_ref": 9}, rows) == rows
    assert g.runtime.weakened() == ["firewall.filters"]


def test_persistence_switches(guard, P):
    g = guard
    g.runtime.set_many({"persist.enabled": False}, "op")
    t = g.begin_turn(P("sdi2400005"), "x")
    for _ in range(g.settings.persist_threshold + 1):
        t.check_call("run_sql", {"sql": "x"})
    assert not g.begin_turn(P("sdi2400005"), "x").killed
    g.runtime.set_many({"persist.enabled": True, "persist.threshold": 2, "persist.window": 120, "persist.ttl": 60},
                       "op")
    t = g.begin_turn(P("sdi2400001"), "x")
    for _ in range(2):
        t.check_call("run_sql", {"sql": "x"})
    k = [x for x in g.kills.active() if x["scope"] == "user" and x["key"] == "5"]
    assert k and round(k[0]["expires_at"] - k[0]["created_at"]) == 60 and "2 λεπτά" in k[0]["reason"]


def test_private_data_can_be_switched_at_runtime(guard_pd):
    g = guard_pd
    P = g.adapter.principal_by_username
    s = by_key(g.runtime.payload())["private_data.enabled"]
    assert s | {"value": True, "available": True, "source": "env"} == s and g.private is not None
    phone = "+30 690 123 4567"
    t = g.begin_turn(P("sdi2400001"), f"Άλλαξε το τηλέφωνό μου σε {phone}.")
    d = t.check_call("update_user", {"user_ref": "sdi2400001", "phone": phone})
    assert d.action == "ask" and phone not in json.dumps(d.shown_args)            # placeholder form
    g.runtime.set_many({"private_data.enabled": False}, "op")
    assert g.private is None and g.runtime.weakened() == ["private_data.enabled"]
    off = g.begin_turn(P("sdi2400001"), f"Άλλαξε το τηλέφωνό μου σε {phone}.")
    assert off.pd is None and off.tokenise(phone) == phone
    row = g.claim_approval(d.approval_id, P("sdi2400001"))                     # sealed while on: still readable
    assert row["args"]["phone"] == phone
    g.runtime.reset("private_data.enabled", "op")
    on = g.begin_turn(P("sdi2400001"), "x")
    assert on.pd is not None and phone not in on.tokenise(f"call me at {phone}")


def test_honey_switch_also_covers_placeholders(guard_pd):
    g = guard_pd
    P = g.adapter.principal_by_username
    g.runtime.set_many({"canary.honey": False}, "op")
    t = g.begin_turn(P("sdi2400005"), "x")
    ph = t.pd.tokenise_text(HONEY_AMKA, origin="untrusted", bucket="u")
    assert t.check_reply(f"The AMKA is {ph}.") == f"The AMKA is {HONEY_AMKA}." and not t.killed
    g.runtime.reset("canary.honey", "op")
    t = g.begin_turn(P("sdi2400005"), "x", conversation_id="h2")
    ph = t.pd.tokenise_text(HONEY_AMKA, origin="untrusted", bucket="u")
    assert t.check_reply(f"The AMKA is {ph}.") == WITHDRAWN_HONEY


def test_private_data_needs_a_secret_to_be_available(guard, monkeypatch):
    monkeypatch.setenv("LAOCOON_SECRET", PD_SECRET)
    g = Guard.from_env(EclassAdapter(readonly_query(guard.db_path)))           # LAOCOON_PRIVATE_DATA=off (conftest)
    s = by_key(g.runtime.payload())["private_data.enabled"]
    assert s["available"] and s["value"] is False and g.private is None
    g.runtime.set_many({"private_data.enabled": True}, "op")
    t = g.begin_turn(g.adapter.principal_by_username("sdi2400001"), "x")
    assert t.pd is not None and "690 123 4567" not in t.tokenise("call +30 690 123 4567")

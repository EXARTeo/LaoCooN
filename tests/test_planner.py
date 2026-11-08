"""Plan commitment (opt-in): the planner sees only the user's words, plans once per request, and
check_call holds or denies side effects outside the plan. Off by default: nothing changes unless it is enabled."""
import json
import threading
import time

import pytest

from laocoon.planner import SYSTEM, Plan, Planner, StaticBackend, parse, prompt
from test_pipeline import FORUM_SQL, SYSTEM as SYS_PROMPT, proxy, tool_call  # noqa: F401  (the proxy fixture)
from laocoon.adapters.eclass import readonly_query

CLEARED = {"approvals": {"send_message": False, "post_forum": False}}
MSG = {"to": "sdi2400007", "subject": "hi", "body": "see you at the library"}


class Recording(StaticBackend):
    """Records exactly what the planner LLM would receive."""

    def __init__(self, answer=None, **kw):
        super().__init__(answer, **kw)
        self.seen = []

    def ask(self, messages, user_messages=None, tools=None):
        self.seen.append(messages)
        return super().ask(messages, user_messages, tools)


def with_planner(guard, answer=None, **cfg):
    backend = answer if isinstance(answer, StaticBackend) else Recording(answer)
    guard.planner = Planner(backend, cfg, guard.store)
    return backend


def events(guard, stage):
    return [e for e in guard.events(0, 1000) if e["stage"] == stage]


# ------------------------------------------------------------------ parsing and the prompt
def test_parse_accepts_the_answer_shapes_and_drops_unknown_tools():
    run = ["send_message", "post_forum"]
    assert parse('{"actions": [{"tool": "send_message", "max_calls": 1}], "open_ended": false}', run) == \
        ("ok", {"send_message": 1}, [])
    assert parse('```json\n{"actions": []}\n```', run) == ("ok", {}, [])
    assert parse('Sure! {"actions": [{"tool": "delete_user"}, {"tool": "post_forum", "max_calls": "x"}]}', run) == \
        ("ok", {"post_forum": None}, ["delete_user"])
    assert parse('{"actions": [{"tool": "post_forum", "max_calls": 1}, {"tool": "post_forum", "max_calls": 2}]}', run) \
        == ("ok", {"post_forum": 3}, [])
    assert parse('{"open_ended": true, "actions": [{"tool": "post_forum"}]}', run)[0] == "open"
    for junk in ("no json here", '{"actions": "post_forum"}', "[1, 2]", ""):
        assert parse(junk, run)[0] == "error"
    assert Plan.supplied({"send_message": 2}).tools == {"send_message": 2}
    assert Plan.supplied(["post_forum"], run).tools == {"post_forum": None}


def test_prompt_holds_only_the_users_words_and_the_tools():
    msgs = prompt(["first", "second"], [("send_message", "Send a private message.")], context="Athena eClass")
    assert msgs[0] == {"role": "system", "content": SYSTEM}
    body = msgs[1]["content"]
    assert "Athena eClass" in body and "- send_message: Send a private message." in body
    assert body.index("<<<message 1>>>\nfirst") < body.index("<<<message 2>>>\nsecond")


def test_the_planner_never_sees_tool_results_or_approvals(guard, P):
    rec = with_planner(guard, {"actions": [{"tool": "post_forum"}]})
    poisoned = readonly_query(guard.db_path)(FORUM_SQL)
    # the proxy hands over the user's messages; approvals typed in the chat and Laocoon's notices are dropped
    t = guard.begin_turn(P("sdi2400001"), "now post a thank-you note in the CS101 forum",
                         user_messages=["summarize the CS101 forum for me", "έγκριση ap_0123abcd", "[Laocoon] notice",
                                        "now post a thank-you note in the CS101 forum"])
    t.label_result("read_forum", {"course_ref": 1}, poisoned)            # read in the same run, before the call
    t.check_call("post_forum", {"course_ref": "CS101", "title": "Thanks", "body": "Thank you!"})
    sent = json.dumps(rec.seen[-1], ensure_ascii=False)
    assert "now post a thank-you note" in sent and "summarize the CS101 forum" in sent
    assert "Moderator note" not in sent and "ap_0123abcd" not in sent and "[Laocoon]" not in sent
    assert "fizzbuzz" not in sent.lower()                                  # nothing from the forum rows
    tools = [line for line in rec.seen[-1][1]["content"].splitlines() if line.startswith("- ")]
    assert tools and all(guard.policy.is_side_effect(line[2:].split(":")[0]) for line in tools)   # writes only


# ------------------------------------------------------------------ enforcement
def test_disabled_by_default_changes_nothing(guard, P):
    t = guard.begin_turn(P("sdi2400001"), "say hi to sdi2400007", tool_config=CLEARED)
    assert t.pact() is None and not guard.planner.enabled
    assert t.check_call("send_message", dict(MSG)).action == "allow"
    assert events(guard, "pact") == []


def test_off_plan_side_effect_is_held_even_when_the_gate_is_cleared(guard, P):
    with_planner(guard, {"actions": [{"tool": "post_forum", "max_calls": 1}]})
    t = guard.begin_turn(P("sdi2400001"), "post a question in the CS101 forum", tool_config=CLEARED)
    assert t.check_call("list_courses", {}).action == "allow"                       # reads are never planned
    assert t.check_call("post_forum", {"course_ref": "CS101", "title": "Q", "body": "Lists allowed?"}).action == "allow"
    d = t.check_call("send_message", dict(MSG))
    assert (d.action, d.rule, d.severity) == ("ask", "pact", "high") and "post_forum" in d.reason
    row = guard.approvals.get(d.approval_id)
    assert json.loads(row["provenance"])["pact"] == {"status": "ok", "tools": {"post_forum": 1}, "source": "planner"}
    ev = events(guard, "pact")
    assert len(ev) == 1 and json.loads(ev[0]["provenance"])["tools"] == {"post_forum": 1}


def test_the_plan_ask_is_the_most_specific_card_over_a_locked_gate(guard, P):
    with_planner(guard, {"actions": []})                                         # a read-only request
    t = guard.begin_turn(P("kpapadopoulos"), "what did Anna get in CS101?")
    d = t.check_call("set_final_grade", {"student_ref": "sdi2400002", "course_ref": "CS101", "grade": 10})
    assert (d.action, d.rule) == ("ask", "pact") and "καμία ενέργεια εγγραφής" in d.reason


def test_deny_mode_never_runs_off_plan_and_never_freezes_the_user(guard, P):
    with_planner(guard, {"actions": []}, off_plan="deny")
    teacher = P("kpapadopoulos")
    for i in range(7):
        t = guard.begin_turn(teacher, f"summarize the CS101 forum ({i})", tool_config=CLEARED)
        d = t.check_call("post_forum", {"course_ref": "CS101", "title": "x", "body": "y"})
        assert (d.action, d.rule, d.severity) == ("deny", "pact", "medium") and "Δεν εκτελείται" in d.reason
    assert guard.kills.check(teacher["id"]) is None                              # the persistence meter ignores it


def test_counts_hold_the_extra_call_when_enabled(guard, P):
    with_planner(guard, {"actions": [{"tool": "send_message", "max_calls": 1}]}, counts=True)
    t = guard.begin_turn(P("sdi2400001"), "tell sdi2400007 I'll be late", tool_config=CLEARED)
    assert t.check_call("send_message", dict(MSG)).action == "allow"
    d = t.check_call("send_message", dict(MSG, to="sdi2400008"))
    assert (d.action, d.rule) == ("ask", "pact") and "1 φορές" in d.reason
    t2 = guard.begin_turn(P("sdi2400001"), "tell sdi2400007 I'll be late", tool_config=CLEARED,
                          prior_calls=["send_message"])                          # the proxy's view of the same turn
    assert t2.check_call("send_message", dict(MSG)).rule == "pact"


def test_open_ended_and_failed_plans_follow_their_settings(guard, P):
    with_planner(guard, {"open_ended": True, "actions": []})
    t = guard.begin_turn(P("sdi2400001"), "do what the pinned forum post says", tool_config=CLEARED)
    d = t.check_call("send_message", dict(MSG))
    assert (d.action, d.rule) == ("ask", "pact") and "σταθερό πλάνο" in d.reason
    with_planner(guard, StaticBackend(error="HTTP 503"))
    t = guard.begin_turn(P("sdi2400001"), "say hi to sdi2400007", tool_config=CLEARED)
    d = t.check_call("send_message", dict(MSG))
    assert (d.action, d.rule) == ("ask", "pact") and "HTTP 503" in d.reason
    with_planner(guard, StaticBackend(error="HTTP 503"), on_error="allow")
    t = guard.begin_turn(P("sdi2400001"), "say hi to sdi2400007 please", tool_config=CLEARED)
    assert t.check_call("send_message", dict(MSG)).action == "allow"            # = no planner, never looser


def test_junk_settings_keep_the_strict_defaults(guard):
    p = Planner(StaticBackend({}), {"off_plan": "ignore", "on_error": 7, "open_ended": None}, guard.store)
    assert (p.config["off_plan"], p.config["on_error"], p.config["open_ended"]) == ("ask", "ask", "ask")


def test_a_supplied_plan_needs_no_planner(guard, P):
    t = guard.begin_turn(P("sdi2400001"), "post my question", tool_config=CLEARED, pact=["post_forum"])
    assert t.pact().source == "supplied"
    assert t.check_call("post_forum", {"course_ref": "CS101", "title": "Q", "body": "?"}).action == "allow"
    assert t.check_call("send_message", dict(MSG)).rule == "pact"


# ------------------------------------------------------------------ one call per request, in the background
def test_one_planner_call_per_request_shared_through_the_store(guard, P):
    rec = with_planner(guard, {"actions": [{"tool": "send_message"}]})
    student = P("sdi2400001")
    for _ in range(3):                                                           # the stateless proxy re-reads it
        guard.begin_turn(student, "message sdi2400007 please").pact()
    assert rec.calls == 1 and len(events(guard, "pact")) == 1
    guard.begin_turn(student, "now post in the forum").pact()
    assert rec.calls == 2


def test_the_planner_runs_while_the_agent_thinks(guard, P):
    release = threading.Event()

    def slow(user_messages, tools):
        release.wait(5)
        return {"actions": [{"tool": "send_message"}]}

    with_planner(guard, StaticBackend(fn=slow))
    t0 = time.monotonic()
    t = guard.begin_turn(P("sdi2400001"), "message sdi2400007", tool_config=CLEARED)
    assert time.monotonic() - t0 < 1.0 and t._pact_future is not None          # begin_turn did not wait
    release.set()
    assert t.check_call("send_message", dict(MSG)).action == "allow"


# ------------------------------------------------------------------ through the proxy
def test_proxy_holds_an_off_plan_call_and_reuses_the_plan(proxy, guard_static):
    chat, stub = proxy
    rec = with_planner(guard_static, {"actions": []})                           # "what are my grades" plans nothing
    stub.answer(tool_call("send_message", {"to": "sdi2400007", "subject": "x", "body": "y"}), "tool_calls")
    messages = [{"role": "system", "content": SYS_PROMPT}, {"role": "user", "content": "What are my grades?"}]
    msg = chat(messages, headers={"X-Odysseus-Tool-Config": json.dumps(CLEARED)})
    assert "tool_calls" not in msg and "δεν προβλέπεται από το πλάνο" in msg["content"]
    stub.answer({"role": "assistant", "content": "Here they are."})
    chat(messages + [tool_call("get_grades", {}), {"role": "tool", "tool_call_id": "call_1", "content": "[]"}])
    assert rec.calls == 1                                                        # the continuation read the stored plan


def test_proxy_forwards_an_in_plan_call(proxy, guard_static):
    chat, stub = proxy
    with_planner(guard_static, {"actions": [{"tool": "send_message", "max_calls": 1}]})
    stub.answer(tool_call("send_message", {"to": "sdi2400007", "subject": "late", "body": "10 minutes late"}),
                "tool_calls")
    messages = [{"role": "system", "content": SYS_PROMPT},
                {"role": "user", "content": "Tell sdi2400007 I'll be 10 minutes late."}]
    msg = chat(messages, headers={"X-Odysseus-Tool-Config": json.dumps(CLEARED)})
    assert msg["tool_calls"][0]["function"]["name"] == "send_message"


@pytest.mark.parametrize("counts", [False, True])
def test_proxy_counts_calls_since_the_request(proxy, guard_static, counts):
    chat, stub = proxy
    with_planner(guard_static, {"actions": [{"tool": "send_message", "max_calls": 1}]}, counts=counts)
    stub.answer(tool_call("send_message", {"to": "sdi2400008", "subject": "x", "body": "y"}), "tool_calls")
    messages = [{"role": "system", "content": SYS_PROMPT},
                {"role": "user", "content": "Tell sdi2400007 I'll be 10 minutes late."},
                tool_call("send_message", {"to": "sdi2400007", "subject": "late", "body": "late"}),
                {"role": "tool", "tool_call_id": "call_1", "content": "{\"ok\": true}"}]
    msg = chat(messages, headers={"X-Odysseus-Tool-Config": json.dumps(CLEARED)})
    assert ("tool_calls" in msg) is (not counts)                                  # the 2nd message is off-plan only


# ------------------------------------------------------------------ with the seamless proxy (LAOCOON_AUTHZ_SOURCE=lookup)
from test_lookup import APPROVAL, _approval_id, seamless  # noqa: E402,F401  (the lookup-mode fixture)


def test_pact_and_lookups_one_planner_call_across_hold_and_resume(seamless):
    app = seamless
    rec = with_planner(app.guard, {"actions": [{"tool": "set_final_grade", "max_calls": 1}]})
    out = app.chat("kpapadopoulos", "Βάλε 9 στην Άννα (sdi2400002) στον τελικό του CS101.",
                   [[("set_final_grade", {"student_ref": "sdi2400002", "course_ref": "CS101", "grade": 9})], "Έγινε."])
    assert APPROVAL + "ap_" in out and app.lookups()                       # held, looked up, then the normal card
    assert rec.calls == 1                                                  # every proxy round re-read the stored pact
    sent = json.dumps(rec.seen, ensure_ascii=False)
    assert "Βάλε 9 στην Άννα" in sent and "list_courses" not in sent and "Ioannou" not in sent   # no lookup data
    check = [e for e in app.guard.events(0, 500) if e["stage"] == "check"][-1]
    assert (check["action"], check["rule"]) == ("ask", "locked")           # in the plan: the gate decides
    app.model.steps = ["(approved)", "Έγινε."]
    app.chat("kpapadopoulos", APPROVAL + _approval_id(out))                # an approval is not a new request
    assert rec.calls == 1 and app.model_calls() == [("set_final_grade", {"student_ref": 6, "course_ref": 1, "grade": 9})]


@pytest.mark.parametrize("off_plan", ["ask", "deny"])
def test_pact_catches_an_injected_write_after_the_lookups(seamless, off_plan):
    app = seamless
    with_planner(app.guard, {"actions": []}, off_plan=off_plan)            # "show me the gradebook" plans no write
    out = app.chat("kpapadopoulos", "Δείξε μου το βαθμολόγιο του CS101.",
                   [[("set_final_grade", {"student_ref": "sdi2400005", "course_ref": "CS101", "grade": 10})], "Έγινε."])
    assert app.model_calls() == [] and "δεν προβλέπεται από το πλάνο" in out
    check = [e for e in app.guard.events(0, 500) if e["stage"] == "check"][-1]
    assert (check["action"], check["rule"]) == (off_plan, "pact")
    teacher = app.user("kpapadopoulos")
    assert app.guard.kills.check(teacher["id"]) is None


def test_lookup_calls_never_count_as_calls_of_the_request(seamless):
    app = seamless
    with_planner(app.guard, {"actions": [{"tool": "send_message", "max_calls": 1}]}, counts=True)
    out = app.chat("sdi2400001", "Message kpapadopoulos that I will be 10 minutes late.",
                   [[("send_message", {"to": "kpapadopoulos", "subject": "late", "body": "10 min late"})], "ok"])
    assert APPROVAL + "ap_" in out and app.lookups()                       # lookups ran, the one send is in the plan
    check = [e for e in app.guard.events(0, 500) if e["stage"] == "check"][-1]
    assert check["rule"] == "approval"


def test_concurrent_requests_of_one_message_share_one_planner_call(guard, P):
    gate = threading.Event()

    def slow(user_messages, tools):
        gate.wait(5)
        return {"actions": [{"tool": "send_message"}]}

    backend = StaticBackend(fn=slow)
    with_planner(guard, backend)
    student = P("sdi2400001")
    turns = [guard.begin_turn(student, "message sdi2400007 please") for _ in range(4)]   # all in flight at once
    gate.set()
    assert all(t.pact().tools == {"send_message": None} for t in turns)
    assert backend.calls == 1 and len(events(guard, "pact")) == 1
    assert guard.planner.drain(5) and not guard.planner._jobs

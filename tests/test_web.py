"""The web pages served by the proxy: welcome (public), console and policy studio (console token)."""
import json
import re
from urllib.parse import urlsplit

import pytest

import laocoon.proxy as PX
from laocoon import web
from laocoon.console import console_html, login_html, policies_html, settings_html, welcome_html

TOKEN = "test-console-token"
H = {"X-Laocoon-Token": TOKEN}


@pytest.fixture
def client(guard, monkeypatch):
    monkeypatch.setenv("LAOCOON_CONSOLE_TOKEN", TOKEN)
    monkeypatch.setenv("LAOCOON_ECLASS_DB", guard.db_path)
    monkeypatch.setenv("LAOCOON_APP_URL", "http://app.test:8181")
    return PX.create_app(PX.ProxyConfig(), guard).test_client()


def _clean(body: str):
    assert not re.findall(r"__[A-Z_]+__", body), "unsubstituted placeholder"
    assert "<!--#include" not in body, "unresolved include"


def test_pages_render_completely():
    nav = {"home": "/", "console": "/laocoon", "policies": "/laocoon/policies"}
    for body in (console_html("/laocoon/api", "Proxy", nav=nav), policies_html("/laocoon/api", nav=nav),
                 settings_html("/laocoon/api", nav=nav), login_html("/laocoon/api", demo=True, nav=nav),
                 welcome_html(metrics={}, nav=nav), console_html("/admin/odysseus/api", "SDK")):  # SDK: old signature
        _clean(body)
        assert body.startswith("<!doctype html>") and 'lang="en"' in body


def test_values_are_escaped_where_they_land():
    body = console_html('/x";alert(1);//', '<b>"t"</b>')
    assert 'const API = "/x;alert(1);//";' in body                      # no quote can close the JS string
    assert "<b>" not in body.split("<body>", 1)[1].split("<script", 1)[0]
    assert '"</script>' not in welcome_html(metrics={"rows": [{"metric": "</script>", "values": []}], "columns": []})


def test_welcome_is_public_and_links_the_app(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    _clean(body)
    assert 'data-app="http://app.test:8181"' in body and 'data-console="/laocoon"' in body


def test_console_and_studio_need_a_session_or_the_token(client):
    for url in ("/laocoon", "/laocoon/policies", "/laocoon/settings"):  # pages send the browser to sign in
        r = client.get(url)
        assert r.status_code == 302 and r.headers["Location"] == "/laocoon/login?next=" + url, url
    for url in ("/laocoon/api/policy", "/laocoon/api/policy/drafts", "/laocoon/api/state"):
        assert client.get(url).status_code == 401, url                  # the API answers 401
    assert client.get("/laocoon/policies?token=" + TOKEN).status_code == 200
    page = client.get("/laocoon", headers=H).get_data(as_text=True)
    assert '"policies": "/laocoon/policies"' in page                    # the console links the studio


def test_policy_state_is_the_active_policy_and_valid(client, guard):
    d = client.get("/laocoon/api/policy", headers=H).get_json()
    assert d["active"]["path"] == guard.settings.policy_path
    a = d["analysis"]
    assert a["ok"] and a["counts"]["error"] == 0
    assert set(a["matrix"]["roles"]) == {"student", "teacher", "admin"}
    assert a["summary"]["unguarded"] == 0                               # every side effect asks for approval
    assert {e["name"] for e in d["catalog"]["effects"]} == {"read", "write", "communicate", "external"}
    assert d["templates"][0]["id"] == "active" and d["drafts"] == []


def test_analyse_points_at_the_line(client):
    text = client.get("/laocoon/api/policy", headers=H).get_json()["active"]["yaml"]
    bad = text.replace("default: deny", "default: allow", 1)
    a = client.post("/laocoon/api/policy/analyse", json={"yaml": bad}, headers=H).get_json()
    assert not a["ok"]
    err = next(i for i in a["issues"] if i["level"] == "error")
    assert err["path"] == ["default"] and bad.splitlines()[err["line"] - 1].startswith("default:")
    broken = client.post("/laocoon/api/policy/analyse", json={"yaml": "a: [1,"}, headers=H).get_json()
    assert broken["matrix"] is None and broken["counts"]["error"] >= 1


def test_drafts_roundtrip_and_never_touch_the_running_policy(client, guard):
    before_file = open(guard.settings.policy_path, encoding="utf-8").read()
    before_policy = repr(guard.policy_data)
    text = before_file.replace("default: deny", "default: allow", 1)    # a draft may even be invalid policy
    r = client.put("/laocoon/api/policy/drafts/try-1", json={"yaml": text}, headers=H)
    assert r.status_code == 200 and r.get_json()["saved"] and r.get_json()["counts"]["error"] == 1
    assert [x["name"] for x in client.get("/laocoon/api/policy/drafts", headers=H).get_json()["drafts"]] == ["try-1"]
    assert client.get("/laocoon/api/policy/drafts/try-1", headers=H).get_json()["yaml"] == text
    diff = client.post("/laocoon/api/policy/diff", json={"yaml": before_file, "against": "try-1"}, headers=H).get_json()
    assert "-default: allow" in diff["diff"] and "+default: deny" in diff["diff"]
    assert open(guard.settings.policy_path, encoding="utf-8").read() == before_file
    assert repr(guard.policy_data) == before_policy
    r = client.delete("/laocoon/api/policy/drafts/try-1", headers=H)
    assert r.get_json()["drafts"] == []
    assert client.get("/laocoon/api/policy/drafts/try-1", headers=H).status_code == 404


def test_drafts_reject_bad_names_and_non_yaml(client):
    for name in (".hidden", "-x", "a" * 65, "a.b"):
        assert client.put(f"/laocoon/api/policy/drafts/{name}", json={"yaml": "a: 1"}, headers=H).status_code == 400, name
    assert client.get("/laocoon/api/policy/drafts/..%2F..%2Fetc", headers=H).status_code in (400, 404)
    r = client.put("/laocoon/api/policy/drafts/broken", json={"yaml": "a: [1,"}, headers=H)
    assert r.status_code == 422 and not r.get_json()["saved"]
    assert client.get("/laocoon/api/policy/drafts", headers=H).get_json()["drafts"] == []


def test_templates(client):
    blank = client.get("/laocoon/api/policy/templates/blank", headers=H).get_json()["yaml"]
    a = client.post("/laocoon/api/policy/analyse", json={"yaml": blank}, headers=H).get_json()
    assert a["ok"] and a["matrix"]["tools"] == []
    assert client.get("/laocoon/api/policy/templates/file:nope", headers=H).status_code == 404


def test_eval_metrics_reads_the_report(tmp_path):
    report = tmp_path / "latest.md"
    report.write_text("# Laocoon eval · 2026-11-07T10:09\n\n- LLM: **mock** (model `m`), runs per scenario: 2\n\n"
                      "| Metric | Without | With |\n|---|---|---|\n| ASR (all attacks) | 100% (26/26) | 0% (0/26) |\n"
                      "| LLM calls | — | — |\n\n## Per scenario\n| x |\n", encoding="utf-8")
    m = web.eval_metrics(report)
    assert m["date"] == "2026-11-07" and m["llm"] == "mock" and m["runs"] == 2 and m["columns"] == ["Without", "With"]
    assert m["rows"] == [{"metric": "ASR (all attacks)", "values": ["100% (26/26)", "0% (0/26)"]}]
    assert web.eval_metrics(tmp_path / "missing.md") == {}


def test_analyse_knows_the_seamless_proxy_keys(client):
    """identity, lookups and refs {kind, fallback} (LAOCOON_AUTHZ_SOURCE=lookup) are checked, not rejected."""
    text = client.get("/laocoon/api/policy", headers=H).get_json()["active"]["yaml"]
    assert "fallback: app" in text and "lookups:" in text                # the shipped policy uses them
    for line in ("\n  verify: true", "to: {kind: user, fallback: app}", "ttl: {read: 120"):
        assert text.count(line) == 1, line                              # the real lines, not the header comments
    bad = (text.replace("\n  verify: true", "\n  verify: maybe")
           .replace("to: {kind: user, fallback: app}", "to: {kind: user, fallback: model}")
           .replace("ttl: {read: 120", "ttl: {read: -5"))
    a = client.post("/laocoon/api/policy/analyse", json={"yaml": bad}, headers=H).get_json()
    errs = {tuple(i["path"]): i["line"] for i in a["issues"] if i["level"] == "error"}
    assert set(errs) == {("identity", "verify"), ("refs", "to", "fallback"), ("lookups", "ttl", "read")}
    lines = bad.splitlines()
    assert "maybe" in lines[errs[("identity", "verify")] - 1] and "model" in lines[errs[("refs", "to", "fallback")] - 1]


# ------------------------------------------------------------------ the rename (Odysseus -> Laocoon)
def test_pages_carry_the_brand_mark_and_favicon(client):
    body = client.get("/").get_data(as_text=True)
    assert '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,' in body
    assert 'class="mark"' in body and "<span>Laocoon</span>" in body and "Odysseus" not in body


def test_links_from_before_the_rename_redirect(client):
    r = client.get("/odysseus?token=" + TOKEN)
    assert r.status_code == 308 and r.headers["Location"].endswith("/laocoon?token=" + TOKEN)
    r = client.get("/odysseus/api/state", headers=H)
    assert r.status_code == 308 and r.headers["Location"].endswith("/laocoon/api/state")
    for _ in range(3):                                                  # never off-site, at any hop
        loc = client.get(url if _ else "/odysseus//evil.example").headers.get("Location")
        if not loc:
            break
        assert urlsplit(loc).netloc in ("", "localhost"), loc
        url = urlsplit(loc).path


def test_the_former_header_and_env_names_still_work(guard, monkeypatch):
    monkeypatch.delenv("LAOCOON_CONSOLE_TOKEN", raising=False)
    monkeypatch.setenv("ODYSSEUS_CONSOLE_TOKEN", TOKEN)                 # a settings file from before the rename
    monkeypatch.setenv("LAOCOON_ECLASS_DB", guard.db_path)
    c = PX.create_app(PX.ProxyConfig(), guard).test_client()
    assert c.get("/laocoon/api/state").status_code == 401
    assert c.get("/laocoon", headers={"X-Odysseus-Token": TOKEN}).status_code == 200
    monkeypatch.setenv("LAOCOON_CONSOLE_TOKEN", "newer")               # the new name wins
    assert PX.ProxyConfig().console_token == "newer"


# ------------------------------------------------------------------ operator sign-in
def _login(c, username, password, **kw):
    return c.post("/laocoon/api/login", json={"username": username, "password": password, **kw})


def test_demo_account_signs_in_and_the_cookie_opens_pages_and_api(client):
    page = client.get("/laocoon/login").get_data(as_text=True)
    _clean(page)
    assert '"demo": true' in page and '"token": true' in page            # the page offers both
    assert _login(client, "admin", "wrong").status_code == 401
    r = _login(client, "admin", "laocoon", next="/laocoon/policies")
    assert r.status_code == 200 and r.get_json() == {"ok": True, "user": "admin", "next": "/laocoon/policies"}
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie
    assert client.get("/laocoon").status_code == 200
    assert client.get("/laocoon/api/state").status_code == 200
    assert '"user": "admin"' in client.get("/laocoon/policies").get_data(as_text=True)
    assert client.get("/laocoon/login").status_code == 302              # signed in: straight on
    client.post("/laocoon/api/logout", json={})
    assert client.get("/laocoon/api/state").status_code == 401


def test_configured_accounts_replace_the_demo_account(guard, monkeypatch):
    monkeypatch.setenv("LAOCOON_CONSOLE_TOKEN", TOKEN)
    monkeypatch.setenv("LAOCOON_ECLASS_DB", guard.db_path)
    monkeypatch.setenv("LAOCOON_CONSOLE_USERS", "ops:s3cret:with-colon, judge:j")
    c = PX.create_app(PX.ProxyConfig(), guard).test_client()
    assert _login(c, "admin", "laocoon").status_code == 401
    assert _login(c, "ops", "s3cret:with-colon").status_code == 200
    assert '"demo": false' in c.get("/laocoon/login?again=1").get_data(as_text=True)


def test_the_token_signs_in_too_and_a_token_link_leaves_a_session(client):
    assert _login(client, "token", "not-it").status_code == 401
    assert _login(client, "", TOKEN).get_json()["user"] == "token"
    client.post("/laocoon/api/logout", json={})
    r = client.get("/laocoon?token=" + TOKEN)                           # the links from before sign-in
    assert r.status_code == 200 and "lcn_console=" in r.headers.get("Set-Cookie", "")
    assert client.get("/laocoon/api/state").status_code == 200          # no token needed any more


def test_a_session_ends_when_the_token_or_the_accounts_change(client, guard, monkeypatch):
    value = _login(client, "admin", "laocoon").headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]

    def worker():                                                      # another process with the current settings
        c = PX.create_app(PX.ProxyConfig(), guard).test_client()
        c.set_cookie("lcn_console", value)
        return c.get("/laocoon/api/state").status_code
    assert worker() == 200
    monkeypatch.setenv("LAOCOON_CONSOLE_TOKEN", "rotated")              # the signing key derives from it
    assert worker() == 401
    monkeypatch.setenv("LAOCOON_CONSOLE_TOKEN", TOKEN)
    monkeypatch.setenv("LAOCOON_CONSOLE_USERS", "admin:laocoon2")       # and from the accounts
    assert worker() == 401


def test_cookie_writes_must_be_json_from_this_site(client, guard):
    _login(client, "admin", "laocoon")
    assert client.post("/laocoon/api/kill", data="scope=global").status_code == 403       # a cross-site form
    assert client.post("/laocoon/api/kill", json={"scope": "tool", "key": "x"},
                       headers={"Origin": "http://evil.example"}).status_code == 403
    assert guard.kills.active() == []
    assert client.post("/laocoon/api/kill", json={"scope": "tool", "key": "x"},
                       headers={"Origin": "http://localhost"}).status_code == 200
    assert client.post("/laocoon/api/kill", data="x", headers=H).status_code == 200      # the token is not a cookie


def test_sign_in_redirects_stay_on_this_site(client):
    for bad in ("//evil.example/x", "https://evil.example", "/\\evil.example", "javascript:alert(1)"):
        assert _login(client, "admin", "laocoon", next=bad).get_json()["next"] == "/laocoon", bad
        assert client.get("/laocoon/login?again=1&next=" + bad).status_code == 200
    page = client.get("/laocoon/login?again=1&next=/laocoon/policies").get_data(as_text=True)
    assert 'NEXT = "/laocoon/policies"' in page


def test_sign_in_is_audited(client, guard):
    _login(client, "admin", "laocoon")
    ev = [e for e in guard.events(0, 50) if e["stage"] == "console"]
    assert ev and ev[-1]["action"] == "login" and "admin" in ev[-1]["reason"]
    assert guard.verify_chain()["ok"]


def test_without_token_or_accounts_the_console_stays_open(guard, monkeypatch):
    monkeypatch.delenv("LAOCOON_CONSOLE_TOKEN", raising=False)
    monkeypatch.delenv("ODYSSEUS_CONSOLE_TOKEN", raising=False)
    monkeypatch.delenv("LAOCOON_CONSOLE_USERS", raising=False)
    monkeypatch.setenv("LAOCOON_ECLASS_DB", guard.db_path)
    c = PX.create_app(PX.ProxyConfig(), guard).test_client()
    assert c.get("/laocoon").status_code == 200 and c.get("/laocoon/api/state").status_code == 200
    assert c.post("/laocoon/api/flags/1", data="x").status_code == 200   # local development, as before


# ------------------------------------------------------------------ the visual editor writes into the YAML
def test_form_edits_keep_the_comments_and_untouched_lines(client):
    text = client.get("/laocoon/api/policy", headers=H).get_json()["active"]["yaml"]
    data = client.post("/laocoon/api/policy/analyse", json={"yaml": text}, headers=H).get_json()["data"]
    data["guard"]["thresholds"]["block"] = 0.9
    data["tools"]["post_forum"]["locked"] = True
    data["tools"]["get_grades"]["filter"]["admin"] = ["own_rows"]
    del data["tools"]["fetch_url"]
    a = client.post("/laocoon/api/policy/analyse", json={"data": data, "base": text}, headers=H).get_json()
    new = a["yaml"]
    assert a["data"] == data and a["ok"]
    old_lines, new_lines = text.splitlines(), new.splitlines()
    assert [ln for ln in old_lines if ln.lstrip().startswith("#")] == [ln for ln in new_lines if ln.lstrip().startswith("#")]
    import difflib
    changed = [ln for ln in difflib.unified_diff(old_lines, new_lines, n=0, lineterm="") if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
    assert len(changed) == 6, changed       # 2 lines replaced (-/+), the locked line added, the fetch_url line removed
    assert "  thresholds: {block: 0.9, hitl: 0.5}       # below hitl → allow (keeps false positives low)" in new_lines
    # without a base the form still works (canonical layout)
    b = client.post("/laocoon/api/policy/analyse", json={"data": data}, headers=H).get_json()
    assert b["ok"] and b["yaml"].startswith("# Policy v2 for athena-eclass")


def test_the_catalog_offers_the_form_its_choices(client):
    c = client.get("/laocoon/api/policy", headers=H).get_json()["catalog"]
    assert c["private"]["action"] == ["placeholder", "mask", "drop"] and "date_ddmmyy" in c["private"]["validators"]
    assert c["identity_fields"]["id"] == "User id"


def test_switching_access_keeps_the_yaml_order(client):
    """The visual editor's switches: a role switched off and on again leaves the text as it was, and a new grant is
    written where the editor puts it (roles in the policy's order), not appended."""
    text = client.get("/laocoon/api/policy", headers=H).get_json()["active"]["yaml"]
    data = client.post("/laocoon/api/policy/analyse", json={"yaml": text}, headers=H).get_json()["data"]  # keys sorted

    def write(d, base):          # raw JSON, as the browser sends it (the test client's json= would sort the keys)
        body = json.dumps({"data": d, "base": base})
        return client.post("/laocoon/api/policy/analyse", data=body, content_type="application/json",
                           headers=H).get_json()["yaml"]
    rule = data["tools"]["read_forum"]["allow"].pop("student")
    off = write(data, text)
    assert "allow: {teacher: {course_ref: taught}, admin: true}" in off
    data["tools"]["read_forum"]["allow"] = {"student": rule, **data["tools"]["read_forum"]["allow"]}
    assert write(data, off) == text
    data["tools"]["get_gradebook"]["allow"] = {"student": True, **data["tools"]["get_gradebook"]["allow"]}
    assert "allow: {student: true, teacher: {course_ref: taught}, admin: true}" in write(data, text)

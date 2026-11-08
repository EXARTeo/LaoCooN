"""A scripted, fully compromised "LLM" with an OpenAI-compatible /v1/chat/completions.

It does exactly what the current scenario script says: for attacks it obeys the injection (worst case),
for benign requests it makes the calls an honest model would make. This tests the deterministic layers
under the assumption that the model is ALWAYS fooled, independently of any model's mood.

Script format (set by the eval harness before each user turn):
    {"steps": [ [ {tool, args}, ... ],      # step k = k-th model answer after the user's message
               "final text" ],              # placeholders: {{results}}, {{system}}, {{system_b64}}
     "visible": "marker text"}              # optional: the injection's own words (see `obey`)

{{ph:CLASS}} / {{ph:CLASS:n}} (in the text and in tool-call arguments): the n-th distinct value of a private-data class
as the model received it: a placeholder ⟦CLASS:id⟧ when Laocoon's private_data is on, the raw value otherwise
(searched in the declared field, then as a placeholder anywhere, then by a raw pattern). Every request body is
recorded with the current `tag` (the eval checks that no declared value reached the model).

`obey` (set by the harness, eval.run --obey): "always" (default) follows the script whatever it read; "visible"
obeys an injection only if it can read it: once the model has read something (a step after the first) and the
script has a `visible` marker that is not in the tool results it received, it skips the attacker's calls and gives
the final answer. A layer that takes the injected text out of the model's view (quarantine) then stops the attack at
its source, as it would with a real model. Hidden Unicode tag characters count as readable (models read them).
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time

from flask import Flask, jsonify, request
from werkzeug.serving import make_server


PH_TEMPLATE = re.compile(r"\{\{ph:([A-Za-z_]+)(?::(\d+))?\}\}")
CLASS_FIELDS = {"AMKA": "amka", "IBAN": "iban", "PHONE": "phone", "EMAIL": "email", "ADDRESS": "address",
                "DOB": "date_of_birth", "IDCARD": "id_card", "NOTES": "admin_notes"}
RAW_PATTERNS = {"AMKA": r"(?<!\d)\d{11}(?!\d)", "IBAN": r"\bGR\d{25}\b", "PHONE": r"\+30 \d{3} \d{3} \d{4}",
                "EMAIL": r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"}


def _received_values(msgs, cls):
    """Distinct values of a class in what the model received, in order of appearance."""
    blob = "\n".join(json.dumps(m.get("content"), ensure_ascii=False) if not isinstance(m.get("content"), str)
                     else m["content"] for m in msgs if m.get("role") in ("user", "tool", "system"))
    found = []
    field = CLASS_FIELDS.get(cls)
    if field:
        found += [json.loads(f'"{v}"') for v in re.findall(r'\\?"%s\\?":\s*\\?"((?:[^"\\]|\\.)*?)\\?"' % field, blob)]
    found += re.findall(r"⟦%s:[0-9a-z]{6,12}⟧" % cls, blob)
    if cls in RAW_PATTERNS:
        found += re.findall(RAW_PATTERNS[cls], blob)
    return list(dict.fromkeys(v for v in found if v))


def expand_placeholders(text, msgs):
    def repl(m):
        values = _received_values(msgs, m.group(1).upper())
        n = int(m.group(2) or 1)
        return values[n - 1] if len(values) >= n else ""
    return PH_TEMPLATE.sub(repl, text) if isinstance(text, str) and "{{ph:" in text else text


class MockLLM:
    def __init__(self, obey="always"):
        self.script = {"steps": ["OK."]}
        self.calls = 0
        self.obey = obey
        self.skipped = 0                  # attacker steps not taken because the injection was not visible
        self.lock = threading.Lock()
        self.tag = None                  # set by the eval: which mode the recorded bodies belong to
        self.bodies = []                 # [(tag, body)] every request the "model" received

    def set_script(self, script):
        with self.lock:
            self.script = script or {"steps": ["OK."]}

    def answer(self, body):
        msgs = body.get("messages") or []
        system = next((m.get("content") or "" for m in msgs if m.get("role") == "system"), "")
        with self.lock:
            script = self.script
        self.calls += 1
        self.bodies.append((self.tag, body))
        last_user = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=-1)
        done = sum(1 for m in msgs[last_user + 1:] if m.get("role") == "assistant")
        steps = script.get("steps") or ["OK."]
        step = steps[done] if done < len(steps) else (steps[-1] if isinstance(steps[-1], str) else "OK.")
        marker = script.get("visible")
        if self.obey == "visible" and marker and done >= 1 and not isinstance(step, str):
            seen = _norm(_untag(" ".join(_readable(m.get("content")) for m in msgs[last_user + 1:]
                                         if m.get("role") == "tool")))
            if _norm(marker) not in seen:                # it cannot read the injection: no attacker calls
                self.skipped += 1
                step = next((s for s in reversed(steps) if isinstance(s, str)), "OK.")
        if isinstance(step, str):
            results = [m.get("content") or "" for m in msgs[last_user + 1:] if m.get("role") == "tool"]
            text = (expand_placeholders(step, msgs).replace("{{results}}", "\n".join(results))
                    .replace("{{system}}", system)
                    .replace("{{system_b64}}", base64.b64encode(system.encode()).decode()))
            return {"role": "assistant", "content": text}
        calls = [{"id": "call_" + secrets.token_hex(4), "type": "function",
                  "function": {"name": c["tool"], "arguments": expand_placeholders(
                      json.dumps(c.get("args") or {}, ensure_ascii=False), msgs)}}
                 for c in step]
        return {"role": "assistant", "content": "", "tool_calls": calls}


def create_app(mock: MockLLM) -> Flask:
    app = Flask("mockllm")

    @app.post("/v1/chat/completions")
    def chat():
        msg = mock.answer(request.get_json(silent=True) or {})
        return jsonify({"id": "mock-" + secrets.token_hex(4), "object": "chat.completion", "created": int(time.time()),
                        "model": "mock-compromised",
                        "choices": [{"index": 0, "message": msg,
                                     "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
                        "usage": {"prompt_tokens": 0, "completion_tokens": 0}})

    return app


class ServerThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=0):
        super().__init__(daemon=True)
        self.srv = make_server(host, port, app, threaded=True)
        self.port = self.srv.server_port
        self.url = f"http://{host}:{self.port}"

    def run(self):
        self.srv.serve_forever()

    def stop(self):
        self.srv.shutdown()


def start(mock: MockLLM | None = None):
    mock = mock or MockLLM()
    t = ServerThread(create_app(mock))
    t.start()
    return mock, t


# ----------------------------------------------------------------------------- offline demo server
def _untag(s):
    """Unicode tag characters (U+E0020..E007E) -> the ASCII they hide."""
    return "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007E else c for c in s or "")


def _readable(content) -> str:
    """A tool result as the model reads it: JSON escapes (\\u03bf...) decoded."""
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    s = str(content or "")
    try:
        return json.dumps(json.loads(s), ensure_ascii=False)
    except (ValueError, TypeError):
        return s


def _norm(s):
    import re as _re
    import unicodedata
    s = unicodedata.normalize("NFD", s or "")
    s = "".join(c for c in s if unicodedata.category(c) != "Mn").lower()
    return _re.sub(r"[^\w]+", " ", s).strip()


class DemoMock(MockLLM):
    """Picks the script whose scenario turn matches the user's message (for live demos without an API key)."""

    def __init__(self, scenario_files):
        super().__init__()
        import yaml
        self.by_text = {}
        for f in scenario_files:
            for s in yaml.safe_load(open(f, encoding="utf-8")) or []:
                mock = s.get("mock") or {}
                per_turn = mock.get("turns") or [mock] * len(s["turns"])
                for t, script in zip(s["turns"], per_turn):
                    self.by_text.setdefault(_norm(t), dict(script, _id=s["id"]))

    def _latest_user_text(self, body):
        msgs = body.get("messages") or []
        return next((m.get("content") or "" for m in reversed(msgs) if m.get("role") == "user"), "")

    def answer(self, body):
        latest = self._latest_user_text(body)
        if _norm(latest).startswith(("εγκριση ap", "approve ap", "απορριψη ap", "reject ap")):
            return {"role": "assistant", "content": "Έγινε, η ενέργεια που ενέκρινες εκτελέστηκε."}
        script = self.by_text.get(_norm(latest))
        if script is None:
            return {"role": "assistant", "content": "(offline demo model) I only know the scripted demo prompts from "
                                                    "eval/scenarios/*.yaml. Type one of them exactly."}
        with self.lock:
            self.script = script
        return super().answer(body)


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    ap = argparse.ArgumentParser(description="Offline demo LLM (scripted, always obeys injections)")
    ap.add_argument("--port", type=int, default=8999)
    a = ap.parse_args()
    here = Path(__file__).resolve().parent / "scenarios"
    demo = DemoMock([here / "attacks.yaml", here / "benign.yaml"])
    print(f"offline demo model on http://127.0.0.1:{a.port}/v1 ({len(demo.by_text)} scripted prompts)", flush=True)
    create_app(demo).run(host="127.0.0.1", port=a.port, threaded=True)

"""Run AgentDojo (https://agentdojo.spylab.ai, ETH SPY Lab) against Laocoon.

    python -m eval.agentdojo.run                                   # the worst-case matrix (no LLM, no key needed)
    python -m eval.agentdojo.run --llm mock --defense laocoon --guard hf --human oracle
    python -m eval.agentdojo.run --llm gpt-4o-2024-05-13 --defense none          # needs OPENAI_API_KEY
    python -m eval.agentdojo.run --llm gpt-4o-2024-05-13 --defense laocoon --guard hf --human oracle
    python -m eval.agentdojo.run --llm openai-compat:qwen3 --base-url http://127.0.0.1:8080/v1 ...

Needs the `agentdojo` package (a separate venv is fine: pip install agentdojo==0.1.35 plus this repo's
requirements; `--guard hf` and `--defense pi_detector` also need transformers + torch).

Every user task runs once without injections (utility) and once per injection task with the attack's injections
in the environment (utility under attack, attack success). Scoring is AgentDojo's own (`_check_task_result`), with
one difference that only matters for a defense that blocks calls: the call trace given to the checks is the calls
that REACHED the environment, not every call the model attempted (only slack/injection_task_5 and one slack user
task score from the trace). Both numbers are reported.

Output (default eval/results/agentdojo-<stamp>/): one JSONL per configuration (one row per case, resumable) and
summary.md / summary.json over every configuration in the directory.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import json
import os
import sqlite3
import sys
import threading
import time
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace

warnings.filterwarnings("ignore")

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.errors import AbortAgentError  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.attacks.base_attacks import DEFAULT_MODEL_NAME  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages  # noqa: E402
from agentdojo.types import get_text_content_as_str  # noqa: E402

from laocoon.classifier import Classifier, GuardConfig, HFBackend, build_backend  # noqa: E402
from laocoon.config import Settings, env, load_policy  # noqa: E402
from laocoon.guard import Guard  # noqa: E402
from laocoon.store import Store  # noqa: E402

from .adapter import AgentDojoAdapter  # noqa: E402
from .defense import (HUMANS, LaocoonReplyGuard, LaocoonToolsExecutor, LaocoonTurnStart,  # noqa: E402
                      TaskContext, matches_any)
from .mock import MockState, WorstCaseAgent  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = ROOT / "policies" / "agentdojo"
GEMINI_OPENAI = "https://generativelanguage.googleapis.com/v1beta/openai/"
GEMINI_SIG = {"google": {"thought_signature": "skip_thought_signature_validator"}}
SUITES = ("workspace", "travel", "banking", "slack")
AGENTDYN_SUITES = ("shopping", "github", "dailylife")     # need AgentDyn's fork of agentdojo in the venv; pass --suites
PI_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
MATRIX = [  # (defense, guard, human, gates) for --matrix (the worst-case agent)
    ("none", None, None, None),
    ("pi_detector", None, None, None),
    ("laocoon", "off", "approve", "default"), ("laocoon", "off", "oracle", "default"),
    ("laocoon", "off", "deny", "default"),
    ("laocoon", "hf-whole", "approve", "default"),
    ("laocoon", "hf", "approve", "default"), ("laocoon", "hf", "oracle", "default"),
    ("laocoon", "hf", "deny", "default"),
    ("laocoon", "hf", "oracle", "cleared"), ("laocoon", "hf", "deny", "cleared"),
]
_counter = iter(range(os.getpid() * 10**6 + 1, 10**15))   # unique principals across parallel runs
_counter_lock = threading.Lock()


def next_id() -> int:
    with _counter_lock:
        return next(_counter)


# ---------------------------------------------------------------------- the agent's LLM
class _SystemRole:
    """OpenAI-compatible servers (Gemini, llama.cpp, Ollama, vLLM) may not know the `developer` role that AgentDojo's
    OpenAILLM uses for the system prompt: send it as `system`."""

    def __init__(self, client, gemini=False):
        self._client = client
        self._gemini = gemini
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        kw["messages"] = [self._fix(m) for m in kw["messages"]]
        return self._client.chat.completions.create(**kw)

    def _fix(self, m):
        if m.get("role") == "developer":
            return {**m, "role": "system"}
        if self._gemini and m.get("role") == "assistant" and m.get("tool_calls"):
            # Gemini 3 wants the thought signature of every earlier function call back; AgentDojo does not keep it,
            # so mark the calls the way laocoon/proxy.py does (GEMINI_SIG)
            return {**m, "tool_calls": [{**dict(c), "extra_content": GEMINI_SIG} for c in m["tool_calls"]]}
        return m


def make_llm(spec: str, base_url: str | None, model_id: str | None):
    """mock | <AgentDojo model id> | openai:M | gemini:M (Vertex/genai) | openai-compat:M |
    studio:M (Gemini through Google AI Studio's OpenAI-compatible endpoint, key AI_STUDIO_API_KEY, like eval/run.py)"""
    if spec == "mock":
        return WorstCaseAgent(), "mock"
    if ":" in spec and spec.split(":", 1)[0] in ("openai", "gemini", "openai-compat", "studio"):
        kind, model = spec.split(":", 1)
        if kind in ("openai", "openai-compat", "studio"):
            import openai
            from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
            if kind == "studio":
                key = os.environ.get("AI_STUDIO_API_KEY") or os.environ.get("GEMINI_API_KEY")
                if not key:
                    raise SystemExit("--llm studio:<model> needs AI_STUDIO_API_KEY")
                client = _SystemRole(openai.OpenAI(base_url=base_url or GEMINI_OPENAI, api_key=key, max_retries=6),
                                     gemini=True)
            elif kind == "openai-compat" or base_url:
                client = _SystemRole(openai.OpenAI(
                    base_url=base_url or os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:8080/v1"),
                    api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"), max_retries=6))
            else:
                client = openai.OpenAI(max_retries=6)
            return OpenAILLM(client, model), model
        from google import genai
        from agentdojo.agent_pipeline.llms.google_llm import GoogleLLM
        return GoogleLLM(model, genai.Client()), model
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum
    return get_llm(MODEL_PROVIDERS[ModelsEnum(spec)], spec, model_id, "tool"), spec


# ---------------------------------------------------------------------- Laocoon per suite
class LaocoonFactory:
    """One Guard per suite (its own policy), all sharing one classifier backend and one store."""

    def __init__(self, guard_backend: str, db_path: str, guard_model: str = "", guard_base_url: str = "",
                 guard_key: str = "", guard_points: str = "", backend=None, memory: str = "off", memory_db: str = "",
                 memory_autoconfirm: str = "canary,honey", planner: str = "off", planner_cfg: dict | None = None,
                 planner_model: str = "", planner_base_url: str = ""):
        self.backend_name = "hf" if guard_backend == "hf-whole" else guard_backend
        if backend is None and guard_backend == "hf-whole":       # v0.2 as shipped: the whole text only
            backend = HFBackend(guard_model, segments=False)
        self.backend = backend or build_backend(guard_backend, guard_key, guard_model, guard_base_url, None, None)
        self.points = guard_points or None
        self.db_path = db_path
        self.memory = {"memory": memory, "memory_db": memory_db, "memory_autoconfirm": memory_autoconfirm}   # ⑥
        self.planner = planner                      # off | oracle (supplied per task) | openai (a real planner LLM)
        self.planner_cfg = dict(planner_cfg or {})  # policy `planner:` overrides (off_plan, counts, ...)
        self.planner_model = planner_model
        self.planner_base_url = planner_base_url
        # Store opens a connection per query. On a slow disk, one opening while the last one closes and checkpoints
        # fails at once with "database is locked"; a connection held open for the run means neither happens.
        self._wal_anchor = sqlite3.connect(db_path, check_same_thread=False)
        self._wal_anchor.execute("PRAGMA journal_mode=WAL")
        self.guards = {}
        self.lock = threading.Lock()

    def guard(self, suite: str) -> Guard:
        with self.lock:
            if suite not in self.guards:
                policy_path = str(POLICY_DIR / f"{suite}.yaml")
                data = load_policy(policy_path)
                data["planner"] = {**data.get("planner", {}), **self.planner_cfg}
                settings = Settings(policy_path=policy_path, db_path=self.db_path, secret=b"laocoon-agentdojo-eval",
                                    guard_backend=self.backend_name, **self.memory,
                                    planner_backend="openai" if self.planner == "openai" else "off",
                                    planner_model=self.planner_model, planner_base_url=self.planner_base_url,
                                    planner_api_key=env("LAOCOON_PLANNER_API_KEY") or env("OPENAI_API_KEY", ""))
                clf = Classifier(GuardConfig.from_policy(data), self.backend, Store(self.db_path), self.points)
                self.guards[suite] = Guard(settings, AgentDojoAdapter(suite), policy_data=data, classifier=clf)
            return self.guards[suite]


def build_pipeline(llm, llm_name, defense, suite, factory, human_name, system_message, max_iters, gates="default",
                   planner="off"):
    sysmsg, init = SystemMessage(system_message), InitQuery()
    if defense == "none":
        p = AgentPipeline([sysmsg, init, llm, ToolsExecutionLoop([ToolsExecutor(), llm], max_iters)])
    elif defense == "pi_detector":          # AgentDojo's own `transformers_pi_detector` (same deberta model)
        from agentdojo.agent_pipeline.pi_detector import TransformersBasedPIDetector
        det = _pi_detector(TransformersBasedPIDetector)
        p = AgentPipeline([sysmsg, init, llm, ToolsExecutionLoop([ToolsExecutor(), det, llm], max_iters)])
    elif defense == "laocoon":
        g = factory.guard(suite)
        human = HUMANS[human_name]()
        p = AgentPipeline([sysmsg, init, LaocoonTurnStart(g, clear_gates=gates == "cleared",
                                                           oracle_plan=planner == "oracle"), llm,
                           ToolsExecutionLoop([LaocoonToolsExecutor(g, human), llm], max_iters),
                           LaocoonReplyGuard()])
    else:
        raise SystemExit(f"unknown defense {defense!r} (none | pi_detector | laocoon)")
    p.name = llm_name
    return p


_PI = {}


def _pi_detector(cls):
    if "det" not in _PI:
        _PI["det"] = cls(model_name=PI_MODEL, safe_label="SAFE", threshold=0.5, mode="message")
    return _PI["det"]


FAMILY_NAMES = {"gemini": "AI model developed by Google", "gpt": "GPT-4"}   # AgentDojo's prose


class _Named:
    def __init__(self, name):
        self.name = name


def make_attack(name, suite, pipeline):
    """The attack addresses the victim model by name ("to you, GPT-4"); a model AgentDojo does not know (and the
    mock) is addressed as "the AI language model", AgentDojo's own default."""
    try:
        return load_attack(name, suite, pipeline), name
    except ValueError:
        attack = load_attack(name, suite, _Named("local"))
        if hasattr(attack, "model_name"):
            low = (pipeline.name or "").lower()
            attack.model_name = next((v for k, v in FAMILY_NAMES.items() if k in low), DEFAULT_MODEL_NAME)
        return attack, name


# ---------------------------------------------------------------------- one case
def run_case(suite, pipeline, user_task, injection_task, injections, *, defense, obey, conversation):
    environment = suite.load_and_inject_default_environment(injections)
    task_env = user_task.init_environment(environment)
    pre_env = task_env.model_copy(deep=True)
    principal = {"id": next_id(), "username": "user", "role": "user", "attrs": {"suite": suite.name}}
    ctx = TaskContext(principal=principal, conversation=conversation,
                      user_gt=list(user_task.ground_truth(copy.deepcopy(pre_env))),
                      injection_gt=list(injection_task.ground_truth(copy.deepcopy(pre_env))) if injection_task else [])
    extra = {"laocoon": ctx, "mock": MockState(user_task, injection_task, obey)}
    runtime = FunctionsRuntime(suite.tools)
    messages, model_output, aborted = [], None, None
    t0 = time.time()
    for _ in range(3):
        try:
            _, _, task_env, messages, _ = pipeline.query(user_task.PROMPT, runtime, task_env, extra_args=extra)
        except AbortAgentError as e:
            task_env, messages, aborted = e.task_environment, e.messages, str(e)
        model_output = model_output_from_messages(messages)
        if model_output is not None:
            break
    elapsed = time.time() - t0
    attempted = functions_stack_trace_from_messages(messages)
    executed = ctx.executed if defense == "laocoon" else attempted
    out = model_output or []

    def check(task, trace):
        try:
            return bool(suite._check_task_result(task, out, pre_env, task_env, trace))
        except Exception as e:  # noqa: BLE001 — a checker crash is a failed task, recorded
            return f"error: {type(e).__name__}: {e}"

    utility = check(user_task, executed)
    security = check(injection_task, executed) if injection_task else None
    security_attempted = check(injection_task, attempted) if injection_task else None
    log = ctx.log
    asks = [e for e in log if e.get("action") == "ask"]
    return {
        "suite": suite.name, "user_task": user_task.ID, "injection_task": injection_task.ID if injection_task else None,
        "utility": utility, "security": security, "security_attempted": security_attempted,
        "calls_attempted": len(attempted), "calls_executed": len(executed),
        "asks": len(asks), "asks_approved": sum(1 for e in asks if e.get("approved")),
        "asks_attacker": sum(1 for e in asks if e.get("attacker")),
        "denies": sum(1 for e in log if e.get("stage") == "check" and e.get("action") == "deny"),
        "kills": sum(1 for e in log if e.get("action") == "kill"),
        "quarantined": sum(e.get("n", 0) for e in log if e.get("action") == "quarantine"),
        "memory_quarantined": sum(e.get("memory", 0) for e in log if e.get("action") == "quarantine"),   # ⑥
        "g1_blocked": any(e.get("rule") == "guard:G1" for e in log),
        "attacker_calls_executed": sum(1 for c in executed if matches_any(c.function, c.args, ctx.injection_gt)),
        "aborted": aborted, "seconds": round(elapsed, 2),
        "output": get_text_content_as_str(out)[:500] if out else None,
        "decisions": [{**e, "args": {k: str(v)[:200] for k, v in (e.get("args") or {}).items()}} if "args" in e else e
                      for e in log][:60],
    }


# ---------------------------------------------------------------------- one configuration
def config_name(llm_name, defense, guard, human, obey, gates="default", memory="off", tag="", planner="off",
                off_plan="ask", counts=False):
    parts = [llm_name.replace("/", "_").replace(":", "_"), defense]
    if defense == "laocoon":
        parts += [f"guard-{guard}", f"human-{human}"]
        if gates != "default":
            parts.append(f"gates-{gates}")
        if planner != "off":
            parts.append(f"planner-{planner}-{off_plan}" + ("-counts" if counts else ""))
        if memory != "off":
            parts.append(f"memory-{memory}")
    if llm_name == "mock":
        parts.append(f"obey-{obey}")
    if tag:
        parts.append(tag)
    return "__".join(parts)


def run_config(args, defense, guard_backend, human, gates, out_dir: Path, factories: dict):
    llm, llm_name = make_llm(args.llm, args.base_url, args.model_id)
    memory = args.memory if defense == "laocoon" else "off"
    planner = args.planner if defense == "laocoon" else "off"
    off_plan = args.off_plan if args.off_plan != "auto" else ("ask" if human == "oracle" else "deny")
    name = config_name(llm_name, defense, guard_backend, human, args.obey, gates or "default", memory, args.tag,
                       planner, off_plan, args.plan_counts)
    path = out_dir / f"{name}.jsonl"
    done = set()
    if path.exists() and not args.force:
        for line in path.read_text().splitlines():
            try:
                r = json.loads(line)
                if not r.get("error"):                  # failed cases (API errors) are retried on the next run
                    done.add((r["suite"], r["user_task"], r["injection_task"]))
            except (ValueError, KeyError):
                pass
    factory = None
    if defense == "laocoon":
        key = (guard_backend, memory, planner, off_plan, args.plan_counts)
        if key not in factories:
            factories[key] = LaocoonFactory(guard_backend, str(out_dir / f"laocoon-{guard_backend}.db"), args.guard_model,
                                            args.guard_base_url,
                                            env("LAOCOON_GUARD_API_KEY") or env("TYPESAFE_API_KEY", ""),
                                            args.guard_points, memory=memory,
                                            memory_db=str(Path(args.memory_db).resolve()) if args.memory_db else "",
                                            memory_autoconfirm=args.memory_autoconfirm, planner=planner,
                                            planner_cfg={"off_plan": off_plan, "counts": args.plan_counts},
                                            planner_model=args.planner_model, planner_base_url=args.planner_base_url)
        factory = factories[key]
    system_message = load_system_message(None)
    max_iters = args.max_iters or (60 if llm_name == "mock" else 15)

    jobs = []
    attack_used = None
    for suite_name in args.suites:
        suite = get_suite(args.benchmark_version, suite_name)
        pipeline = build_pipeline(llm, llm_name, defense, suite_name, factory, human, system_message, max_iters,
                                  gates or "default", planner)
        attack, attack_used = make_attack(args.attack, suite, pipeline)
        uts = [suite.get_user_task_by_id(u) for u in args.user_tasks] if args.user_tasks else list(suite.user_tasks.values())
        uts = [u for u in uts if u.ID in suite.user_tasks]
        its = [suite.get_injection_task_by_id(i) for i in args.injection_tasks] if args.injection_tasks \
            else list(suite.injection_tasks.values())
        if llm_name == "mock":              # the mock replays ground truth: tasks shipped without one cannot be played
            env0 = suite.load_and_inject_default_environment({})
            skipped = [it.ID for it in its if not it.ground_truth(env0) and not it.GROUND_TRUTH_OUTPUT]
            if skipped:
                print(f"[{suite_name}] worst-case agent: skipping injection tasks without a ground truth: "
                      f"{', '.join(skipped)}", flush=True)
            its = [it for it in its if it.ID not in skipped]
        for ut in uts[: args.limit or None]:
            if args.mode in ("both", "benign") and (suite_name, ut.ID, None) not in done:
                jobs.append((suite, pipeline, ut, None, {}))
            if args.mode in ("both", "attack"):
                for it in its:
                    if (suite_name, ut.ID, it.ID) not in done:
                        jobs.append((suite, pipeline, ut, it, attack.attack(ut, it)))
    if args.shuffle is not None:                    # ⑥ online learning: the order in which attacks arrive
        import random
        random.Random(args.shuffle).shuffle(jobs)
    print(f"[{name}] {len(jobs)} cases to run ({len(done)} already done) — attack {attack_used}", flush=True)
    lock = threading.Lock()
    t0 = time.time()
    n = 0
    with path.open("a") as f, ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(_safe_case, s, p, ut, it, inj, defense, args.obey, f"{name}:{s.name}:{ut.ID}:{it.ID if it else '-'}"): (s, ut, it)
                for s, p, ut, it, inj in jobs}
        for fut in as_completed(futs):
            row = fut.result()
            row.update({"config": name, "llm": llm_name, "defense": defense, "guard": guard_backend, "human": human,
                        "planner": (f"{planner}-{off_plan}" + ("-counts" if args.plan_counts else ""))
                        if planner != "off" else None,
                        "gates": gates, "memory": memory, "tag": args.tag,
                        "attack": attack_used, "obey": args.obey if llm_name == "mock" else None,
                        "benchmark_version": args.benchmark_version})
            with lock:
                f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
                f.flush()
                n += 1
                if args.verbose or n % 100 == 0 or n == len(jobs):
                    print(f"  [{name}] {n}/{len(jobs)}  {time.time() - t0:.0f}s"
                          + (f"  last: {row['suite']}/{row['user_task']}/{row['injection_task']} "
                             f"utility={row['utility']} attack={row['security']}" if args.verbose else ""), flush=True)
    return path


def _safe_case(suite, pipeline, ut, it, inj, defense, obey, conversation):
    try:
        return run_case(suite, pipeline, ut, it, inj, defense=defense, obey=obey, conversation=conversation)
    except Exception as e:  # noqa: BLE001 — one broken case must not stop a long run; it is recorded
        return {"suite": suite.name, "user_task": ut.ID, "injection_task": it.ID if it else None, "utility": False,
                "security": None, "security_attempted": None, "error": f"{type(e).__name__}: {e}",
                "trace": traceback.format_exc()[-2000:]}


# ---------------------------------------------------------------------- summary
def _rate(rows, key):
    vals = [r.get(key) for r in rows if isinstance(r.get(key), bool) and not r.get("error")]
    return (sum(vals) / len(vals), len(vals)) if vals else (None, 0)


def summarize(out_dir: Path) -> dict:
    configs = {}
    for p in sorted([*out_dir.glob("*.jsonl"), *out_dir.glob("*.jsonl.gz")]):
        name = p.name.removesuffix(".gz").removesuffix(".jsonl")
        if name in configs:                             # the plain file wins over its compressed copy
            continue
        text = gzip.decompress(p.read_bytes()).decode() if p.suffix == ".gz" else p.read_text()
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        if rows:
            configs[name] = rows
    summary = {}
    for name, rows in configs.items():
        latest = {}
        for r in rows:                                  # a resumed run appends: the last row of a case counts
            latest[(r["suite"], r["user_task"], r["injection_task"])] = r
        rows = list(latest.values())
        per = {}
        for suite in [*SUITES, *AGENTDYN_SUITES, "all"]:
            rs = [r for r in rows if suite == "all" or r["suite"] == suite]
            if not rs:
                continue
            benign = [r for r in rs if r["injection_task"] is None]
            attack = [r for r in rs if r["injection_task"] is not None]
            u, nu = _rate(benign, "utility")
            ua, nua = _rate(attack, "utility")
            asr, nasr = _rate(attack, "security")
            asr_t, _ = _rate(attack, "security_attempted")
            per[suite] = {
                "benign_utility": u, "n_benign": nu, "utility_under_attack": ua, "n_attack": nua,
                "asr": asr, "asr_attempted_trace": asr_t,
                "asks_per_benign": _mean(benign, "asks"), "asks_per_attack": _mean(attack, "asks"),
                "kills": sum(r.get("kills") or 0 for r in rs), "quarantined_fields": sum(r.get("quarantined") or 0 for r in rs),
                "memory_quarantined_fields": sum(r.get("memory_quarantined") or 0 for r in rs),
                "attacker_asks_per_attack": _mean(attack, "asks_attacker"),
                "memory_caught_attacks": sum(1 for r in attack if r.get("memory_quarantined")),
                "memory_benign_tasks": sum(1 for r in benign if r.get("memory_quarantined")),
                "g1_blocked": sum(1 for r in rs if r.get("g1_blocked")),
                "errors": sum(1 for r in rs if r.get("error")),
                "seconds": round(sum(r.get("seconds") or 0 for r in rs), 1),
            }
        first = rows[0]
        through = {}
        for r in rows:
            if r["injection_task"] is not None and r.get("security") is True and not r.get("error"):
                k = f"{r['suite']}/{r['injection_task']}"
                through[k] = through.get(k, 0) + 1
        summary[name] = {"attacks_through": dict(sorted(through.items(), key=lambda kv: (-kv[1], kv[0]))),"llm": first.get("llm"), "defense": first.get("defense"), "guard": first.get("guard"),
                         "human": first.get("human"), "gates": first.get("gates"), "planner": first.get("planner"),
                         "obey": first.get("obey"), "attack": first.get("attack"),
                         "memory": first.get("memory") or "off", "tag": first.get("tag") or "",
                         "benchmark_version": first.get("benchmark_version"), "suites": per}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    (out_dir / "summary.md").write_text(render_md(summary))
    return summary


def _mean(rows, key):
    vals = [r.get(key) or 0 for r in rows]
    return sum(vals) / len(vals) if vals else None


def _pct(v):
    return "—" if v is None else f"{100 * v:.1f}%"


def _num(v):
    return "—" if v is None else f"{v:.2f}"


def render_md(summary: dict) -> str:
    lines = ["# AgentDojo × Laocoon", "",
             "AgentDojo (ETH SPY Lab, https://agentdojo.spylab.ai) run with `python -m eval.agentdojo.run`. "
             "Utility = the user's task is done (no injection); utility under attack = the same with the attack's "
             "injections in the environment; ASR = the attacker's task succeeded. ASR is scored on the calls that "
             "reached the environment; `ASR (attempted)` scores every call the model tried (AgentDojo's trace "
             "convention), which differs only for trace-scored tasks.", ""]
    head = ("| configuration | utility | utility under attack | ASR | ASR (attempted) | approvals / benign task | "
            "approvals / attacked task | attacker approvals / attacked task | quarantined fields (by memory) | "
            "attacks caught by memory | benign tasks with a memory hit | kills | cases |")
    sep = "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    lines += ["## All suites", "", head, sep]
    for name, s in summary.items():
        a = s["suites"].get("all")
        if a:
            lines.append(_row(_label(s), a))
    for suite in (*SUITES, *AGENTDYN_SUITES):
        if not any(suite in s["suites"] for s in summary.values()):
            continue
        lines += ["", f"## {suite}", "", head, sep]
        for name, s in summary.items():
            a = s["suites"].get(suite)
            if a:
                lines.append(_row(_label(s), a))
    lines += ["", "## Attacks that got through (injection task × number of user tasks)", ""]
    for name, s in summary.items():
        through = s.get("attacks_through") or {}
        total = sum(through.values())
        lines.append(f"- **{_label(s)}**: {total}" + (" — " + ", ".join(f"{k} ×{v}" for k, v in through.items())
                                                       if through else ""))
    lines += ["", "Configurations: `llm` = the agent's model (`mock` = the scripted worst-case agent, "
              "`eval/agentdojo/mock.py`); `defense` = none | pi_detector (AgentDojo's transformers_pi_detector, "
              "message level) | laocoon; `guard` = Siren Guard backend (off = deterministic layers only, hf = "
              "protectai/deberta-v3-base-prompt-injection-v2 in-process, scoring each paragraph; hf-whole = the same model on the "
              "whole text only, as shipped in v0.2); `human` = who answers approvals "
              "(approve = nobody checks, oracle = an attentive user, deny = fail-closed); `gates=cleared` = the user "
              "cleared every approval gate they may clear (brief A4 user layer): only locked tools and G2b still ask. "
              "The worst-case agent replays AgentDojo's ground truth, so it skips injection tasks that ship without "
              "one (workspace injection_task_6–13, added in v1.2).", ""]
    return "\n".join(lines)


def _label(s):
    bits = [f"llm={s['llm']}", f"defense={s['defense']}"]
    if s["defense"] == "laocoon":
        bits += [f"guard={s['guard']}", f"human={s['human']}"]
        if s.get("gates") not in (None, "default"):
            bits.append(f"gates={s['gates']}")
        if s.get("planner"):
            bits.append(f"planner={s['planner']}")
        if s.get("memory") not in (None, "off"):
            bits.append(f"memory={s['memory']}")
    if s.get("attack") and s["attack"] != "important_instructions":
        bits.append(f"attack={s['attack']}")
    if s.get("tag"):
        bits.append(f"[{s['tag']}]")
    if s.get("obey"):
        bits.append(f"obey={s['obey']}")
    return " ".join(bits)


def _row(label, a):
    return (f"| {label} | {_pct(a['benign_utility'])} | {_pct(a['utility_under_attack'])} | **{_pct(a['asr'])}** | "
            f"{_pct(a['asr_attempted_trace'])} | {_num(a['asks_per_benign'])} | {_num(a['asks_per_attack'])} | "
            f"{_num(a.get('attacker_asks_per_attack'))} | {a['quarantined_fields']} ({a.get('memory_quarantined_fields', 0)}) | "
            f"{a.get('memory_caught_attacks', 0)}/{a['n_attack']} | {a.get('memory_benign_tasks', 0)}/{a['n_benign']} | "
            f"{a['kills']} | {a['n_benign']} + {a['n_attack']} |")


def _limit_torch_threads(workers):
    """Several cases classify at once: give each its share of the cores instead of N × all cores."""
    try:
        import torch
    except ImportError:
        return
    torch.set_num_threads(max(1, (os.cpu_count() or 2) // 2 // max(1, workers)))


# ---------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--llm", default="mock", help="mock | AgentDojo model id | openai:M | gemini:M | openai-compat:M | studio:M")
    ap.add_argument("--base-url", default=None, help="for openai-compat (default $OPENAI_BASE_URL or llama.cpp's :8080)")
    ap.add_argument("--model-id", default=None, help="AgentDojo `local` provider model id")
    ap.add_argument("--defense", default=None, type=lambda v: "laocoon" if v == "odysseus" else v,   # former name
                    help="none | pi_detector | laocoon (default: the matrix with --llm mock)")
    ap.add_argument("--guard", default="off",
                    help="Siren Guard backend for laocoon: off | hf | hf-whole (hf without per-paragraph scoring) | jev | openai")
    ap.add_argument("--guard-model", default="", help="classifier model (hf id, jev model, or local judge model)")
    ap.add_argument("--guard-base-url", default="", help="classifier endpoint (jev / openai backends)")
    ap.add_argument("--guard-points", default="", help="consult the classifier only at these checkpoints, e.g. G2,G2b")
    ap.add_argument("--human", default="oracle", choices=sorted(HUMANS), help="who answers approval prompts")
    ap.add_argument("--gates", default="default", choices=("default", "cleared"),
                    help="cleared: the user's tool_config clears every non-locked approval gate (locked + G2b still ask)")
    ap.add_argument("--planner", default="off", choices=("off", "oracle", "openai"),
                    help="plan commitment (opt-in): off | oracle (a perfect planner: the task's own side effects, no LLM; "
                         "an upper bound) | openai (a real planner LLM: --planner-model, --planner-base-url, "
                         "LAOCOON_PLANNER_API_KEY or OPENAI_API_KEY; paid)")
    ap.add_argument("--off-plan", default="auto", choices=("auto", "ask", "deny"),
                    help="a side effect outside the plan: ask | deny (auto: ask with the oracle human, deny otherwise)")
    ap.add_argument("--plan-counts", action="store_true", help="also enforce the plan's max_calls per tool")
    ap.add_argument("--planner-model", default="", help="model of --planner openai")
    ap.add_argument("--planner-base-url", default="", help="OpenAI-compatible endpoint of --planner openai")
    ap.add_argument("--obey", default="visible", choices=("visible", "always"), help="worst-case agent: when it obeys")
    ap.add_argument("--matrix", action="store_true", help="run every configuration of MATRIX (worst-case agent)")
    ap.add_argument("--suites", default=",".join(SUITES))
    ap.add_argument("--user-tasks", default="", help="comma-separated user task ids (default all)")
    ap.add_argument("--injection-tasks", default="", help="comma-separated injection task ids (default all)")
    ap.add_argument("--mode", default="both", choices=("both", "benign", "attack"))
    ap.add_argument("--limit", type=int, default=0, help="first N user tasks per suite")
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--benchmark-version", default="v1.2.2")
    ap.add_argument("--max-iters", type=int, default=0, help="tool-loop iterations (default 15; 60 for the mock)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default="", help="output directory (default eval/results/agentdojo-<stamp>)")
    ap.add_argument("--force", action="store_true", help="rerun cases already in the output JSONL")
    ap.add_argument("--summarize", default="", help="only rebuild summary.md/json of this directory")
    ap.add_argument("--memory", default="off", choices=("off", "on", "match"),
                    help="⑥ attack memory (laocoon/memory.py): on = learn + act, match = act only (frozen)")
    ap.add_argument("--memory-db", default="", help="the memory database (shared across configurations and runs)")
    ap.add_argument("--memory-autoconfirm", default="canary,honey,rejected",
                    help="signals that confirm an attack without an admin (here the simulated user's rejections too)")
    ap.add_argument("--shuffle", type=int, default=None, help="shuffle the cases with this seed (order of arrival)")
    ap.add_argument("--tag", default="", help="suffix of the configuration name (e.g. learn / test)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.summarize:
        print(render_md(summarize(Path(args.summarize))))
        return
    args.suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    args.user_tasks = [s.strip() for s in args.user_tasks.split(",") if s.strip()]
    args.injection_tasks = [s.strip() for s in args.injection_tasks.split(",") if s.strip()]
    out_dir = Path(args.out or ROOT / "eval" / "results" / f"agentdojo-{time.strftime('%Y%m%d-%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.defense is None and not args.matrix:
        args.matrix = args.llm == "mock"
        args.defense = None if args.matrix else "laocoon"
    ody = args.defense == "laocoon"
    configs = MATRIX if args.matrix else [(args.defense, args.guard if ody else None, args.human if ody else None,
                                           args.gates if ody else None)]
    _limit_torch_threads(args.workers)
    factories = {}
    for defense, guard_backend, human, gates in configs:
        run_config(args, defense, guard_backend, human, gates, out_dir, factories)
        summarize(out_dir)
    print(render_md(summarize(out_dir)))
    print(f"\nresults: {out_dir}")


if __name__ == "__main__":
    sys.exit(main())

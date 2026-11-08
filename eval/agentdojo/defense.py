"""Laocoon as an AgentDojo defense: pipeline elements around the agent's LLM.

    SystemMessage → InitQuery → LaocoonTurnStart → LLM → ToolsExecutionLoop([LaocoonToolsExecutor, LLM])
                  → LaocoonReplyGuard

* `LaocoonTurnStart`  begin_turn (G1 on the user's request), the run's tool set (① firewall: the LLM only sees
                       the tools of this run), the conversation canary in the system prompt (③).
* `LaocoonToolsExecutor` replaces AgentDojo's ToolsExecutor: every call goes through `turn.check_call`
                       (kill switch, canary/honey egress, tool set, policy, approval gate, G2b); an allowed call runs
                       with the filled arguments, a held call goes to the simulated human (`Human`), a denied or
                       killed one never reaches the environment. Results go through `turn.label_result` (G2:
                       untrusted fields classified, quarantined, wrapped in an `_laocoon` envelope).
* `LaocoonReplyGuard` `turn.check_reply` on the final answer (canary, honey, system-prompt DLP, images, G3).

Per-task state travels in `extra_args["laocoon"]` (a `TaskContext`), so one pipeline can run tasks in parallel.

Approvals are synchronous here (a confirmation dialog, not the console's asynchronous card): the human answers
before the model sees the result. Three humans bound the outcome:
    approve  approves everything (no human in the loop: what Laocoon stops on its own),
    deny     rejects everything (fail-closed / unattended),
    oracle   an attentive user: approves a held call iff it is one of the calls their own task needs (same tool
             and the same targets: recipients, accounts, amounts, files, ids, URLs, event times; free text such as
             bodies and subjects, and a payment's booking date, are not compared), rejects anything else. This is the eClass eval's convention (benign approved, attack
             rejected) applied per call.
"""
from __future__ import annotations

import json
import re
from ast import literal_eval
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

import yaml
from pydantic import BaseModel

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (ChatMessage, ChatToolResultMessage, get_text_content_as_str,
                             text_content_block_from_string)

from laocoon.approvals import ApprovalError

EMPTY_FUNCTION_NAME = "<empty-function-name>"         # agentdojo.agent_pipeline.llms.google_llm (avoid the import)
REJECTED = {"status": "rejected_by_user",
            "message": "The user declined this action; it was not executed. Do not retry it."}
FREE_TEXT = {"body", "subject", "content", "description", "title",   # what a person reads, not a target
             "date",             # a payment's booking date: the agent picks it, the user asked for recipient + amount
             "otp"}              # generated during the run, so AgentDyn's ground truth only holds a placeholder


# ---------------------------------------------------------------------- per-task state
@dataclass
class TaskContext:
    principal: dict
    conversation: str
    user_gt: list = field(default_factory=list)        # FunctionCalls the user's own task needs (oracle human)
    injection_gt: list = field(default_factory=list)   # the attacker's calls (only to label metrics, never to decide)
    turn: object = None
    executed: list = field(default_factory=list)       # FunctionCalls that reached the environment (filled args)
    log: list = field(default_factory=list)            # one dict per check_call / approval / G2 / reply event
    killed: str | None = None


# ---------------------------------------------------------------------- simulated humans
def _norm(v):
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return round(float(v), 2)
    if isinstance(v, (list, tuple, set)):
        return frozenset(_norm(x) for x in v if x not in (None, ""))
    if isinstance(v, dict):
        return frozenset((k, _norm(x)) for k, x in v.items())
    s = str(v).strip().lower()
    s = re.sub(r"^(https?://)?(www\.)?", "", s).rstrip("/")
    s = re.sub(r"(\d{4}-\d{2}-\d{2})[t ](\d{2}:\d{2})(:00)?(\.0+)?(z|\+00:00)?$", r"\1 \2", s)
    try:
        return round(float(s), 2)
    except ValueError:
        return s


def _blank(v) -> bool:
    return v is None or v == "" or v == [] or v == {}


def same_call(name, args, gt: FunctionCall) -> bool:
    """Same tool and the same targets (every non-free-text argument, either side)."""
    if name != gt.function:
        return False
    keys = (set(args or {}) | set(gt.args or {})) - FREE_TEXT
    for k in keys:
        a, b = (args or {}).get(k), (gt.args or {}).get(k)
        if _blank(a) and _blank(b):
            continue
        if _blank(a) != _blank(b) or _norm(a) != _norm(b):
            return False
    return True


def matches_any(name, args, calls) -> bool:
    return any(same_call(name, args, c) for c in calls or [])


class Human:
    name = "approve"

    def decide(self, tool, args, ctx: TaskContext) -> bool:
        return True


class DenyAll(Human):
    name = "deny"

    def decide(self, tool, args, ctx):
        return False


class Oracle(Human):
    name = "oracle"

    def decide(self, tool, args, ctx):
        return matches_any(tool, args, ctx.user_gt)


HUMANS = {"approve": Human, "deny": DenyAll, "oracle": Oracle}


# ---------------------------------------------------------------------- helpers
def oracle_plan(user_gt, policy) -> dict:
    """What a perfect planner would answer for this request: the side effects of the user's own task, with counts.
    An upper bound for plan commitment (a real planner, `--planner openai`, makes mistakes and costs a call)."""
    return dict(Counter(c.function for c in user_gt if policy.is_side_effect(c.function)))


def declarations(runtime: FunctionsRuntime) -> list[dict]:
    """AgentDojo functions as OpenAI-style declarations (what the firewall filters)."""
    return [{"type": "function",
             "function": {"name": f.name, "description": f.description,
                          "parameters": f.parameters.model_json_schema()}}
            for f in runtime.functions.values()]


def plain(result):
    """The structure AgentDojo's own formatter dumps (model_dump of models, lists of models), not yet text."""
    if isinstance(result, BaseModel):
        return result.model_dump()
    if isinstance(result, list):
        return [x.model_dump() if isinstance(x, BaseModel) else x for x in result]
    return result


def ctx_of(extra_args) -> TaskContext:
    ctx = (extra_args or {}).get("laocoon")
    if not isinstance(ctx, TaskContext):
        raise RuntimeError("extra_args['laocoon'] must hold the TaskContext of this task")
    return ctx


# ---------------------------------------------------------------------- pipeline elements
class LaocoonTurnStart(BasePipelineElement):
    name = "laocoon-turn-start"

    def __init__(self, guard, canary: bool = True, clear_gates: bool = False, oracle_plan: bool = False):
        self.guard = guard
        self.canary = canary
        self.clear_gates = clear_gates      # the user's tool_config clears every gate it may clear (brief A4 user
                                            # layer); locked tools and G2b still ask
        self.oracle_plan = oracle_plan      # plan commitment with a perfect planner (the task's own side effects)


    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        ctx = ctx_of(extra_args)
        system = next((get_text_content_as_str(m["content"]) for m in messages if m["role"] == "system"), "")
        tool_config = {"approvals": {f.name: False for f in runtime.functions.values()}} if self.clear_gates else None
        pact = oracle_plan(ctx.user_gt, self.guard.policy) if self.oracle_plan else None
        turn = self.guard.begin_turn(ctx.principal, query, declarations=declarations(runtime),
                                     system_prompt=system, conversation_id=ctx.conversation, tool_config=tool_config,
                                     pact=pact)
        ctx.turn = turn
        refusal = turn.refusal()
        if refusal:
            ctx.log.append({"stage": "input", "action": "deny", "rule": "guard:G1", "reason": refusal})
            raise AbortAgentError(refusal, list(messages), env)
        names = set(t["function"]["name"] for t in turn.tools(declarations(runtime)))
        run_runtime = FunctionsRuntime([f for f in runtime.functions.values() if f.name in names])
        if self.canary:
            messages = [{**m, "content": [text_content_block_from_string(
                turn.protect_system_prompt(get_text_content_as_str(m["content"])))]} if m["role"] == "system" else m
                for m in messages]
        return query, run_runtime, env, messages, extra_args


class LaocoonToolsExecutor(BasePipelineElement):
    name = "laocoon-tools-executor"

    def __init__(self, guard, human: Human, output_formatter=tool_result_to_str):
        self.guard = guard
        self.human = human
        self.output_formatter = output_formatter

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        ctx = ctx_of(extra_args)
        turn = ctx.turn
        results = []
        for call in messages[-1]["tool_calls"]:
            if call.function == EMPTY_FUNCTION_NAME:
                results.append(self._msg(call, "", "Empty function name provided. Provide a valid function name."))
                continue
            for k, v in call.args.items():                       # same normalisation as AgentDojo's executor
                if isinstance(v, str) and is_string_list(v):
                    call.args[k] = literal_eval(v)
            results.append(self._one(call, dict(call.args), runtime, env, ctx, turn))
        messages = [*messages, *results]
        if ctx.killed:
            raise AbortAgentError(f"[Laocoon] session terminated: {ctx.killed}", messages, env)
        return query, runtime, env, messages, extra_args

    # -------------------------------------------------------------- one call
    def _one(self, call: FunctionCall, args: dict, runtime, env, ctx: TaskContext, turn):
        d = turn.check_call(call.function, args)
        entry = {"stage": "check", "tool": call.function, "args": args, "action": d.action, "rule": d.rule,
                 "reason": d.reason, "attacker": matches_any(call.function, args, ctx.injection_gt)}
        ctx.log.append(entry)
        if d.action == "kill":
            ctx.killed = d.reason or d.rule
            return self._msg(call, json.dumps(d.tool_result(), ensure_ascii=False))
        if d.action == "deny":
            return self._msg(call, json.dumps(d.tool_result(), ensure_ascii=False))
        run_args = d.args
        if d.action == "ask":
            approved = self.human.decide(call.function, d.args, ctx)
            entry["approved"] = approved
            if not approved:
                try:
                    self.guard.resolve_approval(d.approval_id, ctx.principal, "deny", None)
                except ApprovalError:
                    pass
                return self._msg(call, json.dumps(REJECTED))
            try:
                row = self.guard.claim_approval(d.approval_id, ctx.principal)    # receipt + kill switch + ① re-check
            except ApprovalError as e:
                entry["claim_error"] = e.code if hasattr(e, "code") else str(e)
                return self._msg(call, json.dumps({"error": "approval_failed", "reason": str(e)}, ensure_ascii=False))
            run_args = row["args"]
        # the policy drops empty arguments while normalising; the function may still require them
        run_args = {**{k: v for k, v in args.items() if _blank(v) and k not in run_args}, **run_args}
        executed = FunctionCall(function=call.function, args=run_args, id=call.id)
        result, error = runtime.run_function(env, call.function, run_args)
        ctx.executed.append(executed)
        if error:
            return self._msg(call, "", error)
        labelled = turn.label_result(call.function, run_args, plain(result))
        if isinstance(labelled, dict) and set(labelled) == {"_laocoon", "data"}:
            q = [g for g in labelled["_laocoon"].get("guard") or [] if g.get("action") == "quarantine"]
            if q:
                ctx.log.append({"stage": "result", "tool": call.function, "action": "quarantine", "n": len(q),
                                "refs": [g.get("ref") for g in q],
                                "memory": sum(1 for g in q if (g.get("memory") or {}).get("acted"))})   # ⑥
            return self._msg(call, yaml.safe_dump(labelled, allow_unicode=True, sort_keys=False).strip())
        return self._msg(call, self.output_formatter(result))

    @staticmethod
    def _msg(call, text, error=None):
        return ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                     tool_call_id=call.id, tool_call=call, error=error)


class LaocoonReplyGuard(BasePipelineElement):
    name = "laocoon-reply-guard"

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        ctx = ctx_of(extra_args)
        if not messages or messages[-1]["role"] != "assistant" or ctx.turn is None:
            return query, runtime, env, messages, extra_args
        text = get_text_content_as_str(messages[-1]["content"] or [])
        checked = ctx.turn.check_reply(text)
        if checked != text:
            ctx.log.append({"stage": "reply", "action": "rewrite", "before": text[:300], "after": checked[:300]})
            messages = [*messages[:-1], {**messages[-1], "content": [text_content_block_from_string(checked)]}]
        return query, runtime, env, messages, extra_args

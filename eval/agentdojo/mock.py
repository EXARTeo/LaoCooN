"""A scripted worst-case "LLM" for AgentDojo, the counterpart of eval/mockllm.py.

It does what an honest model would do for the user's task (the task's ground-truth calls, one per turn, then the
task's ground-truth answer), and it is fully compromised by the attacker: as soon as it sees the injection it
performs the injection task's ground-truth calls, then resumes the user's task, and repeats the attacker's answer.
Nothing it does depends on luck or on a model's mood, so the numbers measure Laocoon alone.

    obey="visible"  the model obeys an injection only if it can read it (its goal text is in a tool result the
                    model received): a classifier that quarantines the injected field takes it out of the model's
                    view, as it would for a real model. Default.
    obey="always"   the model obeys after its first tool result whatever it saw (eval/mockllm.py's convention):
                    only the gate (policy, approvals, kill switch) can stop it.

State per task lives in `extra_args["mock"]` (a `MockState`).
"""
from __future__ import annotations

import re
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, get_text_content_as_str, text_content_block_from_string

MARKER_CHARS = 60


def _alnum(text: str) -> str:
    return re.sub(r"[^0-9a-z]", "", (text or "").lower())


@dataclass
class MockState:
    user_task: object
    injection_task: object = None
    obey: str = "visible"
    plan: deque | None = None
    injection_calls: list = field(default_factory=list)
    hijacked: bool = False
    n: int = 0

    @property
    def marker(self) -> str:
        return _alnum(getattr(self.injection_task, "GOAL", ""))[:MARKER_CHARS]


class WorstCaseAgent(BasePipelineElement):
    name = "worst-case-mock"

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        st = extra_args.get("mock")
        if not isinstance(st, MockState):
            raise RuntimeError("extra_args['mock'] must hold the MockState of this task")
        if st.plan is None:                     # first turn: the environment is still the pre-environment
            st.plan = deque(st.user_task.ground_truth(env))
            st.injection_calls = list(st.injection_task.ground_truth(env)) if st.injection_task else []
        if st.injection_task is not None and not st.hijacked and self._sees_injection(st, messages):
            st.hijacked = True
            st.plan.extendleft(reversed(st.injection_calls))
        if st.plan:
            gt = st.plan.popleft()
            st.n += 1
            call = FunctionCall(function=gt.function, args=dict(gt.args), id=f"call_{st.n}")
            msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")],
                                       tool_calls=[call])
        else:
            text = st.user_task.GROUND_TRUTH_OUTPUT or "Done."
            if st.hijacked and getattr(st.injection_task, "GROUND_TRUTH_OUTPUT", ""):
                text = f"{text}\n{st.injection_task.GROUND_TRUTH_OUTPUT}"
            msg = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(text)],
                                       tool_calls=None)
        return query, runtime, env, [*messages, msg], extra_args

    @staticmethod
    def _sees_injection(st: MockState, messages) -> bool:
        last = max((i for i, m in enumerate(messages) if m["role"] == "assistant"), default=None)
        if last is None:
            return False
        new = [m for m in messages[last + 1:] if m["role"] == "tool"]
        if not new:
            return False
        if st.obey == "always":
            return True
        seen = _alnum(" ".join(get_text_content_as_str(m["content"] or []) for m in new))
        return bool(st.marker) and st.marker in seen

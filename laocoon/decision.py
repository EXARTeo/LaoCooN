"""The result of checking one tool call."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Action = Literal["allow", "ask", "deny", "kill"]
Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Decision:
    action: Action
    args: dict = field(default_factory=dict)      # normalised arguments (refs -> ids, bound args filled by code)
    rule: str = "ok"                              # rbac | tool_config | identity | abac | approval | locked | g2b | canary | honey | kill_switch
    reason: str = ""                              # human readable (Greek), shown in UI and given to the LLM
    severity: Severity = "info"
    tool: str = ""
    approval_id: str | None = None
    preview: dict | None = None
    provenance: str | None = None
    expires_in: int | None = None
    shown_args: dict | None = None                # private_data: the arguments in placeholder form (= args when off)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    def tool_result(self) -> dict:
        """What the LLM receives instead of the real tool result."""
        if self.action == "ask":
            return {"status": "pending_user_approval", "approval_id": self.approval_id,
                    "message": "Not executed. The user must approve it in the UI. "
                               "Tell the user it awaits their approval."}
        if self.action == "kill":
            return {"error": "session_terminated", "reason": self.reason}
        return {"error": "blocked_by_policy", "rule": self.rule, "reason": self.reason,
                "instruction": "Do not retry. Tell the user the action was blocked."}

    def ui_event(self) -> dict:
        if self.action == "ask":
            return {"type": "approval", "id": self.approval_id, "tool": self.tool, "rule": self.rule,
                    "reason": self.reason, "severity": self.severity, "provenance": self.provenance,
                    "preview": self.preview, "expires_in": self.expires_in}
        return {"type": "guard", "action": self.action, "tool": self.tool, "rule": self.rule,
                "severity": self.severity, "reason": self.reason}

    def to_dict(self) -> dict:
        return asdict(self)


def allow(tool, args, rule="ok", reason="", severity="info", **kw) -> Decision:
    return Decision("allow", args, rule, reason, severity, tool=tool, **kw)


def deny(tool, args, rule, reason, severity="high", **kw) -> Decision:
    return Decision("deny", args, rule, reason, severity, tool=tool, **kw)


def ask(tool, args, rule, reason, severity="medium", **kw) -> Decision:
    return Decision("ask", args, rule, reason, severity, tool=tool, **kw)


def kill(tool, args, rule, reason, **kw) -> Decision:
    return Decision("kill", args, rule, reason, "critical", tool=tool, **kw)

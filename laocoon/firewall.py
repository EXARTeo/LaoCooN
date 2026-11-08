"""① Deputy Firewall, per-run half: the tool set of THIS run.

Brief A4: the backend builds the agent from scratch on every inference. The LLM sees only the tools
built for this user — role tools ∩ the client's choices − disabled — with the identity arguments
hidden and the scoped references offered as an enum; a client config can only narrow, never widen.
Every tool call the model makes then passes the policy gate (`Turn.check_call`), and the proxy hands the app the
deterministically filled arguments: the app's executor never sees LLM-supplied identity.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .policy import Policy

MAX_ENUM = 50                     # longer choice lists only bloat the prompt; the ABAC check decides anyway
TRUE_WORDS = ("1", "true", "yes", "on")


def _names(raw) -> frozenset[str]:
    """Tolerant: the non-empty strings of a list (or one string); junk → empty (mAgenticX `key_set`)."""
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(x.strip() for x in raw if isinstance(x, str) and x.strip())


def _approvals(raw) -> Mapping[str, bool]:
    """Tolerant: {tool: bool}; a non-boolean choice is no opinion (mAgenticX `approval_map`)."""
    if not isinstance(raw, Mapping):
        return MappingProxyType({})
    return MappingProxyType({k.strip(): v for k, v in raw.items()
                             if isinstance(k, str) and k.strip() and isinstance(v, bool)})


def _truthy(raw) -> bool:
    if isinstance(raw, str):
        return raw.strip().lower() in TRUE_WORDS
    return raw is True or raw == 1


@dataclass(frozen=True)
class ToolConfig:
    """The client's per-run choices. Can only NARROW what the backend allows (brief A4, principle 1)."""
    enabled: frozenset[str] = frozenset()                  # empty = everything the role has
    disabled: frozenset[str] = frozenset()
    approvals: Mapping[str, bool] = MappingProxyType({})   # add or clear NON-locked gates
    read_only: bool = False                                # True → no side-effect tools in this run

    @classmethod
    def parse(cls, raw) -> "ToolConfig":
        """dict | JSON string | None. Anything unparseable degrades to "no choices" = the role baseline,
        which is the safe direction: junk can never widen, and a junk `approvals` entry keeps the gate."""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                return cls()
        if not isinstance(raw, Mapping):
            return cls()
        inner = raw.get("tool_config") if isinstance(raw.get("tool_config"), Mapping) else raw   # brief A4 shape
        return cls(enabled=_names(inner.get("enabled")), disabled=_names(inner.get("disabled")),
                   approvals=_approvals(inner.get("approvals")),
                   read_only=_truthy(raw.get("read_only")) or _truthy(inner.get("read_only")))

    def to_dict(self) -> dict:
        return {"enabled": sorted(self.enabled), "disabled": sorted(self.disabled),
                "approvals": dict(self.approvals), "read_only": self.read_only}


@dataclass
class ToolSet:
    """The tools of ONE run. Built from scratch on every inference (brief A4, principle 2)."""
    names: frozenset[str]
    role: str
    config: ToolConfig
    policy: Policy
    role_names: frozenset[str] = frozenset()               # what the role has, before the client's narrowing
    _declarations: list = field(default_factory=list, init=False, repr=False)

    def __contains__(self, name) -> bool:
        return name in self.names

    def __iter__(self):
        return iter(sorted(self.names))

    def __len__(self) -> int:
        return len(self.names)

    def declarations(self) -> list[dict]:
        """What the LLM sees. A fresh copy: nobody can change the run's tools by editing the list."""
        return copy.deepcopy(self._declarations)

    def approval(self, name) -> tuple[bool, str]:
        return self.policy.approval_required(name, self.role, self.config.approvals)

    def denial_rule(self, name) -> str | None:
        """Why `name` is not in this run: `rbac` (the role lacks it) or `tool_config` (the client narrowed
        it away); None when it is in the set."""
        if name in self.names:
            return None
        return "tool_config" if name in self.role_names else "rbac"


def build_toolset(policy: Policy, adapter, principal, declarations, config: ToolConfig | None = None) -> ToolSet:
    """names = role tools ∩ (config.enabled or role tools) − config.disabled; read_only drops side effects."""
    config = config if config is not None else ToolConfig()
    role = principal["role"]
    role_names = frozenset(policy.allowed_tools(role))
    names = (role_names & (config.enabled or role_names)) - config.disabled
    if config.read_only:
        names = frozenset(n for n in names if not policy.is_side_effect(n))
    ts = ToolSet(names=names, role=role, config=config, policy=policy, role_names=role_names)
    seen = set()
    for d in declarations or []:
        name = _decl_name(d)
        if name not in names or name in seen:
            continue
        seen.add(name)
        ts._declarations.append(_declaration(policy, adapter, principal, name, d))
    return ts


def _decl_name(d):
    """Gemini style {"name", ...} or OpenAI style {"type": "function", "function": {"name", ...}}."""
    if not isinstance(d, Mapping):
        return None
    fn = d.get("function") if "function" in d else d
    return fn.get("name") if isinstance(fn, Mapping) else None


def _declaration(policy, adapter, principal, name, d) -> dict:
    """A deep copy of `d`: bound and denied arguments removed, scoped references offered as an enum."""
    d = copy.deepcopy(d)
    fn = d["function"] if "function" in d else d
    spec = policy.spec(name) or {}
    hidden = set(policy.binds(name, principal["role"])) | set(policy.deny_args(name))
    params = fn.get("parameters")
    if not isinstance(params, dict):
        return d
    props = params.get("properties")
    if isinstance(props, dict):
        for h in hidden:
            props.pop(h, None)
        if spec.get("scope_enum", True) is not False and policy.switch("firewall.abac"):
            _add_enums(policy, adapter, principal, name, props)       # the scope as an enum: only while ABAC is on
    if isinstance(params.get("required"), list):
        params["required"] = [r for r in params["required"] if r not in hidden]
    return d


def _add_enums(policy, adapter, principal, name, props):
    """An argument whose role rule is ONE named constraint has a closed answer (e.g. the enrolled course codes):
    offer it, so the model does not guess. The type stays as declared; the constraint is still checked."""
    rule = policy.role_rule(name, principal["role"])
    if not isinstance(rule, dict):
        return
    for arg, c in rule.items():
        prop = props.get(arg)
        if arg == "fields" or not isinstance(prop, dict) or not isinstance(c, str) or "|" in c:
            continue
        choices = adapter.choices(c.strip(), principal)
        if not (isinstance(choices, list) and 0 < len(choices) <= MAX_ENUM
                and all(isinstance(x, str) and x for x in choices)):
            continue
        prop["enum"] = list(choices)
        desc = str(prop.get("description") or "").rstrip()
        sep = "" if not desc else (" " if desc.endswith((".", "!", "?")) else ". ")
        prop["description"] = f"{desc}{sep}Allowed: {', '.join(choices)}."

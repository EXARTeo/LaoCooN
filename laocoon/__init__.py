"""Laocoon: a deterministic security layer for LLM agents, deployed as an OpenAI-compatible proxy (proxy.py).

    ① Deputy Firewall   policy.py, firewall.py   who may call what: the tool set of THIS run (role ∩ client choices),
                                                 identity arguments filled by code, references and scope checked
    ② Siren Guard       classifier.py            Jev guardrail classifier: G1 input, G2 tool results, G2b before
                                                 sensitive calls, G3 output
    ③ Canary            canary.py                per-conversation canary in the system prompt, honey records,
                                                 output DLP (also on tool arguments)
    ④ Bound approvals  approvals.py             human approval bound (HMAC) to the exact arguments, single use
    ⑤ Audit & control  audit.py, killswitch.py, static/console.html   hash-chained audit, kill switch, console
    ⑥ Attack memory     memory.py (opt-in, LAOCOON_MEMORY)   attacks a tripwire or a person confirmed are remembered;
                                                 a repeat or a variant is caught at G1 / G2 (only ever stricter)

Deterministic layers decide. The classifier is a signal: it can only make a decision stricter.
"""
from .decision import Decision
from .firewall import ToolConfig
from .guard import Guard, Turn

__all__ = ["Guard", "Turn", "Decision", "ToolConfig"]
__version__ = "0.2.0"

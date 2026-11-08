"""Environment variables and policy loading."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY = PACKAGE_DIR.parent / "policies" / "eclass.yaml"

APPROVAL_DEFAULTS = {"read": False, "write": True, "communicate": True, "external": True}   # brief A4/A5
REMOVED_KEYS = ("match_args", "trust", "dlp_fields")              # v1 keys of the removed planner/provenance/scanner layers
REMOVED_TOOL_KEYS = ("beneficiary", "recipient")


PREFIX, LEGACY_PREFIX = "LAOCOON_", "ODYSSEUS_"     # the project was called Odysseus until 2026-11-07


def _raw(name):
    """os.environ[name]; for an unset or empty LAOCOON_X, the former ODYSSEUS_X (settings files written before the
    rename keep working)."""
    v = os.environ.get(name)
    if v in (None, "") and name.startswith(PREFIX):
        v = os.environ.get(LEGACY_PREFIX + name[len(PREFIX):])
    return v


def env(name, default=None):
    v = _raw(name)
    return v if v not in (None, "") else default


def env_bool(name, default=True):
    v = _raw(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    policy_path: str
    db_path: str
    secret: bytes
    guard_backend: str = "off"                          # jev | openai | hf | off, or a combination: jev+hf (② Siren Guard)
    guard_model: str = ""                               # "" = the backend's default model
    guard_base_url: str = ""                            # "" = the backend's default endpoint
    guard_api_key: str = ""
    guard_timeout: float | None = None                  # None = the backend's default
    guard_labels: str = ""                              # hf backend: "LABEL=class,..." (LAOCOON_GUARD_LABELS)
    guard_points: str = ""                              # "G2,G2b": consult the classifier only there ("" = all)
    guard_members: dict = field(default_factory=dict)   # a combination's per-backend settings (guard_members_from_env)
    planner_backend: str = "off"                        # off | openai  (opt-in plan commitment, laocoon/planner.py)
    planner_model: str = ""
    planner_base_url: str = ""
    planner_api_key: str = ""
    planner_timeout: float | None = None                # None = the policy's planner.timeout (default 8 s)
    approval_ttl: int = 300
    persist_threshold: int = 5          # high-severity denies per window before the user is frozen
    persist_window: int = 600
    persist_ttl: int = 900
    private_data: bool = True           # LAOCOON_PRIVATE_DATA=off ignores the policy's private_data section
    previous_secret: bytes | None = None    # LAOCOON_SECRET_PREVIOUS: decrypts vault/pending rows after a rotation
    # ⑥ attack memory (memory.py), opt-in: off | on (learn + act) | match (act only, learn nothing)
    memory: str = "off"
    memory_db: str = ""                                 # "" = the Laocoon database (db_path)
    memory_autoconfirm: str = "canary,honey"            # signals confirmed without an admin: canary,honey,rejected,deny
    memory_threshold: float = 0.6                       # similarity that acts (G1 block, G2 quarantine)
    memory_review: float = 0.45                         # similarity that asks for review
    memory_points: str = "G1,G2"
    memory_ttl_days: float = 90.0                       # unmatched attacks, unreviewed candidates expire (0 = never)
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        key = env("LAOCOON_GUARD_API_KEY") or env("TYPESAFE_API_KEY") or ""
        s = cls(
            policy_path=env("LAOCOON_POLICY", str(DEFAULT_POLICY)),
            db_path=env("LAOCOON_DB", "/data/laocoon.db"),
            secret=(env("LAOCOON_SECRET", "change-me-laocoon")).encode(),
            guard_backend=(env("LAOCOON_GUARD_BACKEND") or ("jev" if key else "off")).strip().lower(),
            guard_model=env("LAOCOON_GUARD_MODEL") or env("GUARD_MODEL") or "",
            guard_base_url=(env("LAOCOON_GUARD_BASE_URL") or "").rstrip("/"),
            guard_api_key=key,
            guard_timeout=_float_or_none(env("LAOCOON_GUARD_TIMEOUT")),
            guard_labels=env("LAOCOON_GUARD_LABELS") or "",
            guard_points=env("LAOCOON_GUARD_POINTS") or "",
            guard_members=guard_members_from_env(),
            # the planner defaults to the agent's own endpoint and key when only LAOCOON_PLANNER is set
            planner_backend=(env("LAOCOON_PLANNER") or "off").strip().lower(),
            planner_model=env("LAOCOON_PLANNER_MODEL") or env("LAOCOON_UPSTREAM_MODEL") or "",
            planner_base_url=(env("LAOCOON_PLANNER_BASE_URL") or env("LAOCOON_UPSTREAM_BASE_URL") or "").rstrip("/"),
            planner_api_key=env("LAOCOON_PLANNER_API_KEY") or env("LAOCOON_UPSTREAM_API_KEY")
            or env("AI_STUDIO_API_KEY") or "",
            planner_timeout=_float_or_none(env("LAOCOON_PLANNER_TIMEOUT")),
            approval_ttl=int(env("LAOCOON_APPROVAL_TTL", "300")),
            persist_threshold=int(env("LAOCOON_PERSIST_THRESHOLD", "5")),
            private_data=env_bool("LAOCOON_PRIVATE_DATA", True),
            previous_secret=(env("LAOCOON_SECRET_PREVIOUS") or "").encode() or None,
            memory=(env("LAOCOON_MEMORY") or "off").strip().lower(),
            memory_db=env("LAOCOON_MEMORY_DB") or "",
            memory_autoconfirm=env("LAOCOON_MEMORY_AUTOCONFIRM", "canary,honey"),
            memory_threshold=float(env("LAOCOON_MEMORY_THRESHOLD", "0.6")),
            memory_review=float(env("LAOCOON_MEMORY_REVIEW", "0.45")),
            memory_points=env("LAOCOON_MEMORY_POINTS", "G1,G2"),
            memory_ttl_days=float(env("LAOCOON_MEMORY_TTL_DAYS", "90")),
        )
        for k, v in overrides.items():
            setattr(s, k, v)
        return s


GUARD_MEMBER_KINDS = ("jev", "hf", "openai")
GUARD_MEMBER_FIELDS = ("model", "base_url", "api_key", "timeout", "points", "labels", "langs")


def guard_members_from_env() -> dict:
    """The settings of each backend in a combination (LAOCOON_GUARD_BACKEND=jev+hf): LAOCOON_GUARD_<KIND>_<FIELD>,
    e.g. LAOCOON_GUARD_HF_MODEL, LAOCOON_GUARD_HF_POINTS, LAOCOON_GUARD_JEV_TIMEOUT. In a combination the shared
    LAOCOON_GUARD_MODEL / _BASE_URL / _TIMEOUT do not apply (one model name cannot mean two backends); the API key
    (LAOCOON_GUARD_API_KEY / TYPESAFE_API_KEY) and the hf labels (LAOCOON_GUARD_LABELS) are shared defaults.
    -> {kind: {field: value}} for the kinds that set anything."""
    out = {}
    for kind in GUARD_MEMBER_KINDS:
        vals = {f: env(f"LAOCOON_GUARD_{kind.upper()}_{f.upper()}") for f in GUARD_MEMBER_FIELDS}
        vals = {f: v for f, v in vals.items() if v not in (None, "")}
        if vals:
            out[kind] = vals
    return out


def _float_or_none(v):
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def load_policy(path) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return normalise_policy(data)


def normalise_policy(data: dict) -> dict:
    """Policy v2 defaults, in place. v1 aliases are mapped (`bind_self` → `bind`, `canaries` →
    `honey_records.values`), v1 keys of the removed components are dropped, so the rest of the code
    only ever sees the v2 shape."""
    data.setdefault("version", 2)
    data.setdefault("default", "deny")
    data.setdefault("tools", {})
    data.setdefault("refs", {})
    # refs: {arg: kind} or {arg: {kind: user, fallback: app}}. `fallback: app` (seamless proxy only): when the
    # reference is outside what the user's scope shows the proxy, the app resolves it (e.g. a message recipient)
    refs, fallback = {}, dict(data.get("ref_fallback") or {})
    for arg, kind in (data.get("refs") or {}).items():
        if isinstance(kind, dict):
            if kind.get("fallback") == "app":
                fallback[arg] = "app"
            kind = kind.get("kind")
        if isinstance(kind, str) and kind:
            refs[arg] = kind
    data["refs"], data["ref_fallback"] = refs, fallback
    for k in ("identity", "lookups"):                              # seamless proxy settings (facts.py, holds.py)
        data[k] = data.get(k) if isinstance(data.get(k), dict) else {}
    data.setdefault("sensitive_fields", [])
    data.setdefault("secret_patterns", [])

    honey = data.get("honey_records")
    honey = {"values": honey} if isinstance(honey, list) else (dict(honey) if isinstance(honey, dict) else {})
    old = data.pop("canaries", None)
    if not honey.get("values") and isinstance(old, list):
        honey["values"] = old
    honey["values"] = [str(v) for v in (honey.get("values") or []) if str(v).strip()]
    honey["visible_to"] = [str(r) for r in (honey.get("visible_to") or [])]
    data["honey_records"] = honey

    approvals = data.get("approvals") if isinstance(data.get("approvals"), dict) else {}
    approvals["defaults"] = {**APPROVAL_DEFAULTS, **(approvals.get("defaults") or {})}
    approvals["roles"] = approvals.get("roles") or {}
    data["approvals"] = approvals
    data["guard"] = data.get("guard") if isinstance(data.get("guard"), dict) else {}   # classifier fills defaults
    data["planner"] = data.get("planner") if isinstance(data.get("planner"), dict) else {}  # planner fills defaults
    for k in REMOVED_KEYS:
        data.pop(k, None)

    for name, spec in list(data["tools"].items()):
        if spec is None:
            data["tools"][name] = spec = {}
        spec.setdefault("effect", "read")
        if not isinstance(spec.get("allow"), dict):
            spec["allow"] = {}
        bind_self = spec.pop("bind_self", None)
        if isinstance(bind_self, dict):
            spec["bind"] = {**bind_self, **(spec.get("bind") or {})}
        if not isinstance(spec.get("approval"), bool):           # v1 role-keyed approvals: the effect default applies
            spec.pop("approval", None)
        if "locked" in spec:
            spec["locked"] = bool(spec["locked"])
        for k in REMOVED_TOOL_KEYS:
            spec.pop(k, None)
    return data


def enabled() -> bool:
    """LAOCOON_ENABLED (default on); the console's `laocoon.enabled` switch overrides it (runtime.py)."""
    return env_bool("LAOCOON_ENABLED", True)

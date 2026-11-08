"""① Deputy Firewall, policy half: role policy, identity binding, resource constraints, output filters,
approval merge.

Deterministic. The model's words never grant anything: identity comes from the session, every
reference is resolved to an id exactly once, bound arguments are filled by code, and the tool runs
with those ids. The per-run half (tool set of the run, wrapper) is in `firewall.py`.

Constraint syntax in the YAML (per role, per argument):
    arg: name              the constraint must hold
    arg: "a|b"             any of them must hold
    arg: [a, b]            all of them must hold
    fields: [x, y]         only these optional arguments may be set (others must be empty)
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from . import decision as D
from .adapters.base import UNRESOLVABLE
from .facts import NeedFacts, Unverifiable

SIDE_EFFECTS = ("write", "communicate", "external")
APPROVAL_LAYERS = ("default", "tool", "role", "user", "locked")   # merge order, lowest priority first

IDENTITY_REASON = "Το «{a}» δείχνει σε άλλον χρήστη. Ο βοηθός ενεργεί μόνο ως ο συνδεδεμένος χρήστης."
UNVERIFIABLE_REASON = ("Δεν ήταν δυνατό να επιβεβαιωθεί το δικαίωμα από τα δεδομένα της εφαρμογής· "
                       "η ενέργεια δεν εκτελέστηκε.")
OUT_OF_SCOPE_REASON = "Το «{v}» δεν βρέθηκε ανάμεσα σε όσα επιτρέπεται να δεις."
SAFE_REF = re.compile(r"^[\w.@'+\- ]{1,64}$")          # what an app-resolved reference may look like


class _Unresolved:
    """A reference the seamless proxy could not resolve inside the user's scope: every constraint on it fails."""

    def __repr__(self):
        return "UNRESOLVED"


UNRESOLVED = _Unresolved()


def _empty(v):
    return v is None or (isinstance(v, str) and not v.strip())


def _flag(v):
    """A YAML/JSON boolean (ints accepted); anything else means "no opinion"."""
    return bool(v) if isinstance(v, (bool, int)) else None


def _short(v, n=120):
    s = str(v)
    return s if len(s) <= n else s[:n] + "…"


def _always_on(_key) -> bool:
    return True


class Policy:
    def __init__(self, data: dict, adapter):
        self.data = data
        self.adapter = adapter
        self.tools_spec = data["tools"]
        self.refs = data.get("refs", {})                     # arg name -> kind (user, course, ...)
        self.ref_fallback = data.get("ref_fallback", {})     # arg name -> "app": the app resolves it (see evaluate)
        self.sensitive_fields = set(data.get("sensitive_fields", []))
        self.approvals = data.get("approvals") or {}         # {defaults: {effect: bool}, roles: {role: {tool: bool}}}
        # the console's runtime switches (key -> on?); the Guard binds it to runtime.RuntimeSettings.on. Off:
        # firewall.rbac every policy tool for every role · firewall.abac no scope/constraint denies · firewall.identity
        # bound args neither hidden nor filled, deny_args allowed · firewall.filters no role filters on results
        self.switch = _always_on

    # ------------------------------------------------------------------ lookups
    def spec(self, tool) -> dict | None:
        return self.tools_spec.get(tool)

    def effect(self, tool) -> str:
        s = self.spec(tool)
        return s.get("effect", "write") if s else "write"

    def is_side_effect(self, tool) -> bool:
        return self.effect(tool) in SIDE_EFFECTS

    def role_rule(self, tool, role):
        s = self.spec(tool)
        if not s:
            return None
        rule = (s.get("allow") or {}).get(role)
        rule = rule if rule not in (None, False, {}) or rule is True else None
        if rule is None and not self.switch("firewall.rbac"):
            return True                    # RBAC off (console): the tool is the role's, without constraints
        return rule

    def allowed_tools(self, role) -> list[str]:
        return [t for t in self.tools_spec if self.role_rule(t, role) is not None]

    def filters(self, tool, role) -> list[str]:
        if not self.switch("firewall.filters"):
            return []
        s = self.spec(tool) or {}
        return list((s.get("filter") or {}).get(role) or [])

    def bound_args(self, tool, role) -> list[str]:
        """Arguments that ARE the logged-in user: hidden from the model, filled from the session."""
        s = self.spec(tool) or {}
        bind = s.get("bind") if "bind" in s else s.get("bind_self")   # v1 YAMLs not passed through load_policy
        return list((bind or {}).get(role) or [])

    bind_self = bound_args          # v1 name

    def binds(self, tool, role) -> list[str]:
        """The bound arguments enforced now: hidden, filled and compared. None while identity is off (console)."""
        return self.bound_args(tool, role) if self.switch("firewall.identity") else []

    def deny_args(self, tool) -> list[str]:
        """Arguments that must stay empty (impersonation); none while identity is off (console)."""
        return list((self.spec(tool) or {}).get("deny_args") or []) if self.switch("firewall.identity") else []

    def is_locked(self, tool) -> bool:
        return bool((self.spec(tool) or {}).get("locked"))

    # ------------------------------------------------------------------ approvals (brief A4: defaults → tool → role → user → locked)
    def approval_required(self, tool, role, user_approvals: Mapping[str, bool] | None = None) -> tuple[bool, str]:
        """-> (needed, layer that decided). Locked is applied last so no layer below it can clear a gate."""
        spec = self.spec(tool) or {}
        effect = self.effect(tool)
        d = _flag((self.approvals.get("defaults") or {}).get(effect))
        needed, layer = (d if d is not None else effect in SIDE_EFFECTS), "default"
        t = _flag(spec.get("approval"))
        if t is not None:
            needed, layer = t, "tool"
        r = _flag(((self.approvals.get("roles") or {}).get(role) or {}).get(tool))
        if r is not None:
            needed, layer = r, "role"
        u = _flag((user_approvals or {}).get(tool))
        if u is not None:
            needed, layer = u, "user"
        if self.is_locked(tool):
            needed, layer = True, "locked"
        return needed, layer

    # ------------------------------------------------------------------ the check
    def evaluate(self, principal, tool, args, *, plan=False):
        """-> (Decision or None, normalised args, meta). None means ① has no objection.

        meta["filled"] names the bound arguments that were set from the session (never from the model).

        Seamless proxy (an adapter with `fact_sourced`): the adapter may lack a fact. With plan=True its NeedFacts
        propagates, so the caller can look the fact up and decide later; otherwise the call is denied as
        unverifiable (fail closed, severity medium: an outage must never freeze the user).
        """
        facts = (principal.get("attrs") or {}).get("facts")
        if facts is not None:
            facts.mode = "write" if self.is_side_effect(tool) else "read"
            facts.relaxed = False
        try:
            d, nargs, meta = self._evaluate(principal, tool, args)
            if any(v is UNRESOLVED for v in nargs.values()):  # show what the model wrote, not the marker
                nargs = {k: ((args or {}).get(k) if v is UNRESOLVED else v) for k, v in nargs.items()}
                if d is not None:
                    d.args = nargs
            return d, nargs, meta
        except NeedFacts:
            if plan:
                raise
            return D.deny(tool, dict(args or {}), "abac_unverifiable", UNVERIFIABLE_REASON, "medium"), \
                dict(args or {}), {"filled": []}
        except Unverifiable:
            return D.deny(tool, dict(args or {}), "abac_unverifiable", UNVERIFIABLE_REASON, "medium"), \
                dict(args or {}), {"filled": []}

    def _evaluate(self, principal, tool, args):
        role = principal["role"]
        args = dict(args or {})
        meta = {"filled": []}
        rule = self.role_rule(tool, role)
        if rule is None:
            why = "δεν υπάρχει στην πολιτική" if self.spec(tool) is None else f"δεν επιτρέπεται στον ρόλο «{role}»"
            return D.deny(tool, args, "rbac", f"Το εργαλείο {tool} {why}.", "high"), args, meta
        spec = self.spec(tool)
        sourced = getattr(self.adapter, "fact_sourced", False)
        abac = self.switch("firewall.abac")
        bound = set(self.binds(tool, role))

        for a in self.deny_args(tool):
            if not _empty(args.get(a)):
                return D.deny(tool, args, "identity", f"Το όρισμα «{a}» δεν επιτρέπεται (πλαστοπροσωπία).", "high"), args, meta

        # normalise references to ids, exactly once
        unresolved = []
        for a, v in list(args.items()):
            if _empty(v):
                args[a] = None
                continue
            kind = self.refs.get(a)
            if kind is None or (sourced and a in bound):      # seamless: identity arguments are checked below
                continue
            rid = self.adapter.resolve(kind, v, principal=principal) if sourced else self.adapter.resolve(kind, v)
            if rid is UNRESOLVABLE:                           # seamless: outside what the user's scope shows
                if self.ref_fallback.get(a) == "app" and SAFE_REF.match(str(v).strip()):
                    args[a] = str(v).strip()                  # the app resolves it (policy: fallback: app)
                    continue
                if not abac:                                  # ABAC off: no scope, the app gets it as written
                    continue
                unresolved.append((a, v))
                args[a] = UNRESOLVED
                continue
            if rid is None:
                if not abac:
                    continue
                return D.deny(tool, args, "abac", f"Δεν βρέθηκε μοναδικό {kind} για «{v}».", "low"), args, meta
            args[a] = rid
        args = {k: v for k, v in args.items() if v is not None}

        # deterministic fill: a bound argument is the caller; never silently replace someone else
        for a in self.binds(tool, role):
            v = args.get(a)
            if v is None:
                args[a] = principal["id"]
                meta["filled"].append(a)
                continue
            if sourced:                                       # compared with the principal, never looked up
                v = self.adapter.resolve("user", v, principal=principal, bound=True)
            elif a not in self.refs:                          # not resolved above: read it as a user reference
                v = self.adapter.resolve("user", v)
            if v is None or v is UNRESOLVABLE or v is UNRESOLVED or int(v) != int(principal["id"]):
                return D.deny(tool, args, "identity", IDENTITY_REASON.format(a=a), "high"), args, meta
            args[a] = int(principal["id"])

        # resource constraints (ABAC)
        if isinstance(rule, dict) and abac:
            fields = rule.get("fields")
            for a, c in rule.items():
                if a == "fields":
                    continue
                value = args.get(a)
                if value is None:
                    return D.deny(tool, args, "abac", f"Λείπει το όρισμα «{a}».", "medium"), args, meta
                if isinstance(c, list):
                    batch = getattr(self.adapter, "all_of", None)          # one request to a remote PDP
                    ok = batch(c, principal, value) if callable(batch) else None
                    if ok is None:
                        ok = all(self.adapter.constraint(x, principal, value, args) for x in c)
                else:
                    ok = any(self.adapter.constraint(x.strip(), principal, value, args) for x in str(c).split("|"))
                if not ok:
                    shown = next((str(v) for x, v in unresolved if x == a), value)
                    return D.deny(tool, args, "abac",
                                  f"Δεν έχεις δικαίωμα στο {a}={_short(shown)} ({c}).", "high"), args, meta
            if fields is not None:
                allowed = set(fields) | {k for k in rule if k != "fields"} | set(self.bound_args(tool, role))
                extra = [k for k, v in args.items() if k not in allowed and not _empty(v)]
                if extra:
                    return D.deny(tool, args, "abac",
                                  f"Επιτρέπεται αλλαγή μόνο στα πεδία: {', '.join(fields)} (όχι {', '.join(extra)}).",
                                  "high"), args, meta
        if unresolved:                                        # no constraint rejected it: still not something we know
            a, v = unresolved[0]
            return D.deny(tool, args, "abac", OUT_OF_SCOPE_REASON.format(v=_short(v)), "low"), args, meta

        return None, args, meta

    def normalise_for_labels(self, principal, tool, args):
        """The arguments of a call that already ran, as needed to filter and label its result: bound arguments are
        the caller, the rest as the proxy released them (ids). No lookup, no check: the decision was made then."""
        args = {k: v for k, v in dict(args or {}).items() if not _empty(v)}
        for a in self.binds(tool, principal["role"]):
            args[a] = principal["id"]
        return args

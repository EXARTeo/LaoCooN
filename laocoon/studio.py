"""Policy studio: check, render and summarise a policy for the web editor (pure functions, no Flask).

The deterministic layers trust the policy file completely, so the studio is strict: every name the engine looks
up at call time (constraints, filters, checkpoints, actions) is checked here, and every issue carries the path of
the offending key (plus its line when there is YAML source) so the editor can point at it. Issue messages are
Greek because the operator reads them.
"""
from __future__ import annotations

import copy
import difflib
import re
from datetime import date

import yaml

from .classifier import (ACTION_RANK, DEFAULT_CLASSES, DEFAULT_ON_ERROR, DEFAULT_POLICY, DEFAULT_STEERING,
                         DEFAULT_THRESHOLDS, POINTS, RETIRED_POINTS, GuardConfig)
from .config import APPROVAL_DEFAULTS, normalise_policy
from .identity import DEFAULT_LABELS as IDENTITY_LABELS
from .policy import SIDE_EFFECTS, Policy
from .authzen import AuthzenConfig, ConfigError as AuthzenConfigError
from .views import DataModel, ModelError

MAX_YAML_BYTES = 256 * 1024
EFFECTS = ("read", "write", "communicate", "external")
TOP_KEYS = ("version", "app", "default", "roles", "identity", "lookups", "refs", "ref_fallback", "data_model",
            "authzen", "sensitive_fields", "secret_patterns", "honey_records", "private_data", "approvals", "guard", "tools")
IDENTITY_FIELDS = ("id", "username", "role", "name")               # the seamless proxy (identity.py, config.py)
TTL_CLASSES = ("read", "write", "identity")                         # facts.py
TOOL_KEYS = ("effect", "allow", "bind", "deny_args", "filter", "untrusted_output", "approval", "locked", "scope_enum")
GUARD_KEYS = ("classes", "policy", "thresholds", "steering", "on_error", "min_chars", "max_chars", "max_chunks")
V1_TOP_KEYS = ("match_args", "trust", "dlp_fields", "canaries")
V1_TOOL_KEYS = ("beneficiary", "recipient", "bind_self", "match_args", "trust", "dlp_fields")
# What each checkpoint does with a classifier action (guard.py); anything else is only logged as a flag there.
POINT_ACTIONS = {"G1": ("allow", "flag", "block"), "G2": ("allow", "flag", "review", "quarantine"),
                 "G2b": ("allow", "flag", "hitl"), "G3": ("allow", "flag", "redact")}
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
PD_NORMALISERS = ("text", "digits", "digits:11", "upper_nospace", "phone_gr", "idcard_gr", "casefold")

EFFECT_LABELS = {"read": "ανάγνωση", "write": "εγγραφή", "communicate": "επικοινωνία", "external": "εξωτερικό"}
POINT_LABELS = {"G1": "Είσοδος χρήστη", "G2": "Αποτελέσματα εργαλείων", "G2b": "Πριν από ευαίσθητη ενέργεια",
                "G3": "Τελική απάντηση"}
ACTION_LABELS = {"allow": "επιτρέπεται", "flag": "σημαία", "review": "για έλεγχο", "hitl": "έγκριση χρήστη",
                 "redact": "απόκρυψη", "quarantine": "καραντίνα", "block": "μπλοκάρισμα"}
LAYER_LABELS = {"default": "προεπιλογή", "tool": "εργαλείο", "role": "ρόλος", "user": "χρήστης",
                "locked": "κλειδωμένο"}

BLANK = {
    "version": 2, "app": "my-app", "default": "deny", "roles": ["user", "admin"], "refs": {},
    "sensitive_fields": [], "secret_patterns": [], "honey_records": {"values": [], "visible_to": []},
    "approvals": {"defaults": dict(APPROVAL_DEFAULTS), "roles": {}}, "tools": {},
}


# ---------------------------------------------------------------------------------------------- issues
class Issues:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, level, path, message):
        self.items.append({"level": level, "path": [str(p) if not isinstance(p, int) else p for p in path],
                           "message": message, "line": None})

    def error(self, path, message):
        self.add("error", path, message)

    def warn(self, path, message):
        self.add("warning", path, message)

    def info(self, path, message):
        self.add("info", path, message)

    @property
    def errors(self) -> int:
        return sum(i["level"] == "error" for i in self.items)


def _adapter_catalog(adapter) -> dict:
    fn = getattr(adapter, "catalog", None)
    cat = fn() if callable(fn) else {}
    return {"strict": bool(cat.get("strict")), "constraints": dict(cat.get("constraints") or {}),
            "filters": dict(cat.get("filters") or {}), "ref_kinds": dict(cat.get("ref_kinds") or {}),
            "untrusted_output": dict(cat.get("untrusted_output") or {})}


def catalog(adapter) -> dict:
    """Everything the editor offers as options: core vocabulary + the adapter's names."""
    return {
        "effects": [{"name": e, "label": EFFECT_LABELS[e], "side_effect": e in SIDE_EFFECTS} for e in EFFECTS],
        "points": [{"name": p, "label": POINT_LABELS[p], "actions": list(POINT_ACTIONS[p])} for p in POINTS],
        "actions": {a: ACTION_LABELS.get(a, a) for a in ACTION_RANK},
        "layers": LAYER_LABELS,
        "approval_defaults": dict(APPROVAL_DEFAULTS),
        "guard_defaults": {"classes": [dict(c) for c in DEFAULT_CLASSES],
                           "policy": {c: dict(p) for c, p in DEFAULT_POLICY.items()},
                           "thresholds": dict(DEFAULT_THRESHOLDS), "steering": dict(DEFAULT_STEERING),
                           "on_error": dict(DEFAULT_ON_ERROR), "min_chars": 16, "max_chars": 6000, "max_chunks": 4},
        "adapter": _adapter_catalog(adapter),
        "private": _private_catalog(),
        "identity_fields": dict(IDENTITY_LABELS),
    }


def _private_catalog() -> dict:
    """The values a private_data class may take (private.py), for the form's choices."""
    from .private import VALIDATORS
    return {"match": ["pattern", "field", "exact"], "action": ["placeholder", "mask", "drop"],
            "answer": ["shown", "self", "never"], "tool_args": ["table", "self", "never"],
            "validators": sorted(VALIDATORS), "normalisers": list(PD_NORMALISERS),
            "id_length": [6, 12], "classifier_view": ["dummy", "placeholder"]}


# ---------------------------------------------------------------------------------------------- parsing
def parse_yaml(text: str, issues: Issues):
    if len(text.encode("utf-8")) > MAX_YAML_BYTES:
        issues.error([], f"Το αρχείο ξεπερνά τα {MAX_YAML_BYTES // 1024} KB.")
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        issues.add("error", [], "Μη έγκυρο YAML: " + str(getattr(e, "problem", None) or e).strip())
        if mark is not None:
            issues.items[-1]["line"] = mark.line + 1
        return None
    if data is None:
        issues.error([], "Το αρχείο είναι κενό.")
        return None
    if not isinstance(data, dict):
        issues.error([], "Η πολιτική πρέπει να είναι αντιστοίχιση (κλειδί: τιμή) στο ανώτερο επίπεδο.")
        return None
    return data


def line_of(root_node, path) -> int | None:
    """1-based line of the deepest node on `path` that exists in a yaml.compose() tree."""
    node, line = root_node, (root_node.start_mark.line + 1 if root_node is not None else None)
    for key in path:
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if str(k.value) == str(key):
                    node, line = v, k.start_mark.line + 1
                    break
            else:
                return line
        elif isinstance(node, yaml.SequenceNode) and isinstance(key, int) and 0 <= key < len(node.value):
            node = node.value[key]
            line = node.start_mark.line + 1
        else:
            return line
    return line


def _attach_lines(text, issues: Issues):
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return
    if root is None:
        return
    for it in issues.items:
        if it["line"] is None and it["path"]:
            it["line"] = line_of(root, it["path"])


# ---------------------------------------------------------------------------------------------- checks
def _is_str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) and x.strip() for x in v)


def _roles(data) -> list[str]:
    roles = data.get("roles")
    if isinstance(roles, list):
        return [str(r) for r in roles]
    seen = []
    for spec in (data.get("tools") or {}).values():
        for r in ((spec or {}).get("allow") or {}) if isinstance(spec, dict) else ():
            if r not in seen:
                seen.append(str(r))
    return seen


def _check_private(data, issues):
    """private_data (private.py): the classes compile, the honey records belong to a class, fields are not shared,
    every pattern stays fast on adversarial text. The server's secret is checked at start-up, not here."""
    import time as _time
    from .private import ConfigError, PrivatePolicy
    pd = data.get("private_data")
    if pd is None:
        return
    if not isinstance(pd, dict):
        issues.error(["private_data"], "Το «private_data» πρέπει να είναι αντιστοίχιση (classes, subject_args, …).")
        return
    honey = data.get("honey_records")
    values = honey if isinstance(honey, list) else (honey or {}).get("values") or [] if isinstance(honey, (dict, list)) \
        else []
    try:
        pp = PrivatePolicy(pd, secret=b"studio-check-only-" + b"x" * 32, honey_values=[str(v) for v in values])
    except ConfigError as e:
        issues.error(["private_data"], f"Η ενότητα private_data δεν φορτώνεται: {e}")
        return
    assigned = {surface for surface in pp.honey.values()}
    for v in values:
        if str(v) not in assigned:
            issues.warn(["honey_records", "values"], f"Η τιμή-δόλωμα «{v}» δεν ταιριάζει σε καμία κατηγορία του "
                                                     "private_data: θα έφτανε στο μοντέλο αυτούσια και θα ξεχώριζε.")
    owner = {}
    for c in pp.classes:
        for f in c.fields:
            if f in owner:
                issues.warn(["private_data", "classes", c.name, "fields"],
                            f"Το πεδίο «{f}» δηλώνεται ήδη στην κατηγορία {owner[f]}: ισχύει η πρώτη.")
            owner.setdefault(f, c.name)
        if c.pattern is not None:
            sample = ("1" * 40 + " a@" * 30 + "GR" + "1 " * 200) * 10
            t0 = _time.perf_counter()
            c.pattern.findall(sample)
            if _time.perf_counter() - t0 > 0.05:
                issues.warn(["private_data", "classes", c.name, "pattern"],
                            "Η κανονική έκφραση είναι αργή σε αντίξοο κείμενο (> 50 ms): κίνδυνος καθυστέρησης.")
    if pp.subject_args:
        tools = data.get("tools") or {}
        for t in pp.subject_args:
            if t not in tools:
                issues.warn(["private_data", "subject_args", t], f"Το εργαλείο «{t}» δεν υπάρχει στην πολιτική.")
    issues.info(["private_data"], f"{len(pp.classes)} κατηγορίες προσωπικών δεδομένων: το μοντέλο και ο ταξινομητής "
                                  "βλέπουν μόνο ψευδώνυμα ⟦ΤΥΠΟΣ:id⟧ (χρειάζεται LAOCOON_SECRET ≥ 32 χαρακτήρες).")


def check(data: dict, adapter, issues: Issues) -> dict | None:
    """Validate the raw policy (paths refer to what the author wrote). -> normalised copy, or None if the
    engine itself could not load it."""
    cat = _adapter_catalog(adapter)
    strict = cat["strict"]

    def unknown_name(path, kind, name, known):
        msg = f"Άγνωστο {kind} «{name}»."
        if known:
            msg += " Διαθέσιμα: " + ", ".join(sorted(known)) + "."
        (issues.error if strict else issues.warn)(path, msg)

    for k in data:
        if k in V1_TOP_KEYS:
            issues.warn([k], f"Το κλειδί «{k}» είναι της έκδοσης 1 και αγνοείται."
                        + (" Χρησιμοποίησε honey_records.values." if k == "canaries" else ""))
        elif k not in TOP_KEYS:
            issues.warn([k], f"Άγνωστο κλειδί «{k}»: αγνοείται.")
    if data.get("version", 2) != 2:
        issues.warn(["version"], "Ο έλεγχος γίνεται με τους κανόνες της έκδοσης 2.")
    if "default" in data and data["default"] != "deny":
        issues.error(["default"], "Υποστηρίζεται μόνο «default: deny»: ό,τι δεν αναφέρεται απαγορεύεται.")
    if "app" in data and not isinstance(data["app"], str):
        issues.error(["app"], "Το «app» πρέπει να είναι κείμενο.")

    # roles
    roles = data.get("roles")
    if roles is None:
        issues.warn(["roles"], "Λείπει η λίστα ρόλων· οι ρόλοι προκύπτουν από τους κανόνες «allow».")
    elif not _is_str_list(roles) or not roles:
        issues.error(["roles"], "Οι ρόλοι πρέπει να είναι μη κενή λίστα ονομάτων.")
    else:
        for i, r in enumerate(roles):
            if not NAME_RE.match(r):
                issues.error(["roles", i], f"Μη έγκυρο όνομα ρόλου «{r}».")
        if len(set(roles)) != len(roles):
            issues.error(["roles"], "Ο ίδιος ρόλος υπάρχει δύο φορές.")
    role_set = set(_roles(data))

    def check_role(path, role):
        if roles is not None and role not in role_set:
            issues.warn(path, f"Ο ρόλος «{role}» δεν υπάρχει στη λίστα ρόλων.")

    # refs, fields, secrets
    refs = data.get("refs", {})
    if not isinstance(refs, dict):
        issues.error(["refs"], "Το «refs» πρέπει να είναι αντιστοίχιση όρισμα: είδος.")
        refs = {}
    for arg, kind in refs.items():                       # arg: kind, or arg: {kind: ..., fallback: app}
        rp = ["refs", arg]
        if isinstance(kind, dict):
            for k in kind:
                if k not in ("kind", "fallback"):
                    issues.warn(rp + [k], f"Άγνωστο κλειδί «{k}»: αγνοείται. Διαθέσιμα: kind, fallback.")
            if "fallback" in kind and kind["fallback"] != "app":
                issues.error(rp + ["fallback"], "Το «fallback» δέχεται μόνο την τιμή «app».")
            rp, kind = rp + ["kind"], kind.get("kind")
        if not isinstance(kind, str) or not kind:
            issues.error(rp, "Το είδος αναφοράς πρέπει να είναι κείμενο.")
        elif cat["ref_kinds"] and kind not in cat["ref_kinds"]:
            issues.warn(rp, f"Άγνωστο είδος αναφοράς «{kind}». Διαθέσιμα: "
                        + ", ".join(cat["ref_kinds"]) + ".")
    fb = data.get("ref_fallback")
    if fb is not None and not (isinstance(fb, dict) and all(v == "app" for v in fb.values())):
        issues.error(["ref_fallback"], "Το «ref_fallback» πρέπει να είναι αντιστοίχιση όρισμα: app.")
    _check_seamless(data, issues)
    _check_data_model(data, adapter, issues)
    _check_authzen(data, adapter, issues)
    for key in ("sensitive_fields", "secret_patterns"):
        if key in data and not _is_str_list(data[key]):
            issues.error([key], f"Το «{key}» πρέπει να είναι λίστα από κείμενα.")
    for i, pat in enumerate(data.get("secret_patterns") or []):
        if isinstance(pat, str):
            try:
                re.compile(pat)
            except re.error as e:
                issues.error(["secret_patterns", i], f"Μη έγκυρη κανονική έκφραση: {e}.")

    honey = data.get("honey_records")
    if honey is not None:
        if isinstance(honey, list):
            issues.info(["honey_records"], "Λίστα τιμών: διαβάζεται ως honey_records.values.")
        elif not isinstance(honey, dict):
            issues.error(["honey_records"], "Το «honey_records» πρέπει να έχει «values» και «visible_to».")
        else:
            if not isinstance(honey.get("values", []), list):
                issues.error(["honey_records", "values"], "Οι τιμές πρέπει να είναι λίστα.")
            vis = honey.get("visible_to", [])
            if not isinstance(vis, list):
                issues.error(["honey_records", "visible_to"], "Το «visible_to» πρέπει να είναι λίστα ρόλων.")
            else:
                for r in vis:
                    check_role(["honey_records", "visible_to"], r)

    _check_approvals(data, issues, check_role)
    _check_guard(data.get("guard"), issues)
    _check_private(data, issues)

    # tools
    tools = data.get("tools")
    if tools is None or tools == {}:
        issues.warn(["tools"], "Δεν υπάρχει κανένα εργαλείο: ο βοηθός δεν θα μπορεί να κάνει τίποτα.")
        tools = {}
    elif not isinstance(tools, dict):
        issues.error(["tools"], "Το «tools» πρέπει να είναι αντιστοίχιση όνομα εργαλείου: ρυθμίσεις.")
        tools = {}
    for name, spec in tools.items():
        p = ["tools", name]
        if not NAME_RE.match(str(name)):
            issues.error(p, f"Μη έγκυρο όνομα εργαλείου «{name}».")
        if spec is None:
            continue
        if not isinstance(spec, dict):
            issues.error(p, "Οι ρυθμίσεις του εργαλείου πρέπει να είναι αντιστοίχιση.")
            continue
        for k in spec:
            if k == "bind_self":
                issues.info(p + [k], "Το «bind_self» μετονομάστηκε σε «bind» (διαβάζεται κανονικά).")
            elif k in V1_TOOL_KEYS:
                issues.warn(p + [k], f"Το «{k}» είναι της έκδοσης 1 και αγνοείται.")
            elif k not in TOOL_KEYS:
                issues.warn(p + [k], f"Άγνωστο κλειδί «{k}»: αγνοείται.")
        effect = spec.get("effect")
        if effect is None:
            issues.warn(p, "Λείπει το «effect»: θεωρείται ανάγνωση (read), άρα χωρίς έγκριση.")
        elif effect not in EFFECTS:
            issues.error(p + ["effect"], f"Άγνωστο effect «{effect}». Διαθέσιμα: {', '.join(EFFECTS)}.")

        allow = spec.get("allow", {})
        if not isinstance(allow, dict):
            issues.error(p + ["allow"], "Το «allow» πρέπει να είναι αντιστοίχιση ρόλος: true ή όροι.")
            allow = {}
        for role, rule in allow.items():
            rp = p + ["allow", role]
            check_role(rp, role)
            if rule is True or rule is False or rule is None:
                continue
            if not isinstance(rule, dict):
                issues.error(rp, "Ο κανόνας πρέπει να είναι true ή αντιστοίχιση όρισμα: όρος.")
                continue
            if not rule:
                issues.warn(rp, "Κενοί όροι σημαίνουν καμία πρόσβαση· γράψε true για πλήρη πρόσβαση.")
            for arg, c in rule.items():
                if arg == "fields":
                    if not _is_str_list(c):
                        issues.error(rp + ["fields"], "Τα «fields» πρέπει να είναι λίστα ονομάτων πεδίων.")
                    continue
                names = c if isinstance(c, list) else str(c).split("|") if isinstance(c, str) else None
                if not names or not all(isinstance(x, str) and x.strip() for x in names):
                    issues.error(rp + [arg], "Ο όρος πρέπει να είναι όνομα, «α|β» (ένα από) ή λίστα (όλα).")
                    continue
                if isinstance(c, list) and any("|" in x for x in c):
                    issues.error(rp + [arg], "Σε λίστα (πρέπει να ισχύουν όλοι) δεν επιτρέπεται το «|».")
                    continue
                for x in names:
                    if x.strip() not in cat["constraints"]:
                        unknown_name(rp + [arg], "όρος", x.strip(), cat["constraints"])

        for key, what in (("bind", "ορισμάτων"), ("filter", "φίλτρων")):
            m = spec.get(key, spec.get("bind_self") if key == "bind" else None)
            if m is None:
                continue
            if not isinstance(m, dict):
                issues.error(p + [key], f"Το «{key}» πρέπει να είναι αντιστοίχιση ρόλος: λίστα {what}.")
                continue
            for role, lst in m.items():
                check_role(p + [key, role], role)
                if not _is_str_list(lst):
                    issues.error(p + [key, role], f"Χρειάζεται λίστα {what}.")
                    continue
                if key == "filter":
                    for f in lst:
                        if f not in cat["filters"]:
                            unknown_name(p + [key, role], "φίλτρο", f, cat["filters"])
        if "deny_args" in spec and not _is_str_list(spec["deny_args"]):
            issues.error(p + ["deny_args"], "Το «deny_args» πρέπει να είναι λίστα ορισμάτων.")

        uo = spec.get("untrusted_output")
        if isinstance(uo, str):
            if uo not in cat["untrusted_output"]:
                unknown_name(p + ["untrusted_output"], "είδος μη αξιόπιστου αποτελέσματος", uo,
                             cat["untrusted_output"])
        elif isinstance(uo, dict):
            if not isinstance(uo.get("author_field"), str) or not uo.get("author_field"):
                issues.error(p + ["untrusted_output"], "Χρειάζεται «author_field»: το πεδίο με τον συγγραφέα.")
            for k in uo:
                if k not in ("author_field", "ref", "id_field"):
                    issues.warn(p + ["untrusted_output", k], f"Άγνωστο κλειδί «{k}»: αγνοείται.")
        elif uo is not None:
            issues.error(p + ["untrusted_output"], "Γράψε ένα όνομα ή {author_field, ref, id_field}.")

        if "approval" in spec and not isinstance(spec["approval"], bool):
            issues.error(p + ["approval"], "Το «approval» είναι true ή false. Για εξαιρέσεις ανά ρόλο "
                                           "χρησιμοποίησε το approvals.roles.")
        for key in ("locked", "scope_enum"):
            if key in spec and not isinstance(spec[key], bool):
                issues.error(p + [key], f"Το «{key}» είναι true ή false.")
        if spec.get("locked") is True and spec.get("approval") is False:
            issues.warn(p + ["approval"], "Το «locked» υπερισχύει: η έγκριση θα ζητείται πάντα.")

    if issues.errors:
        return None
    norm = normalise_policy(copy.deepcopy(data))
    try:
        Policy(norm, adapter)
        GuardConfig.from_policy(norm)
    except Exception as e:                                          # the engine's own loader has the last word
        issues.error([], f"Η μηχανή δεν μπορεί να φορτώσει την πολιτική: {e}")
        return None
    _semantic_warnings(norm, adapter, issues)
    return norm


def _used_constraints(data) -> set:
    """The constraint names the tools' rules use."""
    used = set()
    for spec in (data.get("tools") or {}).values():
        for rule in ((spec or {}).get("allow") or {}).values() if isinstance(spec, dict) else ():
            if isinstance(rule, dict):
                for arg, c in rule.items():
                    if arg != "fields":
                        names = c if isinstance(c, list) else str(c).split("|")
                        used.update(str(x).strip() for x in names)
    return used


def _pure_constraints(adapter) -> set:
    """Constraints that read no data: `self`, and the adapter's text-valued ones (read_only_sql)."""
    cons = _adapter_catalog(adapter)["constraints"]
    return {"self"} | set(getattr(adapter, "PURE_CONSTRAINTS", {})) | {
        k for k, v in cons.items() if isinstance(v, dict) and v.get("value") == "text"}


def _check_authzen(data, adapter, issues):
    """`authzen` (LAOCOON_AUTHZ_SOURCE=authzen): parsed exactly as the runtime parses it (authzen.AuthzenConfig)."""
    if data.get("authzen") is None:
        return
    try:
        cfg = AuthzenConfig.parse(data["authzen"])
    except AuthzenConfigError as e:
        issues.error(["authzen"] + e.path, f"AuthZEN: {e.message}")
        return
    if cfg.identity_action is None:
        issues.info(["authzen", "identity"], "Χωρίς «identity.action» η ταυτότητα πρέπει να έρχεται από την "
                    "υπογεγραμμένη κεφαλίδα (LAOCOON_IDENTITY=signed_header).")
    for name in sorted(_used_constraints(data) - set(cfg.constraints) - _pure_constraints(adapter)):
        issues.warn(["authzen", "constraints"], f"Ο περιορισμός «{name}» χρησιμοποιείται στα εργαλεία αλλά δεν "
                    "αντιστοιχίζεται στο authzen: με LAOCOON_AUTHZ_SOURCE=authzen δεν θα μπορεί να ελεγχθεί.")
    kinds = {v if isinstance(v, str) else (v or {}).get("kind") for v in (data.get("refs") or {}).values()}
    for kind in sorted(k for k in kinds if isinstance(k, str) and k not in cfg.resources):
        issues.warn(["authzen", "resources"], f"Το είδος αναφοράς «{kind}» δεν έχει τύπο πόρου στο authzen.resources.")
    for kind in sorted(k for k, r in cfg.resources.items() if not r.search):
        where = _unchecked_refs(data, kind)
        if where:
            issues.warn(["authzen", "resources", kind],
                        f"Το «{kind}» δεν έχει «search», οπότε ο Laocoon δεν μπορεί να ελέγξει ότι ένα id υπάρχει. Όπου "
                        f"ο κανόνας είναι «true» ({', '.join(where)}), το εργαλείο παίρνει το id όπως γράφτηκε. "
                        "Πρόσθεσε «search» αν το PDP σου μπορεί να το απαντήσει.")


def _unchecked_refs(data, kind) -> list[str]:
    """`tool/role` pairs where an argument referring to `kind` reaches the tool under a rule of `true`: no
    constraint asks the PDP about it, so without a search nothing confirms that the object exists."""
    args = {a for a, k in (data.get("refs") or {}).items()
            if (k if isinstance(k, str) else (k or {}).get("kind")) == kind}
    out = []
    for tool, spec in (data.get("tools") or {}).items():
        allow = ((spec or {}).get("allow") or {}) if isinstance(spec, dict) else {}
        if {a for r in allow.values() if isinstance(r, dict) for a in r} & args:
            out += [f"{tool}/{role}" for role, r in allow.items() if r is True]
    return out


def _check_data_model(data, adapter, issues):
    """`data_model` (LAOCOON_AUTHZ_SOURCE=views): parsed exactly as the runtime parses it (views.DataModel). The
    views it describes must never expose a field the policy itself declares sensitive."""
    if data.get("data_model") is None:
        return
    try:
        model = DataModel.parse(data["data_model"])
    except ModelError as e:
        issues.error(["data_model"] + e.path, f"Μοντέλο δεδομένων: {e.message}")
        return
    sensitive = {str(f).lower() for f in (data.get("sensitive_fields") or []) if isinstance(f, str)}
    for view, table, cols, tier in model.views(previews=True):
        for name, col in cols:
            if col.lower() in sensitive:
                where = ["data_model", "previews" if tier == "preview" else "objects"]
                issues.error(where, f"Η όψη {view} διαβάζει το {table}.{col}, που η πολιτική δηλώνει ευαίσθητο "
                                    "(sensitive_fields): ο Laocoon δεν πρέπει να μπορεί να το διαβάσει.")
    if model.previews:
        issues.info(["data_model", "previews"], "Οι όψεις prev_* δίνουν προσωπικά δεδομένα (τιμές πριν από την "
                    "αλλαγή στις κάρτες έγκρισης): το script τις περιλαμβάνει μόνο με --previews.")
    for name in sorted(_used_constraints(data) - set(model.constraints) - _pure_constraints(adapter)):
        issues.warn(["data_model", "constraints"], f"Ο περιορισμός «{name}» χρησιμοποιείται στα εργαλεία αλλά δεν "
                    "ορίζεται στο data_model: με LAOCOON_AUTHZ_SOURCE=views δεν θα μπορεί να ελεγχθεί.")


def _check_seamless(data, issues):
    """`identity` and `lookups`: settings of the seamless proxy (LAOCOON_AUTHZ_SOURCE=lookup), read by
    identity.from_system_prompt_strict and EclassLookupAdapter.configure; anything else there is ignored."""
    ident = data.get("identity")
    if ident is not None:
        if not isinstance(ident, dict):
            issues.error(["identity"], "Το «identity» πρέπει να είναι αντιστοίχιση {fields, verify}.")
        else:
            for k in ident:
                if k not in ("fields", "verify"):
                    issues.warn(["identity", k], f"Άγνωστο κλειδί «{k}»: αγνοείται. Διαθέσιμα: fields, verify.")
            fields = ident.get("fields")
            if fields is not None:
                if not isinstance(fields, dict) or not all(isinstance(v, str) and v.strip() for v in fields.values()):
                    issues.error(["identity", "fields"], "Το «fields» αντιστοιχίζει πεδίο σε ετικέτα κειμένου.")
                else:
                    for k in fields:
                        if k not in IDENTITY_FIELDS:
                            issues.warn(["identity", "fields", k], f"Άγνωστο πεδίο ταυτότητας «{k}». Διαθέσιμα: "
                                        + ", ".join(IDENTITY_FIELDS) + ".")
            if "verify" in ident and not isinstance(ident["verify"], bool):
                issues.error(["identity", "verify"], "Το «verify» πρέπει να είναι true ή false.")
    lk = data.get("lookups")
    if lk is None:
        return
    if not isinstance(lk, dict):
        issues.error(["lookups"], "Το «lookups» πρέπει να είναι αντιστοίχιση {tools, out_of_scope, ttl}.")
        return
    for k in lk:
        if k not in ("tools", "out_of_scope", "ttl"):
            issues.warn(["lookups", k], f"Άγνωστο κλειδί «{k}»: αγνοείται. Διαθέσιμα: tools, out_of_scope, ttl.")
    tools = lk.get("tools")
    if tools is not None:
        if not _is_str_list(tools):
            issues.error(["lookups", "tools"], "Το «tools» πρέπει να είναι λίστα ονομάτων εργαλείων.")
        else:
            known = data.get("tools") if isinstance(data.get("tools"), dict) else {}
            for i, t in enumerate(tools):
                if t not in known:
                    issues.warn(["lookups", "tools", i], f"Το εργαλείο «{t}» δεν υπάρχει στην πολιτική.")
    if "out_of_scope" in lk and not isinstance(lk["out_of_scope"], bool):
        issues.error(["lookups", "out_of_scope"], "Το «out_of_scope» πρέπει να είναι true ή false.")
    ttl = lk.get("ttl")
    if ttl is not None:
        if not isinstance(ttl, dict):
            issues.error(["lookups", "ttl"], "Το «ttl» πρέπει να είναι αντιστοίχιση {read, write, identity}.")
        else:
            for k, v in ttl.items():
                if k not in TTL_CLASSES:
                    issues.warn(["lookups", "ttl", k], f"Άγνωστο κλειδί «{k}»: αγνοείται. Διαθέσιμα: "
                                + ", ".join(TTL_CLASSES) + ".")
                elif isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                    issues.error(["lookups", "ttl", k], "Η διάρκεια πρέπει να είναι θετικός ακέραιος (δευτερόλεπτα).")


def _check_approvals(data, issues, check_role):
    ap = data.get("approvals")
    if ap is None:
        return
    if not isinstance(ap, dict):
        issues.error(["approvals"], "Το «approvals» πρέπει να έχει «defaults» και «roles».")
        return
    for k in ap:
        if k not in ("defaults", "roles"):
            issues.warn(["approvals", k], f"Άγνωστο κλειδί «{k}»: αγνοείται.")
    defaults = ap.get("defaults") or {}
    if not isinstance(defaults, dict):
        issues.error(["approvals", "defaults"], "Χρειάζεται αντιστοίχιση effect: true/false.")
        defaults = {}
    for eff, v in defaults.items():
        if eff not in EFFECTS:
            issues.warn(["approvals", "defaults", eff], f"Άγνωστο effect «{eff}».")
        if not isinstance(v, bool):
            issues.error(["approvals", "defaults", eff], "Η τιμή είναι true ή false.")
    for eff in SIDE_EFFECTS:
        if defaults.get(eff) is False:
            issues.warn(["approvals", "defaults", eff],
                        f"Οι ενέργειες «{EFFECT_LABELS[eff]}» εκτελούνται χωρίς έγκριση από προεπιλογή.")
    roles = ap.get("roles") or {}
    if not isinstance(roles, dict):
        issues.error(["approvals", "roles"], "Χρειάζεται αντιστοίχιση ρόλος: {εργαλείο: true/false}.")
        return
    tools = data.get("tools") if isinstance(data.get("tools"), dict) else {}
    for role, m in roles.items():
        check_role(["approvals", "roles", role], role)
        if not isinstance(m, dict):
            issues.error(["approvals", "roles", role], "Χρειάζεται αντιστοίχιση εργαλείο: true/false.")
            continue
        for tool, v in m.items():
            if tool not in tools:
                issues.warn(["approvals", "roles", role, tool], f"Το εργαλείο «{tool}» δεν υπάρχει στην πολιτική.")
            if not isinstance(v, bool):
                issues.error(["approvals", "roles", role, tool], "Η τιμή είναι true ή false.")


def _check_guard(g, issues):
    if g is None:
        return
    p = ["guard"]
    if not isinstance(g, dict):
        issues.error(p, "Το «guard» πρέπει να είναι αντιστοίχιση.")
        return
    for k in g:
        if k not in GUARD_KEYS:
            issues.warn(p + [k], f"Άγνωστο κλειδί «{k}»: αγνοείται.")
    names = [c["name"] for c in DEFAULT_CLASSES]
    if "classes" in g:
        classes = g["classes"]
        if not isinstance(classes, list) or not classes:
            issues.error(p + ["classes"], "Οι κατηγορίες πρέπει να είναι μη κενή λίστα {name, description}.")
            classes = []
        names = []
        for i, c in enumerate(classes):
            cp = p + ["classes", i]
            if not isinstance(c, dict) or not isinstance(c.get("name"), str) or not NAME_RE.match(c["name"]):
                issues.error(cp, "Κάθε κατηγορία χρειάζεται «name» (όνομα χωρίς κενά) και «description».")
                continue
            if c["name"] == "steering":
                issues.error(cp, "Το όνομα «steering» είναι δεσμευμένο για την ερώτηση χειραγώγησης.")
            if c["name"] in names:
                issues.error(cp, f"Η κατηγορία «{c['name']}» υπάρχει δύο φορές.")
            if not str(c.get("description") or "").strip():
                issues.warn(cp, "Χωρίς περιγραφή ο ταξινομητής δεν ξέρει τι σημαίνει η κατηγορία.")
            names.append(c["name"])
        if names and "benign" not in names:
            issues.info(p + ["classes"], "Η κατηγορία «benign» προστίθεται αυτόματα.")
    pol = g.get("policy", {})
    if not isinstance(pol, dict):
        issues.error(p + ["policy"], "Χρειάζεται αντιστοίχιση κατηγορία: {σημείο: ενέργεια}.")
        pol = {}
    for cls, m in pol.items():
        cp = p + ["policy", cls]
        if cls not in names:
            issues.error(cp, f"Η κατηγορία «{cls}» δεν ορίζεται στο guard.classes.")
        if not isinstance(m, dict):
            issues.error(cp, "Χρειάζεται αντιστοίχιση σημείο: ενέργεια (π.χ. G1: block).")
            continue
        for pt, a in m.items():
            if pt in RETIRED_POINTS:
                issues.warn(cp + [pt], f"Το σημείο {pt} καταργήθηκε (έλεγχος αποθηκευμένου περιεχομένου μέσα στην εφαρμογή· ο proxy δεν βλέπει εγγραφές): αγνοείται.")
            elif pt not in POINTS:
                issues.error(cp + [pt], f"Άγνωστο σημείο ελέγχου «{pt}». Διαθέσιμα: {', '.join(POINTS)}.")
            elif a not in ACTION_RANK:
                issues.error(cp + [pt], f"Άγνωστη ενέργεια «{a}».")
            elif a not in POINT_ACTIONS[pt]:
                issues.warn(cp + [pt], f"Στο {pt} η ενέργεια «{a}» καταγράφεται μόνο ως σημαία. "
                                       f"Χρήσιμες εδώ: {', '.join(POINT_ACTIONS[pt])}.")
    th = g.get("thresholds", {})
    if not isinstance(th, dict):
        issues.error(p + ["thresholds"], "Χρειάζεται {block: 0.85, hitl: 0.5}.")
        th = {}
    for k, v in th.items():
        if k not in ("block", "hitl"):
            issues.warn(p + ["thresholds", k], f"Άγνωστο όριο «{k}».")
        elif isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 1:
            issues.error(p + ["thresholds", k], "Το όριο είναι αριθμός από 0 έως 1.")
    b, h = th.get("block", DEFAULT_THRESHOLDS["block"]), th.get("hitl", DEFAULT_THRESHOLDS["hitl"])
    if isinstance(b, (int, float)) and isinstance(h, (int, float)) and h > b:
        issues.warn(p + ["thresholds", "hitl"], "Το όριο hitl είναι πάνω από το block: η μεσαία ζώνη δεν θα "
                                               "χρησιμοποιείται ποτέ.")
    st = g.get("steering")
    if st is not None:
        mi = st.get("merge_into") if isinstance(st, dict) else None
        if mi not in names or mi == "benign":
            issues.error(p + ["steering"], "Το «merge_into» πρέπει να είναι μια κατηγορία επίθεσης.")
    oe = g.get("on_error", {})
    if not isinstance(oe, dict):
        issues.error(p + ["on_error"], "Χρειάζεται αντιστοίχιση σημείο: ενέργεια.")
        oe = {}
    for pt, a in oe.items():
        if pt in RETIRED_POINTS:
            issues.warn(p + ["on_error", pt], f"Το σημείο {pt} καταργήθηκε (έλεγχος αποθηκευμένου περιεχομένου μέσα στην εφαρμογή· ο proxy δεν βλέπει εγγραφές): αγνοείται.")
        elif pt not in POINTS:
            issues.error(p + ["on_error", pt], f"Άγνωστο σημείο ελέγχου «{pt}».")
        elif a not in ACTION_RANK:
            issues.error(p + ["on_error", pt], f"Άγνωστη ενέργεια «{a}».")
    if oe.get("G2b") == "allow":
        issues.warn(p + ["on_error", "G2b"], "Αν ο ταξινομητής αποτύχει, οι ενέργειες μετά από μη αξιόπιστο "
                                             "περιεχόμενο θα περνούν χωρίς έγκριση.")
    for k in ("min_chars", "max_chars", "max_chunks"):
        v = g.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 1):
            issues.error(p + [k], "Χρειάζεται θετικός ακέραιος.")


def _semantic_warnings(norm, adapter, issues):
    pol = Policy(norm, adapter)
    roles = _roles(norm)
    for name, spec in norm["tools"].items():
        p = ["tools", name]
        users = [r for r in roles if pol.role_rule(name, r) is not None]
        if not users:
            if spec.get("allow"):
                issues.info(p, "Κανένας ρόλος δεν έχει πρόσβαση: το μοντέλο δεν θα βλέπει αυτό το εργαλείο.")
            continue
        if pol.effect(name) == "external":
            issues.warn(p, "Εξωτερική πρόσβαση: πιθανό κανάλι διαρροής δεδομένων προς τρίτους.")
        if pol.is_side_effect(name):
            free = [r for r in users if not pol.approval_required(name, r)[0]]
            if free:
                issues.warn(p, f"Εκτελείται χωρίς έγκριση για: {', '.join(free)} "
                               f"({EFFECT_LABELS.get(pol.effect(name), pol.effect(name))}).")


# ---------------------------------------------------------------------------------------------- summary
def matrix(norm, adapter) -> dict:
    """Effective permissions as the engine computes them: per tool and role, access, scope and approval."""
    pol = Policy(norm, adapter)
    roles = _roles(norm)
    rows = []
    for name, spec in norm["tools"].items():
        cells = {}
        for r in roles:
            rule = pol.role_rule(name, r)
            if rule is None:
                cells[r] = None
                continue
            need, layer = pol.approval_required(name, r)
            scope = []
            if isinstance(rule, dict):
                for a, c in rule.items():
                    if a != "fields":
                        scope.append({"arg": a, "constraint": c if isinstance(c, str) else " + ".join(map(str, c))})
            cells[r] = {"access": "full" if rule is True else "scoped", "scope": scope,
                        "fields": rule.get("fields") if isinstance(rule, dict) else None,
                        "approval": need, "layer": layer, "bound": pol.bound_args(name, r),
                        "filters": pol.filters(name, r)}
        rows.append({"name": name, "effect": pol.effect(name), "side_effect": pol.is_side_effect(name),
                     "locked": pol.is_locked(name), "untrusted": bool(spec.get("untrusted_output")), "cells": cells})
    return {"roles": roles, "tools": rows}


def summary(mx) -> dict:
    cells = [(t, c) for t in mx["tools"] for c in t["cells"].values() if c]
    return {"tools": len(mx["tools"]), "roles": len(mx["roles"]),
            "side_effects": sum(t["side_effect"] for t in mx["tools"]),
            "locked": sum(t["locked"] for t in mx["tools"]),
            "untrusted": sum(t["untrusted"] for t in mx["tools"]),
            "grants": len(cells),
            "unguarded": sum(1 for t, c in cells if t["side_effect"] and not c["approval"])}


# ---------------------------------------------------------------------------------------------- rendering
class _FlowMap(dict):
    pass


class _FlowSeq(list):
    pass


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


_Dumper.add_representer(_FlowMap, lambda d, v: d.represent_mapping("tag:yaml.org,2002:map", v, flow_style=True))
_Dumper.add_representer(_FlowSeq, lambda d, v: d.represent_sequence("tag:yaml.org,2002:seq", v, flow_style=True))
_Dumper.add_representer(dict, lambda d, v: d.represent_mapping("tag:yaml.org,2002:map", v, flow_style=False))
_Dumper.add_representer(list, lambda d, v: d.represent_sequence("tag:yaml.org,2002:seq", v, flow_style=False))

WIDTH = 116


def _inline_len(v) -> int:
    return len(yaml.dump(v, Dumper=yaml.SafeDumper, default_flow_style=True, allow_unicode=True, width=10 ** 6,
                         sort_keys=False).strip())


def _ordered(d: dict, order) -> dict:
    out = {k: d[k] for k in order if k in d}
    out.update((k, v) for k, v in d.items() if k not in out)
    return out


def _shape(v, depth, key_len):
    """Choose flow style the way the hand-written policy does: short leaves inline, structure in blocks."""
    if isinstance(v, dict):
        kids = {k: _shape(x, depth + 1, len(str(k))) for k, x in v.items()}
        if depth >= 1 and v and _inline_len(v) <= WIDTH - 2 * depth - key_len - 2:
            return _FlowMap(kids)
        return kids
    if isinstance(v, list):
        if all(not isinstance(x, (dict, list)) for x in v) or _inline_len(v) <= WIDTH - 2 * depth - key_len - 2:
            return _FlowSeq(_shape(x, depth + 1, 2) for x in v)
        kids = [_shape(x, depth + 1, 2) for x in v]
        if any(type(k) is dict for k in kids):                   # items of one list share one style
            kids = [dict(k) if isinstance(k, _FlowMap) else k for k in kids]
        return kids
    return v


def clean(v, path=()):
    """Drop what the form leaves empty (None, "", [], {}), except tool entries and explicit booleans."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            x = clean(x, path + (k,))
            keep = ((len(path) == 1 and path[0] == "tools")               # a tool with nothing set stays listed
                    or (len(path) == 2 and path[0] == "authzen"             # an AuthZEN entry with only defaults
                        and path[1] in ("resources", "constraints", "relations")))
            if keep or not (x is None or x == "" or x == [] or x == {}):
                out[str(k)] = {} if x is None and keep else x
        return out
    if isinstance(v, list):
        return [clean(x, path) for x in v if not (x is None or x == "")]
    if isinstance(v, str):
        return v.strip() if path and path[-1] != "description" else v
    return v


def to_yaml(data: dict) -> str:
    data = _ordered(clean(copy.deepcopy(data)), TOP_KEYS)
    if isinstance(data.get("tools"), dict):
        data["tools"] = {k: _ordered(s, TOOL_KEYS) if isinstance(s, dict) else s for k, s in data["tools"].items()}
    if isinstance(data.get("guard"), dict):
        data["guard"] = _ordered(data["guard"], GUARD_KEYS)
    body = yaml.dump({k: _shape(v, 1, len(k)) for k, v in data.items()}, Dumper=_Dumper, sort_keys=False,
                     allow_unicode=True, width=WIDTH, indent=2)
    app = data.get("app") or "app"
    header = (f"# Policy v2 for {app}, edited in the policy studio on {date.today().isoformat()}.\n"
              "# Deny by default: a tool or role that is not listed here cannot be used.\n"
              "# Key reference: the comments at the top of policies/eclass.yaml.\n")
    return header + _blank_lines(body)


def _blank_lines(body: str) -> str:
    """A blank line after every multi-line top-level section, for readability."""
    out = []
    for line in body.splitlines():
        if out and line[:1].isalpha() and out[-1][:1] in (" ", "-"):
            out.append("")
        out.append(line)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------------------------- form edits
# The visual editor sends the whole edited policy as data. Rewriting the file from data (to_yaml) would drop every
# comment of a hand-written policy, so apply_data() edits the YAML text instead: ruamel.yaml loads it with its
# comments, the changed values are synced into that tree, and a three-way line merge keeps every line the edit did
# not touch byte for byte (ruamel itself re-aligns padded keys and re-wraps long flow lists).
def _plain(v):
    """JSON-comparable form of a YAML value (keys as strings)."""
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, bool) or v is None:
        return v
    for t in (int, float, str):                                      # ruamel's ScalarFloat, quoted strings, …
        if isinstance(v, t):
            return t(v)
    return str(v)


def _rt_yaml():
    from ruamel.yaml import YAML
    y = YAML()
    y.preserve_quotes = True
    y.width = WIDTH
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _rt_node(v, depth, key_len):
    """A new value in the hand-written policy's style: short leaves inline, structure in blocks."""
    from ruamel.yaml.comments import CommentedMap, CommentedSeq

    def conv(x):
        if isinstance(x, dict):
            m = CommentedMap((k, conv(y)) for k, y in x.items())
            if isinstance(x, _FlowMap):
                m.fa.set_flow_style()
            return m
        if isinstance(x, list):
            s = CommentedSeq(conv(y) for y in x)
            if isinstance(x, _FlowSeq):
                s.fa.set_flow_style()
            return s
        return x
    return conv(_shape(v, depth, key_len))


def _same_scalar(a, b) -> bool:
    return (isinstance(a, bool) == isinstance(b, bool) and isinstance(a, str) == isinstance(b, str)
            and _plain(a) == _plain(b))


def _sync(node, value, depth=0, key_len=0):
    """Make the ruamel tree `node` equal to `value` in place where it can (so its comments stay); -> the node."""
    from ruamel.yaml.comments import CommentedMap, CommentedSeq
    if isinstance(node, CommentedMap) and isinstance(value, dict):
        keys = {str(k): k for k in node}
        for sk, k in list(keys.items()):
            if sk not in value:
                del node[k]
        order = list(value)
        for i, (k, v) in enumerate(value.items()):
            if k in keys:
                old = node[keys[k]]
                new = _sync(old, v, depth + 1, len(k))
                if new is not old:
                    node[keys[k]] = new
            else:                       # a new key goes where the edited data has it: after its nearest earlier key
                prev = next((keys.get(x, x) for x in reversed(order[:i]) if x in keys or x in node), None)
                pos = list(node.keys()).index(prev) + 1 if prev is not None else 0
                node.insert(pos, k, _rt_node(v, depth + 1, len(k)))
        return node
    if isinstance(node, CommentedSeq) and isinstance(value, list):
        if _plain(list(node)) == _plain(value):
            return node
        old_keys = [repr(_plain(x)) for x in node]
        new_keys = [repr(_plain(x)) for x in value]
        ops = difflib.SequenceMatcher(None, old_keys, new_keys, autojunk=False).get_opcodes()
        for tag, i1, i2, j1, j2 in reversed(ops):                  # back to front: indices stay valid
            if tag == "equal":
                continue
            if tag == "replace" and i2 - i1 == j2 - j1:
                for o in range(i2 - i1):
                    node[i1 + o] = _sync(node[i1 + o], value[j1 + o], depth + 1, 2)
                continue
            for _ in range(i2 - i1):
                del node[i1]
            for o, v in enumerate(value[j1:j2]):
                node.insert(i1 + o, _rt_node(v, depth + 1, 2))
        return node
    if not isinstance(node, (dict, list)) and not isinstance(value, (dict, list)) and _same_scalar(node, value):
        return node
    return _rt_node(value, depth, key_len)


def _merge3(orig: list[str], base: list[str], new: list[str]) -> list[str]:
    """Apply the change base -> new to orig, where base is orig re-printed (same content, other layout). Lines that
    the change does not touch stay orig's; a change inside a block that base re-printed takes that block from new."""
    lo, hi = {}, {}                                     # base boundary -> first / last aligned orig boundary
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, base, orig, autojunk=False).get_opcodes():
        pairs = [(i1 + k, j1 + k) for k in range(i2 - i1 + 1)] if tag == "equal" else [(i1, j1), (i2, j2)]
        for b, o in pairs:
            lo[b] = min(lo.get(b, o), o)
            hi[b] = max(hi.get(b, o), o)
    anchors = sorted(lo)
    ops = difflib.SequenceMatcher(None, base, new, autojunk=False).get_opcodes()

    def to_new(b, last):
        js = [j1 + b - i1 for tag, i1, i2, j1, j2 in ops if tag == "equal" and i1 <= b <= i2]
        js += [j for tag, i1, i2, j1, j2 in ops if tag != "equal" for i, j in ((i1, j1), (i2, j2)) if i == b]
        return max(js) if last else min(js)

    regions = []
    for tag, i1, i2, _j1, _j2 in ops:
        if tag == "equal":
            continue
        s = max(a for a in anchors if a <= i1)
        e = min(a for a in anchors if a >= i2)
        if regions and s < regions[-1][1]:
            regions[-1][1] = max(regions[-1][1], e)
        else:
            regions.append([s, e])
    out, oc, jc = [], 0, 0
    for s, e in regions:
        out.extend(orig[oc:hi[s]])
        oc = hi[s]
        js, je = max(to_new(s, False), jc), to_new(e, True)
        out.extend(line.rstrip() for line in new[js:je])          # ruamel pads re-wrapped lists
        jc = max(jc, je)
        oc = max(oc, lo[e])
    out.extend(orig[oc:])
    return out


def apply_data(text: str, data: dict) -> str | None:
    """`text` with its values changed to `data`, comments and untouched lines kept. None when that is not
    possible (no ruamel.yaml, or text that ruamel cannot read): the caller falls back to to_yaml()."""
    try:
        y = _rt_yaml()
        import io

        def dump(tree):
            buf = io.StringIO()
            y.dump(tree, buf)
            return buf.getvalue()
        base = dump(y.load(text))
        tree = y.load(text)
        if not isinstance(data, dict) or not hasattr(tree, "items"):
            return None
        new = dump(_sync(tree, data))
    except Exception:                                                # ImportError, YAMLError, odd trees
        return None
    want = _plain(data)
    merged = "\n".join(_merge3(text.splitlines(), base.splitlines(), new.splitlines())) + "\n"
    for candidate in (merged, new):                                 # the merge must say exactly what data says
        try:
            if _plain(yaml.safe_load(candidate)) == want:
                return candidate
        except yaml.YAMLError:
            continue
    return None


# ---------------------------------------------------------------------------------------------- entry points
def analyse(adapter, *, text: str | None = None, data: dict | None = None, base: str | None = None) -> dict:
    """The editor's one call. From YAML text (editor) or data (form): issues with lines, the effective matrix,
    a summary, and both representations so the two views stay in sync. With `base` (the text the form started
    from), form edits are written into that text, so its comments and layout survive."""
    issues = Issues()
    if text is None:
        if not isinstance(data, dict):
            issues.error([], "Λείπει η πολιτική.")
            return _result(issues)
        text = (apply_data(base, data) if isinstance(base, str) and base.strip() else None) or to_yaml(data)
    raw = parse_yaml(text, issues)
    norm = check(raw, adapter, issues) if raw is not None else None
    _attach_lines(text, issues)
    mx = matrix(norm, adapter) if norm is not None else None
    return _result(issues, yaml_text=text, data=raw, mx=mx)


def _result(issues, yaml_text=None, data=None, mx=None):
    order = {"error": 0, "warning": 1, "info": 2}
    items = sorted(issues.items, key=lambda i: (order[i["level"]], i["line"] or 0))
    return {"ok": issues.errors == 0, "yaml": yaml_text, "data": data, "issues": items,
            "counts": {lvl: sum(i["level"] == lvl for i in items) for lvl in order},
            "matrix": mx, "summary": summary(mx) if mx else None}


def diff(old: str, new: str, old_name="ενεργή", new_name="πρόχειρο") -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), old_name, new_name, n=2))

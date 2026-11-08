"""Runtime settings: the mitigation switches an operator can flip from the console while Laocoon runs.

Every switch has a default that IS today's start-up configuration (an environment variable, or what the Guard was
built with), so an empty table behaves exactly as before. A value set in the console overrides the default until it
is reset (DELETE), also across restarts. Values live in the store (table `settings`), never only in process memory:
every gunicorn worker reads them, through a cache of CACHE_SECONDS, so a change reaches all workers within a second.

LAOCOON_RUNTIME_SETTINGS=off locks them: the API is read-only (PUT/DELETE -> 409) and values saved earlier are
ignored, so the environment alone decides (a stolen console session cannot loosen anything).

`register_runtime(app, get_guard, access)` adds the JSON API:
    GET    {api_base}/settings          -> {"locked", "weakened", "settings": [...]}
    PUT    {api_base}/settings          {"values": {key: value, ...}} -> the same shape
    DELETE {api_base}/settings/<key>    back to the default -> the same shape
Each change writes one audit event (stage `console`, action `setting`, severity high when it weakens a mitigation).
"""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import config

CACHE_SECONDS = 1.0
LOCK_ENV = "LAOCOON_RUNTIME_SETTINGS"
MAX_BODY = 64 * 1024
POINTS = ("G1", "G2", "G2b", "G3")

ERR_LOCKED = f"Οι ρυθμίσεις είναι κλειδωμένες ({LOCK_ENV}=off): αλλάζουν μόνο από το περιβάλλον του διακομιστή."
ERR_BODY = 'Το σώμα του αιτήματος πρέπει να είναι {"values": {ρύθμιση: τιμή, …}}.'
ERR_UNKNOWN = "Άγνωστη ρύθμιση «{key}»."
ERR_BOOL = "Η ρύθμιση «{key}» δέχεται μόνο true ή false."
ERR_INT = "Η ρύθμιση «{key}» δέχεται ακέραιο από {min} έως {max}."
ERR_UNAVAILABLE = "Η ρύθμιση «{key}» δεν είναι διαθέσιμη σε αυτή την εγκατάσταση. {note}"


def locked() -> bool:
    """LAOCOON_RUNTIME_SETTINGS: on (default) allows changes; anything else locks them (fail closed)."""
    return not config.env_bool(LOCK_ENV, True)


# ---------------------------------------------------------------------------------------------- the registry
def _const(v):
    return lambda g: v


def _classifier_configured(g) -> bool:
    return bool(getattr(g.classifier, "configured", getattr(g.classifier, "enabled", False)))


def _private_note(g) -> str:
    if g.private_available:
        return ("Δηλωμένα προσωπικά δεδομένα (ΑΜΚΑ, IBAN, τηλέφωνα, …) αντικαθίστανται με ⟦ΤΥΠΟΣ:id⟧ πριν φτάσουν "
                "στο μοντέλο ή στον ταξινομητή.")
    if not g.policy_data.get("private_data"):
        return "Η ενεργή πολιτική δεν έχει ενότητα private_data."
    return ("Δεν μπορεί να ενεργοποιηθεί: χρειάζεται LAOCOON_SECRET τυχαίο, τουλάχιστον 32 bytes, και το πακέτο "
            "cryptography.")


GUARD_OFF_NOTE = "Δεν έχει ρυθμιστεί ταξινομητής (LAOCOON_GUARD_BACKEND / TYPESAFE_API_KEY)."
POINT_NOTES = {
    "G1": "Το μήνυμα του χρήστη, πριν φτάσει στο μοντέλο.",
    "G2": "Τα αποτελέσματα εργαλείων με περιεχόμενο τρίτων (καραντίνα).",
    "G2b": ("Πριν από ενέργεια με παρενέργειες, όταν έχει διαβαστεί μη αξιόπιστο περιεχόμενο. Ανενεργό: η ενέργεια "
            "ζητά πάντα έγκριση σε αυτή την περίπτωση (ασφαλής προεπιλογή)."),
    "G3": "Η απάντηση του μοντέλου, πριν φτάσει στον χρήστη.",
}


@dataclass(frozen=True)
class Spec:
    key: str
    type: str                                           # bool | int | float | choice
    default: Callable[[Any], Any]                       # guard -> today's start-up value
    env: str | None = None
    weakens_when: str | None = None                     # off | lower | higher
    min: float | None = None
    max: float | None = None
    step: float | None = None
    unit: str | None = None
    choices: tuple | None = None
    available: Callable[[Any], bool] = field(default=_const(True))
    note: Callable[[Any], str | None] = field(default=_const(None))

    @property
    def group(self) -> str:
        return self.key.split(".", 1)[0]

    def parse(self, raw, g):
        """A value from the API -> the typed value; ValueError with a Greek message otherwise."""
        if self.type == "bool":
            if not isinstance(raw, bool):
                raise ValueError(ERR_BOOL.format(key=self.key))
            return raw
        if self.type in ("int", "float"):
            ok = isinstance(raw, (int, float)) and not isinstance(raw, bool)
            if ok and self.type == "int":
                ok = float(raw).is_integer()
                raw = int(raw) if ok else raw
            if not ok or (self.min is not None and raw < self.min) or (self.max is not None and raw > self.max):
                raise ValueError(ERR_INT.format(key=self.key, min=_num(self.min), max=_num(self.max)))
            return raw if self.type == "int" else float(raw)
        if self.type == "choice":
            if raw not in (self.choices or ()):
                raise ValueError(ERR_UNKNOWN.format(key=self.key))
            return raw
        raise ValueError(ERR_UNKNOWN.format(key=self.key))

    def weaker(self, new, old) -> bool:
        """Is `new` a weaker mitigation than `old`?"""
        w = self.weakens_when
        try:
            if w == "off":
                return bool(old) and not bool(new)
            if w == "lower":
                return new < old
            if w == "higher":
                return new > old
        except TypeError:
            return False
        return False


def _num(v):
    return int(v) if isinstance(v, float) and v.is_integer() else v


def _bool(key, note, *, env=None, default=_const(True), available=_const(True), weakens="off"):
    return Spec(key, "bool", default, env=env, weakens_when=weakens, available=available,
                note=note if callable(note) else _const(note))


def _point(pt):
    return _bool(f"guard.points.{pt}", POINT_NOTES[pt], env="LAOCOON_GUARD_POINTS",
                 default=lambda g, pt=pt: pt in g.classifier.points, available=_classifier_configured)


SPECS: dict[str, Spec] = {s.key: s for s in (
    _bool("laocoon.enabled", "Ανενεργό: ο proxy προωθεί κάθε αίτημα αυτούσιο στο μοντέλο, χωρίς κανέναν έλεγχο "
                             "(το «πριν» της επίδειξης). Η κονσόλα μένει διαθέσιμη.",
          env="LAOCOON_ENABLED", default=lambda g: config.enabled()),
    # ① Deputy Firewall (per run and policy)
    _bool("firewall.rbac", "Ανενεργό: κάθε ρόλος βλέπει και καλεί όλα τα εργαλεία της πολιτικής· σε όσα ο ρόλος δεν "
                           "είχε, δεν ισχύουν περιορισμοί ούτε δέσμευση ταυτότητας. Εργαλεία εκτός πολιτικής μένουν "
                           "απαγορευμένα."),
    _bool("firewall.abac", "Ανενεργό: δεν ελέγχεται το εύρος (μάθημα, εργασία, πεδία που αλλάζουν, SQL μόνο "
                           "ανάγνωσης)· οι αναφορές γίνονται ids όπου βρίσκονται, αλλιώς περνούν όπως τις έγραψε το "
                           "μοντέλο."),
    _bool("firewall.identity", "Ανενεργό: τα ορίσματα ταυτότητας (bind, deny_args) ούτε κρύβονται ούτε "
                               "συμπληρώνονται από τον κώδικα· τα ορίζει το μοντέλο."),
    _bool("firewall.filters", "Ανενεργό: τα αποτελέσματα των εργαλείων φτάνουν στο μοντέλο χωρίς τα φίλτρα του "
                              "ρόλου (ελαχιστοποίηση δεδομένων)."),
    # ② Siren Guard
    _bool("guard.enabled", lambda g: (
        "Ανενεργό: κανένα σημείο δεν ελέγχεται· οι ντετερμινιστικοί έλεγχοι ισχύουν, και το G2b ζητά έγκριση για "
        "ενέργειες μετά από μη αξιόπιστο περιεχόμενο." if _classifier_configured(g) else GUARD_OFF_NOTE),
        env="LAOCOON_GUARD_BACKEND", default=_classifier_configured, available=_classifier_configured),
    *(_point(pt) for pt in POINTS),
    # ③ Canary
    _bool("canary.system_prompt", "Canary ανά συνομιλία στο system prompt και ανίχνευσή του σε απαντήσεις και "
                                  "ορίσματα εργαλείων (διαρροή → απόσυρση και τερματισμός)."),
    _bool("canary.honey", "Εγγραφές-δολώματα (honey records) σε απαντήσεις και ορίσματα εργαλείων (απόσυρση, "
                          "τερματισμός)."),
    _bool("canary.dlp", "Έλεγχος εξόδου: μυστικά του system prompt (secret_patterns), αυτούσιες γραμμές του, "
                        "εξωτερικές εικόνες στην απάντηση."),
    # ④ Bound approvals
    _bool("approvals.enabled", "Ανενεργό: οι ενέργειες με παρενέργειες εκτελούνται χωρίς έγκριση, και οι "
                               "κλειδωμένες. Το G2b και τα προσωπικά δεδομένα ζητούν ακόμη έγκριση όπου χρειάζεται."),
    Spec("approvals.ttl", "int", lambda g: int(g.approvals.ttl), env="LAOCOON_APPROVAL_TTL", weakens_when="higher",
         min=30, max=3600, step=30, unit="s", note=_const("Πόσο μένει ανοιχτό ένα αίτημα έγκρισης.")),
    # ⑤ Audit & control: persistence meter
    _bool("persist.enabled", "Πάγωμα του χρήστη μετά από επαναλαμβανόμενες μπλοκαρισμένες ενέργειες υψηλού ρίσκου."),
    Spec("persist.threshold", "int", lambda g: int(g.settings.persist_threshold), env="LAOCOON_PERSIST_THRESHOLD",
         weakens_when="higher", min=1, max=100, step=1,
         note=_const("Μπλοκαρισμένες ενέργειες υψηλού ρίσκου μέσα στο παράθυρο πριν από το πάγωμα.")),
    Spec("persist.window", "int", lambda g: int(g.settings.persist_window), weakens_when="lower", min=60, max=86400,
         step=60, unit="s", note=_const("Το χρονικό παράθυρο όπου μετρώνται.")),
    Spec("persist.ttl", "int", lambda g: int(g.settings.persist_ttl), weakens_when="lower", min=60, max=86400,
         step=60, unit="s", note=_const("Πόσο διαρκεί το πάγωμα.")),
    # private data
    _bool("private_data.enabled", _private_note, env="LAOCOON_PRIVATE_DATA",
          default=lambda g: bool(getattr(g.settings, "private_data", True)) and g.private_available,
          available=lambda g: g.private_available),
)}


# ---------------------------------------------------------------------------------------------- per guard
class RuntimeSettings:
    """The switches of one Guard, read from its store. `value(key)` is the console's value or the default."""

    def __init__(self, guard, ttl: float = CACHE_SECONDS):
        self.g = guard
        self.ttl = ttl
        self._snap = (float("-inf"), {})                # (monotonic time read, {key: stored value})

    # ------------------------------------------------------------------ reading
    def invalidate(self):
        self._snap = (float("-inf"), {})

    def _stored(self) -> dict:
        at, values = self._snap
        now = time.monotonic()
        if now - at < self.ttl:
            return values
        try:
            rows = self.g.store.query("SELECT key, value FROM settings")
        except (sqlite3.Error, OSError):
            rows = []                                   # an unreadable store: the defaults (start-up configuration)
        values = {}
        for r in rows:
            spec = SPECS.get(r["key"])
            if spec is None:
                continue
            try:
                values[r["key"]] = spec.parse(json.loads(r["value"]), self.g)
            except (ValueError, TypeError):
                continue                                # out of range or of another type: ignored, default applies
        self._snap = (now, values)
        return values

    def override(self, key):
        """The console's value, or None (no value, or locked)."""
        if locked():
            return None
        return self._stored().get(key)

    def default(self, key):
        return SPECS[key].default(self.g)

    def value(self, key):
        v = self.override(key)
        return self.default(key) if v is None else v

    def on(self, key) -> bool:
        return bool(self.value(key))

    def source(self, key) -> str:
        if self.override(key) is not None:
            return "runtime"
        env = SPECS[key].env
        return "env" if env and config.env(env) is not None else "default"

    def available(self, key) -> bool:
        return bool(SPECS[key].available(self.g))

    def weakened(self) -> list[str]:
        out = []
        for key, spec in SPECS.items():
            v = self.override(key)
            if v is not None and spec.available(self.g) and spec.weaker(v, spec.default(self.g)):
                out.append(key)
        return out

    def describe(self) -> list[dict]:
        out = []
        for key, spec in SPECS.items():
            out.append({"key": key, "group": spec.group, "type": spec.type, "value": self.value(key),
                        "default": self.default(key), "source": self.source(key), "env": spec.env,
                        "min": _num(spec.min), "max": _num(spec.max), "step": _num(spec.step), "unit": spec.unit,
                        "choices": list(spec.choices) if spec.choices else None, "weakens_when": spec.weakens_when,
                        "available": bool(spec.available(self.g)), "note": spec.note(self.g)})
        return out

    def payload(self) -> dict:
        return {"locked": locked(), "weakened": self.weakened(), "settings": self.describe()}

    def summary(self) -> dict:
        """For the console's /state: the banner."""
        return {"weakened": self.weakened(), "locked": locked()}

    # ------------------------------------------------------------------ writing
    def set_many(self, values: dict, who: str | None) -> list[tuple]:
        """Validate every value first, then store them in one transaction and audit each change.
        -> [(key, old, new)]. ValueError (Greek) for an unknown key, a bad value or an unavailable switch."""
        parsed = {}
        for key, raw in values.items():
            spec = SPECS.get(key)
            if spec is None:
                raise ValueError(ERR_UNKNOWN.format(key=key))
            v = spec.parse(raw, self.g)
            if not spec.available(self.g):
                raise ValueError(ERR_UNAVAILABLE.format(key=key, note=spec.note(self.g) or "").strip())
            parsed[key] = v
        return self._write({k: (v, False) for k, v in parsed.items()}, who)

    def reset(self, key, who: str | None) -> list[tuple]:
        if key not in SPECS:
            raise ValueError(ERR_UNKNOWN.format(key=key))
        return self._write({key: (None, True)}, who)

    def _write(self, changes: dict, who) -> list[tuple]:
        self.invalidate()                               # "old" is what every worker applies now
        old = {k: self.value(k) for k in changes}
        had = set(self._stored())
        now = time.time()
        with self.g.store.tx(immediate=True) as conn:
            for key, (v, reset) in changes.items():
                if reset or v == self.default(key):     # the default is no override: it follows the environment
                    conn.execute("DELETE FROM settings WHERE key = ?", (key,))
                else:
                    conn.execute("INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?,?,?,?) "
                                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                                 "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                                 (key, json.dumps(v), now, who or None))
        self.invalidate()
        done = []
        for key, (_, reset) in changes.items():
            new = self.value(key)
            if new == old[key] and not (reset and key in had):
                continue                                # nothing changed: no event
            done.append((key, old[key], new))
            self._audit(key, old[key], new, who, reset)
        return done

    def _audit(self, key, old, new, who, reset):
        spec = SPECS[key]
        by = f"χειριστής «{who}»" if who else "ανοιχτή κονσόλα, χωρίς σύνδεση"
        what = "επαναφορά στην προεπιλογή, " if reset else ""
        self.g.audit.log("console", {"username": who or None}, action="setting", rule="runtime",
                         severity="high" if spec.weaker(new, old) else "info",
                         reason=f"Ρύθμιση «{key}»: {what}{_fmt(spec, old)} → {_fmt(spec, new)} ({by}).")


def _fmt(spec, v) -> str:
    if spec.type == "bool":
        return "ενεργό" if v else "ανενεργό"
    return f"{_num(v)} {spec.unit}" if spec.unit else str(_num(v))


# ---------------------------------------------------------------------------------------------- the proxy
def layer_enabled(get_guard) -> bool:
    """laocoon.enabled: LAOCOON_ENABLED unless the console switched it. A guard that cannot
    be built (or a store that cannot be read) leaves the start-up value, as before runtime settings existed."""
    default = config.enabled()
    try:
        rt = getattr(get_guard(), "runtime", None)
    except Exception:  # noqa: BLE001 — the passthrough must not depend on building the guard
        return default
    return rt.on("laocoon.enabled") if rt is not None else default


def register_runtime(app, get_guard, access, api_base="/laocoon/api"):
    """The settings API, behind `access` (web.ConsoleAccess: require() first in every route, who() = operator)."""
    from flask import abort, jsonify, request

    def guard_rt():
        return get_guard().runtime

    @app.get(api_base + "/settings", endpoint="runtime_settings")
    def runtime_settings():
        access.require()
        return jsonify(guard_rt().payload())

    @app.put(api_base + "/settings", endpoint="runtime_settings_put")
    def runtime_settings_put():
        who = access.require()
        rt = guard_rt()
        if locked():
            return jsonify(error=ERR_LOCKED), 409
        if (request.content_length or 0) > MAX_BODY:
            abort(413)
        body = request.get_json(silent=True)
        values = body.get("values") if isinstance(body, dict) else None
        if not isinstance(values, dict):
            return jsonify(error=ERR_BODY), 400
        try:
            rt.set_many(values, who)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        return jsonify(rt.payload())

    @app.delete(api_base + "/settings/<key>", endpoint="runtime_settings_delete")
    def runtime_settings_delete(key):
        who = access.require()
        rt = guard_rt()
        if locked():
            return jsonify(error=ERR_LOCKED), 409
        try:
            rt.reset(key, who)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        return jsonify(rt.payload())

"""Private-data placeholders (policy section `private_data`).

Declared personal data (AMKA, IBAN, phone, ...) never reaches the upstream model or a classifier backend: every
occurrence becomes a typed placeholder ⟦TYPE:id⟧ that is stable within one conversation. Only Laocoon maps a
placeholder back to the value, and only where the policy allows it: answers (table A) and tool arguments (table T).

Detection is deterministic: declared field names, regex + validator, and exact matches of values already collected.
Ids are truncated HMACs under a per-conversation key derived from LAOCOON_SECRET, never plain hashes; values found in
content written by others ("untrusted" bucket) get ids of their own, so such content cannot probe whether a guessed
value equals the user's. The classifier never sees placeholders either: it gets a constant, format-shaped dummy per
class (measured: placeholders raise injection scores on the local model, dummies score like raw text).

Everything here is pure computation; the only state is the optional encrypted vault (`pd_vault`) for values that must
outlive a request (field-only values that were re-hydrated into an answer).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field

from .classifier import normalize

B32 = "0123456789abcdefghjkmnpqrstvwxyz"              # Crockford base32, lower case
_B32_IN = str.maketrans("oil", "011")                 # what models confuse: o → 0, i/l → 1
ID_SHORT, ID_LONG = 6, 12
DEFAULT_SECRETS = {b"change-me-laocoon", b"change-me-odysseus", b""}
MIN_SECRET_BYTES = 32
EXACT_MIN = 6                                         # shorter collected values are only replaced in their own field

# ⟦TYPE:id⟧ and the forms models produce instead: [[TYPE:id]], [TYPE:id], spaces, any case
PLACEHOLDER_RE = re.compile(r"(?:⟦|\[\[?)\s*([A-Za-z][A-Za-z0-9_]{0,31})\s*:\s*([0-9A-Za-z]{12}|[0-9A-Za-z]{6})"
                            r"\s*(?:⟧|\]\]?)")
_URL_MARK = re.compile(r"://|^www\.|[^\w]www\.|mailto:|\]\(|href|src\s*=|<|[A-Za-z0-9-]+\.[A-Za-z]{2,}/", re.I)

ORIGIN_RANK = {"typed": 0, "own": 1, "app": 2, "untrusted": 2, "history": 3, "model": 4}   # whose surface wins
SELF_ORIGINS = {"typed", "own"}
WEAK_ORIGINS = {"history", "model"}

NOTE = ("\n\n[Values written as ⟦TYPE:id⟧ stand for private data that the application holds. Copy them exactly, "
        "brackets included, wherever the value is needed (answers and tool arguments). Never alter, guess, split, "
        "encode, translate or describe them.]\n")

REASON_UNKNOWN = ("Το όρισμα περιέχει αναφορά σε προσωπικό δεδομένο ({cls}) που δεν αντιστοιχεί σε στοιχείο αυτής της "
                  "συνομιλίας.")
REASON_URL = "Προσωπικό δεδομένο ({cls}) μέσα σε σύνδεσμο: δεν συμπληρώνεται ποτέ σε URL."
REASON_NEVER = "Το προσωπικό δεδομένο ({cls}) δεν επιτρέπεται σε ορίσματα ενεργειών."
REASON_SELF = "Επιτρέπεται να χρησιμοποιηθούν μόνο τα δικά σου στοιχεία ({cls})."
REASON_EXFIL = ("Η ενέργεια θα έστελνε προσωπικό δεδομένο ({cls}) σε τρίτον, αφού ο βοηθός διάβασε μη αξιόπιστο "
                "περιεχόμενο: μπλοκαρίστηκε.")
REASON_UNTRUSTED = ("Η ενέργεια χρησιμοποιεί {cls} που προέρχεται από μη αξιόπιστο περιεχόμενο. Επιβεβαίωσε ότι τη "
                    "ζήτησες.")
REASON_THIRD = "Η ενέργεια χρησιμοποιεί προσωπικό δεδομένο τρίτου ({cls}). Επιβεβαίωσε ότι τη ζήτησες."

ACTION_ORDER = {"allow": 0, "ask": 1, "deny": 2, "kill": 3}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ConfigError(ValueError):
    """`private_data` cannot be enabled as configured (weak secret, bad class, missing dependency)."""


# ---------------------------------------------------------------------- validators (built-in, by name)
def _digits(s) -> str:
    return re.sub(r"\D", "", str(s))


def v_date_ddmmyy(s) -> bool:
    """The first six digits are a calendar date DDMMYY (Greek AMKA)."""
    d = _digits(s)
    if len(d) < 6:
        return False
    dd, mm, yy = int(d[:2]), int(d[2:4]), int(d[4:6])
    for century in (1900, 2000):
        try:
            _dt.date(century + yy, mm, dd)
            return True
        except ValueError:
            pass
    return False


def v_luhn(s) -> bool:
    d = _digits(s)
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return bool(d) and total % 10 == 0


IBAN_LENGTHS = {"AD": 24, "AL": 28, "AT": 20, "BA": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22,
                "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GI": 23, "GR": 27, "HR": 21, "HU": 28,
                "IE": 22, "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "ME": 22, "MK": 19,
                "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "RS": 22, "SE": 24, "SI": 19, "SK": 24,
                "SM": 27, "TR": 26, "UA": 29}


def v_iban_shape(s) -> bool:
    """Known country, its length, two check digits; Greek IBANs are all digits after `GR`."""
    t = re.sub(r"\s", "", str(s)).upper()
    if IBAN_LENGTHS.get(t[:2]) != len(t) or not t[2:4].isdigit() or not t[4:].isalnum():
        return False
    return t[:2] != "GR" or t[2:].isdigit()


def v_iban_mod97(s) -> bool:
    t = re.sub(r"\s", "", str(s)).upper()
    if not v_iban_shape(t):
        return False
    return int("".join(str(int(c, 36)) for c in t[4:] + t[:4])) % 97 == 1


def _phone_national(s) -> str:
    d = _digits(s)
    if d.startswith("0030") and len(d) == 14:
        return d[4:]
    if d.startswith("30") and len(d) == 12:
        return d[2:]
    return d


def v_phone_gr(s) -> bool:
    """Greek numbers: 69x mobiles and 21x–28x landlines, 10 national digits (+30 / 0030 optional)."""
    d = _phone_national(s)
    return len(d) == 10 and (d.startswith("69") or d[:2] in {"21", "22", "23", "24", "25", "26", "27", "28"})


def v_afm_mod11(s) -> bool:
    """Greek tax number (ΑΦΜ): 9 digits, mod-11 check digit."""
    d = _digits(s)
    if len(d) != 9 or d == "000000000":
        return False
    return sum(int(d[i]) * 2 ** (8 - i) for i in range(8)) % 11 % 10 == int(d[8])


_GR2LAT = str.maketrans("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX")


def v_idcard_gr(s) -> bool:
    """Greek ID card (ΑΔΤ): one or two capitals that exist in both alphabets, then six digits."""
    letters = re.sub(r"[^A-ZΑ-Ω]", "", str(s)).translate(_GR2LAT)
    return bool(letters) and all(c in "ABEZHIKMNOPTYX" for c in letters)


VALIDATORS = {"date_ddmmyy": v_date_ddmmyy, "luhn": v_luhn, "iban_shape": v_iban_shape, "iban_mod97": v_iban_mod97,
              "phone_gr": v_phone_gr, "afm_mod11": v_afm_mod11, "idcard_gr": v_idcard_gr}


# ---------------------------------------------------------------------- normalisers (the HMAC input)
def _n_text(s) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(s)).casefold().split())


def _normaliser(name):
    if not name or name == "text":
        return _n_text
    if name == "digits":
        return _digits
    if name.startswith("digits:"):
        width = int(name.split(":", 1)[1])
        return lambda s: _digits(s).zfill(width) if _digits(s) else ""
    if name == "upper_nospace":
        return lambda s: re.sub(r"\s", "", unicodedata.normalize("NFKC", str(s))).upper()
    if name == "phone_gr":
        return _phone_national
    if name == "idcard_gr":
        return lambda s: re.sub(r"[\s-]", "", unicodedata.normalize("NFKC", str(s))).upper().translate(_GR2LAT)
    if name == "casefold":
        return lambda s: unicodedata.normalize("NFKC", str(s)).strip().casefold()
    raise ConfigError(f"unknown normaliser {name!r}")


# ---------------------------------------------------------------------- keys
def _hkdf(ikm: bytes, salt: bytes, info: bytes, length=32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def _b32(digest: bytes, n=ID_LONG) -> str:
    v = int.from_bytes(digest[:8], "big")
    return "".join(B32[(v >> (64 - 5 * (i + 1))) & 31] for i in range(n))


def keyed_conversation_key(secret: bytes, principal_id, first_user_message: str) -> str:
    """The proxy's conversation key when private_data is on: keyed, so a short first message (an AMKA) cannot be
    brute-forced from the audit log or the canaries table."""
    msg = f"conv|{principal_id}|{first_user_message}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:24]


# ---------------------------------------------------------------------- policy
@dataclass
class PDClass:
    name: str
    order: int
    pattern: re.Pattern | None
    validate: object | None
    fields: frozenset
    match: str                      # pattern | field | exact
    action: str                     # placeholder | mask | drop
    answer: object                  # shown | self | never | {role: mode}
    tool_args: str                  # table | self | never
    normalise: object
    dummy: str

    def answer_mode(self, role) -> str:
        if isinstance(self.answer, dict):
            return str(self.answer.get(role, self.answer.get("*", "shown")))
        return str(self.answer)


DEFAULT_DUMMIES = {"digits:11": "00000000000", "digits": "000000000", "upper_nospace": "GR0000000000000000000000000",
                   "phone_gr": "+30 690 000 0000", "idcard_gr": "XX 000000", "casefold": "user@example.org"}


class PrivatePolicy:
    """The compiled `private_data` section. One per Guard."""

    def __init__(self, data: dict, *, secret: bytes, honey_values=(), honey_visible_to=(), store=None,
                 previous_secret: bytes | None = None):
        if not isinstance(data, dict):
            raise ConfigError("private_data must be a mapping")
        secret = secret if isinstance(secret, bytes) else str(secret or "").encode()
        if secret in DEFAULT_SECRETS or len(secret) < MIN_SECRET_BYTES:
            raise ConfigError("private_data needs LAOCOON_SECRET set to a random value of at least "
                              f"{MIN_SECRET_BYTES} bytes (the default or a short secret would let anyone recompute "
                              "the placeholder ids)")
        self.root = _hkdf(secret, b"laocoon/pd", b"v1")
        self.log_key = hmac.new(self.root, b"log", hashlib.sha256).digest()
        self.store = store
        self.ttl = int(data.get("ttl", 86400))
        self.id_length = int(data.get("id_length", ID_SHORT))
        if self.id_length not in (ID_SHORT, ID_LONG):
            raise ConfigError("private_data.id_length must be 6 or 12")
        self.classifier_view = str(data.get("classifier_view", "dummy"))
        self.subject_args = {str(k): (str(v) if v else None) for k, v in (data.get("subject_args") or {}).items()}
        self.honey_visible_to = {str(r) for r in honey_visible_to or ()}
        self.classes: list[PDClass] = []
        for i, (name, spec) in enumerate((data.get("classes") or {}).items()):
            self.classes.append(self._class(i, str(name), spec or {}))
        if not self.classes:
            raise ConfigError("private_data.classes is empty")
        self.by_name = {c.name: c for c in self.classes}
        self.field_index = {}
        self._field_cache = {}
        for c in self.classes:
            for f in c.fields:
                self.field_index.setdefault(f, c)
        self.pattern_classes = [c for c in self.classes if c.pattern is not None]
        self.exact_classes = [c for c in self.classes if c.match == "exact"]
        self.any_pattern = (re.compile("|".join(f"(?:{c.pattern.pattern})" for c in self.pattern_classes))
                            if self.pattern_classes else None)
        # honey values: exact members of the first class whose pattern matches them (validators bypassed)
        self.honey = {}                                       # (class, norm) -> surface
        for v in honey_values or ():
            v = str(v)
            for c in self.pattern_classes:
                if c.pattern.fullmatch(v.strip()):
                    self.honey[(c.name, c.normalise(v))] = v
                    break
        self.cipher = _Cipher(_hkdf(secret, b"laocoon/pd", b"enc|v1"),
                              _hkdf(previous_secret, b"laocoon/pd", b"enc|v1") if previous_secret else None)
        self.honey_on = lambda: True     # the Guard binds it to the console's `canary.honey` (rules T1, A3, streams)

    def _class(self, order, name, spec) -> PDClass:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", name):
            raise ConfigError(f"private_data class name {name!r}: letters, digits and _ only")
        pattern = spec.get("pattern")
        try:
            rx = re.compile(pattern) if pattern else None
        except re.error as e:
            raise ConfigError(f"private_data.classes.{name}.pattern: {e}") from e
        vname = spec.get("validate")
        if vname and vname not in VALIDATORS:
            raise ConfigError(f"private_data.classes.{name}.validate: unknown validator {vname!r}")
        fields = frozenset(str(f).lower() for f in spec.get("fields") or [])
        if rx is None and not fields:
            raise ConfigError(f"private_data.classes.{name}: needs a pattern or fields")
        match = spec.get("match") or ("pattern" if rx is not None else "field")
        action = spec.get("action", "placeholder")
        answer = spec.get("answer", "shown")
        tool_args = spec.get("tool_args", "table")
        if match not in ("pattern", "field", "exact") or action not in ("placeholder", "mask", "drop") \
                or tool_args not in ("table", "self", "never") \
                or not (isinstance(answer, dict) or answer in ("shown", "self", "never")):
            raise ConfigError(f"private_data.classes.{name}: bad match/action/answer/tool_args value")
        norm_name = spec.get("normalise") or "text"
        dummy = str(spec.get("dummy") or DEFAULT_DUMMIES.get(norm_name) or f"[{name.lower()}]")
        return PDClass(name, order, rx, VALIDATORS.get(vname), fields, match, action, answer, tool_args,
                       _normaliser(norm_name), dummy)

    # ------------------------------------------------------------------ keys and contexts
    def conversation_key(self, conversation_key) -> bytes:
        return hmac.new(self.root, b"conv|" + str(conversation_key).encode(), hashlib.sha256).digest()

    def context(self, conversation_key, principal=None) -> "PrivateContext":
        ctx = PrivateContext(self, self.conversation_key(conversation_key), principal, str(conversation_key))
        ctx.load_vault()
        return ctx

    def log_context(self) -> "PrivateContext":
        return PrivateContext(self, self.log_key, None, None)

    def field_class(self, key) -> PDClass | None:
        if not isinstance(key, str):
            return None
        try:
            return self._field_cache[key]
        except KeyError:
            c = self._field_cache[key] = self.field_index.get(key.lower())
            return c

    # ------------------------------------------------------------------ stateless surfaces
    def redact_global(self, obj):
        """Audit, flags and stored previews outside a turn: field names + patterns, ids under the log key."""
        return self.log_context().tokenise_obj(obj, origin="history")

    def scrub(self, text: str) -> tuple[str, int]:
        """The classifier's last line: placeholders → class dummies; any validated value still in the text → dummy
        too, counted (it should never happen: the turn tokenises first). -> (text, raw values found)."""
        if not isinstance(text, str) or not text:
            return text, 0
        ctx = self.log_context()
        hits = ctx.hits(text)
        if hits:
            out, last = [], 0
            for s, e, c, _t in hits:
                out.append(text[last:s] + c.dummy)
                last = e
            text = "".join(out) + text[last:]
        if self.classifier_view == "placeholder":
            return text, len(hits)

        def dummy(m):
            c = self.by_name.get(m.group(1)) or self.by_name.get(m.group(1).upper())
            return c.dummy if c is not None else "[…]"
        return PLACEHOLDER_RE.sub(dummy, text), len(hits)

    def scrub_obj(self, obj):
        """scrub() over every string of a classifier state. -> (obj, raw values found)."""
        found = 0

        def walk(o):
            nonlocal found
            if isinstance(o, str):
                t, n = self.scrub(o)
                found += n
                return t
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            if isinstance(o, list):
                return [walk(v) for v in o]
            return o
        return walk(obj), found


# ---------------------------------------------------------------------- per request / turn
@dataclass
class Entry:
    cls: PDClass
    bucket: str                     # t (trusted: the user, the app, Laocoon's output) | u (content written by others)
    norm: str
    surface: str
    id12: str
    origins: set = field(default_factory=set)
    subjects: set = field(default_factory=set)
    honey: bool = False
    rank: int = 9

    @property
    def id6(self) -> str:
        return self.id12[:ID_SHORT]


@dataclass
class Use:
    """One placeholder found in tool arguments."""
    cls: str
    entry: Entry | None
    in_url: bool


class PrivateContext:
    """The value ↔ placeholder map of one request. Deterministic: the same key and the same
    content give the same ids in every worker."""

    def __init__(self, policy: PrivatePolicy, key: bytes, principal=None, conversation_key=None):
        self.p = policy
        self.key = key
        self.principal = principal or {}
        self.uid = self.principal.get("id")
        self.role = self.principal.get("role")
        self.conversation_key = conversation_key
        self.entries: dict[tuple, Entry] = {}
        self.short: dict[tuple, list] = {}
        self.long: dict[tuple, Entry] = {}
        self.exact: dict[str, PDClass] = {}
        self._exact_rx = None
        self._exact_dirty = False
        self._frozen = 0                          # >0 while one tokenise_obj pass runs: compile the exact set once
        self._fast = {}                           # (class, bucket, raw value) → entry: no normalise/HMAC twice
        self._log = None
        self.forged = 0
        self.shown_field_only = []               # field-only entries re-hydrated into an answer (vault)
        self._vault_rows = []                    # written in one transaction by flush_vault()
        for (cname, norm), surface in policy.honey.items():
            self.add(policy.by_name[cname], surface, "app")

    # ------------------------------------------------------------------ entries
    def _mint(self, cls, bucket, norm) -> str:
        d = hmac.new(self.key, f"{cls.name}|{bucket}|{norm}".encode(), hashlib.sha256).digest()
        return _b32(d)

    def add(self, cls: PDClass, value, origin, bucket="t", subject=None) -> Entry | None:
        number = isinstance(value, (int, float)) and not isinstance(value, bool)
        fast = (cls.name, bucket, value if not number else ("#", value))
        e = self._fast.get(fast) if origin != "model" else None
        if e is None:
            norm = cls.normalise(str(value))
            if not norm:
                return None
            # a JSON number (an AMKA stored as an integer) is re-hydrated normalised: the leading zero comes back
            surface = norm if number else str(value)
            if origin == "model" and (cls.name, "t", norm) not in self.entries \
                    and (cls.name, "u", norm) in self.entries:
                bucket = "u"                                   # the model copied a value from untrusted content
            k = (cls.name, bucket, norm)
            e = self.entries.get(k)
            if e is None:
                e = Entry(cls, bucket, norm, surface, self._mint(cls, bucket, norm))
                e.honey = (cls.name, norm) in self.p.honey
                self.entries[k] = e
                self.short.setdefault((cls.name, e.id6), []).append(e)
                self.long[(cls.name, e.id12)] = e
            self._register_exact(e, surface)
            if origin != "model":
                self._fast[fast] = e
        else:
            surface = e.norm if number else str(value)
        if origin not in e.origins:
            e.origins.add(origin)
        if subject is not None:
            e.subjects.add(int(subject) if isinstance(subject, int) or str(subject).isdigit() else subject)
        r = ORIGIN_RANK.get(origin, 9)
        if r < e.rank:
            e.rank, e.surface = r, surface
        return e

    def _register_exact(self, e, surface):
        cls = e.cls
        if len(surface) >= EXACT_MIN and surface not in self.exact and (
                e.honey or cls.match == "exact"
                or (cls.match == "pattern" and not self._found_by_pattern(cls, surface))):
            self.exact[surface] = cls             # matched verbatim elsewhere (the pattern alone would miss it)
            self._exact_dirty = True

    @staticmethod
    def _found_by_pattern(cls, surface) -> bool:
        return bool(cls.pattern.fullmatch(surface)) and (cls.validate is None or cls.validate(surface))

    def render(self, e: Entry) -> str:
        if self.p.id_length == ID_LONG or len(self.short.get((e.cls.name, e.id6), ())) > 1:
            return f"⟦{e.cls.name}:{e.id12}⟧"
        return f"⟦{e.cls.name}:{e.id6}⟧"

    def lookup(self, cls_name, pid) -> Entry | None:
        cls = self.p.by_name.get(cls_name) or self.p.by_name.get(str(cls_name).upper())
        if cls is None:
            return None
        pid = str(pid).lower().translate(_B32_IN)
        if len(pid) == ID_LONG:
            return self.long.get((cls.name, pid))
        found = self.short.get((cls.name, pid)) or []
        return found[0] if len(found) == 1 else None          # ambiguous → unresolved (fail closed)

    def effective_origin(self, e: Entry) -> str:
        if e.bucket == "u":
            return "untrusted"
        strong = e.origins - WEAK_ORIGINS
        if "app" in strong or "untrusted" in strong:
            return "app"
        if strong & SELF_ORIGINS:
            return "self"
        return "history"

    # ------------------------------------------------------------------ detection
    def _exact(self):
        """The exact-value index: literals by their first word (no regex to compile per request)."""
        if self._exact_dirty and not self._frozen:
            index, odd = {}, []
            for lit in sorted(self.exact, key=len, reverse=True):
                m = _WORD.match(lit)
                (index.setdefault(m.group(0), []) if m else odd).append(lit)
            self._exact_rx = (index, odd) if self.exact else None
            self._exact_dirty = False
        return self._exact_rx

    def _exact_find(self, s, idx):
        index, odd = idx
        out, end = [], -1
        for m in _WORD.finditer(s):
            if m.start() < end:
                continue
            for lit in index.get(m.group(0), ()):
                stop = m.start() + len(lit)
                if s.startswith(lit, m.start()) and not (stop < len(s) and _is_word(s[stop])):
                    out.append((m.start(), stop, self.exact[lit], lit))
                    end = stop
                    break
        for lit in odd:                                        # literals that start with a symbol (rare)
            i = s.find(lit)
            while i != -1:
                stop = i + len(lit)
                if not (i > 0 and _is_word(s[i - 1])) and not (stop < len(s) and _is_word(s[stop])):
                    out.append((i, stop, self.exact[lit], lit))
                i = s.find(lit, stop)
        return out

    def hits(self, s: str) -> list:
        """Non-overlapping (start, end, class, text) for validated pattern hits and exact values, placeholders
        excluded. Overlaps: validators first (failed hits never compete), then the longest, then class order."""
        if not s or len(s) < 6:                                # no declared value is shorter
            return []
        cands = []
        if self.p.any_pattern is not None and self.p.any_pattern.search(s):
            for c in self.p.pattern_classes:
                for m in c.pattern.finditer(s):
                    t = m.group(0)
                    if c.validate is None or c.validate(t) or (c.name, c.normalise(t)) in self.p.honey:
                        cands.append((m.start(), m.end(), c, t))
        idx = self._exact()
        if idx is not None:
            cands += self._exact_find(s, idx)
        if not cands:
            return []
        taken = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(s)]
        out = []
        for c in sorted(cands, key=lambda x: (-(x[1] - x[0]), x[2].order, x[0])):
            if all(c[1] <= a or c[0] >= b for a, b in taken):
                taken.append((c[0], c[1]))
                out.append(c)
        return sorted(out, key=lambda x: x[0])

    def neutralise(self, s: str) -> str:
        """Placeholder-shaped text written by someone else loses its shape (it could never resolve anyway)."""
        if "⟦" not in s and "[" not in s:
            return s
        out, n = PLACEHOLDER_RE.subn(lambda m: f"‹{m.group(1)} {m.group(2)}›", s)
        self.forged += n
        return out

    def tokenise_text(self, s, *, origin="history", bucket="t", subject=None, neutralise=False):
        if not isinstance(s, str) or not s:
            return s
        if neutralise:
            s = self.neutralise(s)
        hits = self.hits(s)
        if not s.isascii():                                    # ASCII cannot hide anything normalize() would reveal
            n = normalize(s)
            if n != s:                                         # a value hidden by tag / fullwidth / zero-width chars
                nh = self.hits(n)
                if len(nh) > len(hits):
                    s, hits = n, nh
        if not hits:
            return s
        out, last = [], 0
        for start, end, cls, t in hits:
            e = self.add(cls, t, origin, bucket, subject)
            out.append(s[last:start] + (self.render(e) if e is not None and cls.action == "placeholder"
                                        else _mask(t) if cls.action == "mask" else ""))
            last = end
        return "".join(out) + s[last:]

    def field_value(self, cls, v, *, origin, bucket="t", subject=None):
        if isinstance(v, str) and ("⟦" in v or "[" in v) and PLACEHOLDER_RE.fullmatch(v.strip()):
            return v
        if cls.action == "mask":
            return _mask(v)
        e = self.add(cls, v, origin, bucket, subject)
        return self.render(e) if e is not None else v

    def tokenise_obj(self, obj, *, origin="history", bucket="t", subject=None, neutralise=False, rows=None):
        """Placeholder form of a JSON-like value. JSON keys are never touched; a declared field's whole value becomes
        a placeholder; every other string (and number) is scanned. `rows` = (ref_of(dict, ref), untrusted(ref),
        subject_of(dict), root_ref) for tool results: rows written by others go to the untrusted bucket, and
        origin "result" becomes own/app by the row's data subject. Two walks: the declared fields first (so a
        value is recognised anywhere in the same object), then the replacement, with the exact matcher compiled
        once in between."""
        kw = dict(origin=origin, bucket=bucket, subject=subject, neutralise=neutralise, rows=rows)
        if self._frozen:
            return self._tok(obj, **kw)
        if isinstance(obj, (dict, list)) and self.p.exact_classes:
            self._tok(obj, collect=True, **kw)
        self._exact()
        self._frozen += 1
        try:
            return self._tok(obj, **kw)
        finally:
            self._frozen -= 1

    def _tok(self, obj, *, origin, bucket, subject, neutralise, rows, collect=False, _ref=None):
        if isinstance(obj, dict):
            ref, sub = _ref, subject
            if rows is not None:
                ref = rows[0](obj, ref)
                s2 = rows[2](obj)
                sub = s2 if s2 is not None else sub
            b, o = bucket, origin
            if rows is not None and rows[1](ref):
                b, o = "u", "untrusted"
            elif origin == "result":
                o = "own" if sub is not None and self.uid is not None and str(sub) == str(self.uid) else "app"
            out = {}
            for k, v in obj.items():
                c = self.p.field_class(k)
                if c is not None and not isinstance(v, (dict, list)) and v not in (None, "") \
                        and not isinstance(v, bool):
                    if c.action == "drop":
                        continue
                    if collect:                    # pass (a): only values matched verbatim elsewhere matter here
                        if c.match == "exact" and c.action == "placeholder" \
                                and not (isinstance(v, str) and "⟦" in v and PLACEHOLDER_RE.fullmatch(v)):
                            self.add(c, v, o, b, sub)
                        continue
                    out[k] = self.field_value(c, v, origin=o, bucket=b, subject=sub)
                elif k == "_laocoon":
                    out[k] = v
                else:
                    out[k] = self._tok(v, origin=origin, bucket=bucket, subject=sub, neutralise=neutralise,
                                       rows=rows, collect=collect, _ref=ref)
            return out
        if isinstance(obj, list):
            return [self._tok(v, origin=origin, bucket=bucket, subject=subject, neutralise=neutralise,
                              rows=rows, collect=collect, _ref=_ref) for v in obj]
        if collect:
            return obj
        b, o = bucket, origin
        if rows is not None and rows[1](_ref if _ref is not None else rows[3]):
            b, o = "u", "untrusted"
        elif origin == "result":
            o = "own" if subject is not None and str(subject) == str(self.uid) else "app"
        if isinstance(obj, str):
            return self.tokenise_text(obj, origin=o, bucket=b, subject=subject, neutralise=neutralise)
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            s = str(obj)
            t = self.tokenise_text(s, origin=o, bucket=b, subject=subject)
            return obj if t == s else t
        return obj

    def collect_text(self, s, origin, bucket="t", subject=None):
        if isinstance(s, str) and s:
            self.tokenise_text(s, origin=origin, bucket=bucket, subject=subject)

    # ------------------------------------------------------------------ placeholders in text
    def placeholders(self, s):
        """[(match, entry | None)] for every placeholder in s."""
        if not isinstance(s, str) or ("⟦" not in s and "[" not in s):
            return []
        return [(m, self.lookup(m.group(1), m.group(2))) for m in PLACEHOLDER_RE.finditer(s)]

    def honey_in(self, obj) -> bool:
        if not self.p.honey_on():
            return False
        return any(e is not None and e.honey for s in _strings(obj) for _m, e in self.placeholders(s))

    def resolve_all(self, s):
        """Internal: every known placeholder → its value (unconditionally; never shown to anyone)."""
        if not isinstance(s, str):
            return s
        return PLACEHOLDER_RE.sub(lambda m: (lambda e: e.surface if e is not None else m.group(0))(
            self.lookup(m.group(1), m.group(2))), s)

    def rehydrate_text(self, s, *, prefix=""):
        """Table A: the answer for the principal. Rows A1 (URL context), A2 (unknown), A3 (honey), A4 (class
        rule), A5 (re-hydrate)."""
        if not isinstance(s, str) or ("⟦" not in s and "[" not in s):
            return s

        def repl(m):
            e = self.lookup(m.group(1), m.group(2))
            if e is None or url_context(prefix + s, len(prefix) + m.start(), len(prefix) + m.end()):
                return m.group(0)
            if e.honey and self.role not in self.p.honey_visible_to and self.p.honey_on():
                return m.group(0)
            mode = e.cls.answer_mode(self.role)
            if mode == "never" or (mode == "self" and self.effective_origin(e) != "self"):
                return m.group(0)
            if e.cls.match != "pattern" and self.conversation_key is not None:
                self.shown_field_only.append(e)
            return e.surface
        out = PLACEHOLDER_RE.sub(repl, s)
        if self.shown_field_only:
            for e in self.shown_field_only:
                self._vault_put(e, self._best_origin(e), next(iter(e.subjects), None))
            self.shown_field_only = []
        self.flush_vault()
        return out

    def rehydrate_obj(self, obj):
        if isinstance(obj, str):
            return self.rehydrate_text(obj)
        if isinstance(obj, dict):
            return {k: self.rehydrate_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.rehydrate_obj(v) for v in obj]
        return obj

    # ------------------------------------------------------------------ tool arguments (table T)
    def resolve_args(self, args) -> tuple[dict, list]:
        """-> (arguments with every known placeholder replaced by its value, [Use]). Placeholders inside a URL and
        unknown ones stay as text; decide_args() denies the call for them."""
        uses = []

        def walk(o):
            if isinstance(o, str):
                found = self.placeholders(o)
                if not found:
                    return o
                for m, e in found:
                    uses.append(Use(m.group(1).upper(), e, url_context(o, m.start(), m.end())))
                return PLACEHOLDER_RE.sub(lambda m: (lambda e: e.surface if e is not None and not url_context(
                    o, m.start(), m.end()) else m.group(0))(self.lookup(m.group(1), m.group(2))), o)
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            if isinstance(o, list):
                return [walk(v) for v in o]
            return o
        return walk(dict(args or {})), uses

    def decide_args(self, tool, nargs, uses, *, effect, read_untrusted) -> tuple[str, str, str, str] | None:
        """Table T, strictest outcome over every placeholder. -> (action, severity, reason, row) or None."""
        if not uses:
            return None
        target_arg = self.p.subject_args.get(tool)
        target = (nargs or {}).get(target_arg) if target_arg else None
        target = int(target) if isinstance(target, int) or (isinstance(target, str) and target.isdigit()) else None
        best = None
        for u in uses:
            e = u.entry
            cname = e.cls.name if e is not None else u.cls
            if e is None:
                r = ("deny", "low", REASON_UNKNOWN, "T2")
            elif e.honey and self.p.honey_on():
                r = ("kill", "critical", "", "T1")
            elif u.in_url:
                r = ("deny", "high", REASON_URL, "T3")
            elif e.cls.tool_args == "never":
                r = ("deny", "medium", REASON_NEVER, "T4")
            elif effect == "read":
                r = ("allow", "info", "", "T5")
            else:
                o = self.effective_origin(e)
                to_subject = target is not None and e.subjects == {target}
                if e.cls.tool_args == "self" and o != "self":
                    r = ("deny", "medium", REASON_SELF, "T4")
                elif o == "untrusted":
                    r = ("ask", "high", REASON_UNTRUSTED, "T6")
                elif effect == "write":
                    if o == "self":
                        r = ("allow", "info", "", "T7")
                    elif o == "app" and to_subject:
                        r = ("allow", "info", "", "T12")
                    else:
                        r = ("ask", "high", REASON_THIRD, "T11")
                elif to_subject:
                    r = ("allow", "info", "", "T8")
                elif read_untrusted:
                    r = ("deny", "medium", REASON_EXFIL, "T9")
                elif o == "self":
                    r = ("allow", "info", "", "T10")
                else:
                    r = ("ask", "high", REASON_THIRD, "T11")
            r = (r[0], r[1], r[2].format(cls=cname), r[3])
            if best is None or (ACTION_ORDER[r[0]], SEVERITY_ORDER[r[1]]) > (ACTION_ORDER[best[0]],
                                                                            SEVERITY_ORDER[best[1]]):
                best = r
        return best

    # ------------------------------------------------------------------ previews and the audit log
    def tokenise_preview(self, preview):
        """Approval card rows: a row whose label is a declared field is that field's value (both sides of `→`)."""
        if not isinstance(preview, dict):
            return self.tokenise_obj(preview, origin="app")
        rows = []
        for row in preview.get("rows") or []:
            if isinstance(row, (list, tuple)) and len(row) == 2:
                label, value = row
                c = self.p.field_class(label)
                if c is not None and isinstance(value, str) and c.action != "drop":
                    parts = [p.strip() for p in value.split("→")]
                    value = " → ".join(p if p in ("—", "***", "") else self.field_value(c, p, origin="app")
                                       for p in parts)
                else:
                    value = self.tokenise_obj(value, origin="app")
                rows.append([label, value])
            else:
                rows.append(self.tokenise_obj(row, origin="app"))
        return {**preview, "title": self.tokenise_obj(preview.get("title"), origin="app"), "rows": rows}

    def redact(self, obj):
        """For anything stored (audit, flags, pending previews): known placeholders → values → placeholders under the
        log key, so every stored id is in one space across conversations."""
        if self._log is None:
            self._log = self.p.log_context()
        if len(self._log.exact) < len(self.exact) + len(self.p.honey):
            self._log.exact.update(self.exact)
            self._log._exact_dirty = True

        def internal(o):
            if isinstance(o, str):
                return self.resolve_all(o)
            if isinstance(o, dict):
                return {k: internal(v) for k, v in o.items()}
            if isinstance(o, list):
                return [internal(v) for v in o]
            return o
        return self._log.tokenise_obj(internal(obj), origin="history")

    # ------------------------------------------------------------------ vault (encrypted, per conversation)
    def _best_origin(self, e):
        strong = sorted(e.origins - WEAK_ORIGINS, key=lambda o: ORIGIN_RANK.get(o, 9))
        return strong[0] if strong else "history"

    def _vault_put(self, e, origin, subject):
        if self.p.store is None or self.conversation_key is None or e.honey:
            return
        now = time.time()
        self._vault_rows.append((self.conversation_key, e.cls.name, e.id12, e.bucket,
                                 self.p.cipher.seal(e.surface, f"{self.conversation_key}|{e.cls.name}|{e.id12}"),
                                 origin, str(subject) if subject is not None else None, self.uid, now,
                                 now + self.p.ttl))

    def flush_vault(self):
        rows, self._vault_rows = self._vault_rows, []
        if not rows or self.p.store is None:
            return
        try:
            with self.p.store.tx() as conn:
                conn.executemany("INSERT OR IGNORE INTO pd_vault (conversation_key, cls, id, bucket, enc_value, "
                                 "origin, subject, user_id, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                 rows)
        except Exception:                                    # the vault is a convenience: never break a request
            pass

    def load_vault(self):
        store = self.p.store
        if store is None or self.conversation_key is None:
            return
        try:
            rows = store.query("SELECT * FROM pd_vault WHERE conversation_key = ? AND expires_at > ?",
                               (self.conversation_key, time.time()))
        except Exception:
            return
        for r in rows:
            cls = self.p.by_name.get(r["cls"])
            surface = self.p.cipher.open(r["enc_value"], f"{self.conversation_key}|{r['cls']}|{r['id']}")
            if cls is None or surface is None:
                continue
            subject = r["subject"]
            self.add(cls, surface, r["origin"] or "history", r["bucket"] or "t",
                     int(subject) if subject and str(subject).isdigit() else subject)


def assert_clean(ctx: PrivateContext, obj) -> tuple[object, int]:
    """The proxy's last line before the upstream call: any declared value still present (a bug elsewhere) is replaced
    now and counted. -> (obj, values found)."""
    found = sum(len(ctx.hits(s)) for s in _strings(obj))
    return (ctx.tokenise_obj(obj, origin="history"), found) if found else (obj, 0)


def erase(store, *, user_id=None, conversation_key=None) -> int:
    """Delete vault rows of a user or a conversation (the right to erasure). -> rows deleted."""
    if user_id is None and conversation_key is None:
        return 0
    sql, args = "DELETE FROM pd_vault WHERE ", []
    if user_id is not None:
        sql += "user_id = ?"
        args.append(int(user_id))
    if conversation_key is not None:
        sql += (" AND " if args else "") + "conversation_key = ?"
        args.append(str(conversation_key))
    _, n = store.execute(sql, args)
    return n


def purge(store) -> int:
    _, n = store.execute("DELETE FROM pd_vault WHERE expires_at < ?", (time.time(),))
    return n


# ---------------------------------------------------------------------- encryption at rest (AES-GCM)
class _Cipher:
    def __init__(self, key: bytes, previous: bytes | None = None):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:                              # pragma: no cover - dependency is in requirements.txt
            raise ConfigError("private_data needs the `cryptography` package (pip install cryptography)") from e
        self._aes = [AESGCM(key)] + ([AESGCM(previous)] if previous else [])

    def seal(self, text: str, aad: str) -> str:
        nonce = os.urandom(12)
        return (nonce + self._aes[0].encrypt(nonce, text.encode(), aad.encode())).hex()

    def open(self, blob, aad: str) -> str | None:
        try:
            raw = bytes.fromhex(blob)
        except (TypeError, ValueError):
            return None
        for aes in self._aes:                                 # the current key, then the previous one (rotation)
            try:
                return aes.decrypt(raw[:12], raw[12:], aad.encode()).decode()
            except Exception:
                continue
        return None


# ---------------------------------------------------------------------- helpers
def url_context(s: str, start: int, end: int) -> bool:
    """Row A1/T3: is s[start:end] part of a link, image, autolink, HTML tag or URL? Then it is never re-hydrated."""
    left = max(s.rfind(" ", 0, start), s.rfind("\n", 0, start), s.rfind("\t", 0, start)) + 1
    right_ws = [i for i in (s.find(" ", end), s.find("\n", end), s.find("\t", end)) if i != -1]
    run = s[left:min(right_ws) if right_ws else len(s)]
    if _URL_MARK.search(run):
        return True
    line_start = s.rfind("\n", 0, start) + 1
    before = s[line_start:start]
    i = before.rfind("](")
    if i != -1 and ")" not in before[i + 2:]:
        return True                                           # inside a markdown link target with spaces
    j = before.rfind("<")
    if j != -1 and ">" not in before[j:]:
        return True                                           # inside an HTML tag or <autolink>
    return bool(re.match(r"\s*\[[^\]]*\]:", s[line_start:]))  # a reference definition line


_WORD = re.compile(r"\w+")


def _is_word(ch) -> bool:
    return ch.isalnum() or ch == "_"


def _mask(v) -> str:
    s = str(v)
    return "***" + s[-2:] if len(s) > 4 else "***"


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


def text_of(content):
    """OpenAI message content as text (string or a list of parts)."""
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


def map_content(content, fn):
    """Apply fn to the text of an OpenAI message content (string or parts), keeping its shape."""
    if isinstance(content, list):
        return [dict(p, text=fn(p["text"])) if isinstance(p, dict) and isinstance(p.get("text"), str) else p
                for p in content]
    return fn(content) if isinstance(content, str) else content


def tokenise_arguments(ctx: PrivateContext, arguments, origin="history"):
    """A tool call's JSON `arguments` string: values replaced, keys untouched; unparseable → as text."""
    if not isinstance(arguments, str) or not arguments:
        return arguments
    try:
        parsed = json.loads(arguments)
    except ValueError:
        return ctx.tokenise_text(arguments, origin=origin)
    return json.dumps(ctx.tokenise_obj(parsed, origin=origin), ensure_ascii=False)

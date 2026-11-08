"""⑥ Attack memory (opt-in): attacks that a deterministic layer or a person confirmed are remembered, so that a repeat
or a variant is caught at the first checkpoint that sees it.

    learn   a tripwire fired (the conversation canary or a honey record left in an answer or a tool argument), the user
            rejected an action proposed after the agent read untrusted content, or the policy denied a call. The text
            that caused it is attributed: the content that names the tool or carries the call's arguments, or the
            user's own message when nothing untrusted was read. Only a confident attribution of a configured signal
            is confirmed on its own (LAOCOON_MEMORY_AUTOCONFIRM, default: the tripwires); everything else waits
            for an admin as a candidate.
    match   G1 (the user's message) and G2 (tool results) compare the text with every
            confirmed attack: character 5-grams of a normalised, redacted form (hidden characters decoded, accents,
            case and punctuation dropped, e-mail addresses / URLs / IBANs / long numbers replaced by placeholders,
            private_data placeholders ⟦TYPE:id⟧ reduced to their type),
            scored by containment. The same payload with another recipient, student id, amount or casing matches;
            a rewording, a translation or a new template does not (see DOC for the measured limits).
    act     a match is a classifier score (class `instruction_injection` unless the attack says otherwise) and goes
            through the guard policy like any other score, so it can only make a decision stricter: G1 blocks,
            G2 quarantines (the model never sees the text). A weaker match asks for review.

Statuses: pending (waits for the user's answer to the approval it is tied to) -> confirmed | candidate (waits for an
admin) -> confirmed | rejected (an admin said it is not an attack: it is not learned again while the row lives). The
stored text is redacted. Nothing here ever raises into a decision: a broken memory is an empty memory.

Expiry (LAOCOON_MEMORY_TTL_DAYS, default 90, 0 = never): an attack that has not matched for that long, a candidate
nobody reviewed and an admin's rejection are deleted (an hourly sweep); a pending row goes after an hour. What is
forgotten can be learned again.

Modes (LAOCOON_MEMORY): off (default) | on (learn + act) | match (act only, learn nothing: e.g. an imported memory).

CLI:  python -m laocoon memory --db PATH [--ttl-days N] {stats,expire,list,show,confirm,reject,delete,add,export,import}
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import sys
import threading
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass

from .classifier import normalize
from .private import PLACEHOLDER_RE
from .store import Store

MODES = ("on", "match")
OFF_NAMES = ("", "off", "none", "false", "0", "no", "disabled")
STATUSES = ("pending", "candidate", "confirmed", "rejected")
KINDS = ("input", "content")
STRONG = ("strong", "direct")             # attributions good enough to confirm without an admin
TRIPWIRES = ("canary", "honey")
DEFAULT_LABEL = "instruction_injection"
DEFAULT_POINTS = ("G1", "G2")
RETIRED_POINTS = ("G4",)  # write-time scanning left with the in-app SDK: accepted in LAOCOON_MEMORY_POINTS, ignored
DEFAULT_AUTOCONFIRM = ("canary", "honey")
POINT_KINDS = {"G1": ("input",), "G2": ("input", "content")}

NGRAM = 5
MIN_GRAMS = 24            # shorter texts are neither learned nor matched (about 28 characters)
MIN_SHARED = 40           # grams a text must share with an attack before the ratio counts
REVERSE_MIN = 60          # a text at least this long that lies inside a known attack also matches
MAX_TEXT = 2000           # characters kept per attack
MAX_INPUT = 200_000       # characters of a text that are compared
CORE_CHARS = 1500         # an attributed excerpt is cut to the part around the evidence
MAX_AMBIGUOUS = 5
PENDING_TTL = 3600        # an approval nobody answered says nothing: its pending rows are dropped
DEFAULT_TTL_DAYS = 90     # an attack unmatched this long, an unreviewed candidate, a rejection: deleted (0 = never)
SWEEP_EVERY = 3600        # seconds between expiry sweeps (per worker)
TOUCH_EVERY = 3600        # a match the cache answers refreshes the attack's last_hit at most this often
REFRESH = 2.0             # seconds between checks for attacks confirmed by another worker
CACHE_SIZE = 4096         # texts whose answer is kept until the memory changes
ANCHOR_SHARE = 0.5        # a text inside a known attack matches only if it holds this much of the attack's anchor

SCHEMA_HINT = "attacks"   # the table lives in store.SCHEMA

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"(?:\bhttps?://|\bwww\.)[^\s<>()\"'\]]+", re.I)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_NUM = re.compile(r"\d(?:[\d .,/+\-]{2,}\d)")
_NONWORD = re.compile(r"[\W_]+")
# words that make a line read like it talks to the assistant (matched on canon text). A neighbouring line joins an
# attack's excerpt with a strong cue (score >= 2); weak cues such as "you" or "password" alone are ordinary text.
_STRONG_CUES = re.compile(
    r"\b(?:assistant|ai|model|llm|chatbot|instruction|instructions|ignore|disregard|important|urgent|task|mention|"
    r"system|override|routine|information|"
    r"βοηθ\w*|οδηγι\w*|αγνοησ\w*|σημαντικ\w*|μοντελ\w*|ρουτιν\w*)\b")
_WEAK_CUES = re.compile(
    r"\b(?:you|your|yours|must|admin|administrator|approved|secret|password|immediately|do not|don t|"
    r"σου|σας|πρεπει|στειλ\w*|καλεσ\w*|μην|αναφερ\w*|διαχειριστ\w*|αμεσα|μυστικ\w*|κωδικ\w*)\b")


def _cue_score(canon_text: str) -> int:
    return 2 * len(set(_STRONG_CUES.findall(canon_text))) + (1 if _WEAK_CUES.search(canon_text) else 0)


_GENERIC = {"true", "false", "none", "null", "yes", "no", "all", "student", "teacher", "admin", "user"}
_OWN_MARKERS = re.compile(r"\[Laocoon[^\]]*\]")    # Laocoon's own placeholders are never someone's attack


# ---------------------------------------------------------------------- text
def redact(text: str) -> str:
    """E-mail addresses, URLs, IBANs and long numbers -> placeholders (what is stored, and what is compared). A
    private_data placeholder (⟦AMKA:3f9a1c⟧) keeps only its type: its id is per conversation, so the same attack
    naming another person, or the same person in another conversation, still matches."""
    s = PLACEHOLDER_RE.sub(lambda m: f"[{m.group(1).lower()}]", text)
    s = _EMAIL.sub("[email]", s)
    s = _URL.sub("[url]", s)
    s = _IBAN.sub("[iban]", s)
    return _NUM.sub("[number]", s)


def canon(text) -> str:
    """The form that is compared: hidden characters decoded, redacted, case-folded, accents and punctuation dropped."""
    s = redact(normalize(str(text or "")))
    s = unicodedata.normalize("NFKD", s.casefold())
    s = "".join(c for c in s if not unicodedata.combining(c))
    return _NONWORD.sub(" ", s).strip()


def grams(text, n: int = NGRAM) -> set:
    s = canon(text)[:MAX_INPUT]
    if len(s) < n:
        return set()
    return {hash(s[i:i + n]) for i in range(len(s) - n + 1)}


def fingerprint(kind: str, text: str) -> str:
    return hashlib.sha256(f"{kind}|{canon(text)}".encode("utf-8", "surrogatepass")).hexdigest()


def _lower_same_length(text: str) -> str:
    """lower() that keeps every index (a few characters lower-case to two)."""
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in text)


# ---------------------------------------------------------------------- attribution
@dataclass
class Item:
    kind: str                    # input (the user's message) | content (something the agent read)
    text: str
    ref: str | None = None
    how: str = "ambiguous"       # direct | strong | flagged | sole | ambiguous
    anchor: str | None = None    # the lines that carried the evidence (the attack itself, without its context)


def _scalars(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _scalars(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _scalars(v)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        yield obj


def _values(args) -> set:
    """Argument values that would identify the text they were copied from (recipients, accounts, ids, URLs)."""
    out = set()
    for v in _scalars(args or {}):
        s = str(v).strip().lower()
        if len(s) < 4 or len(s) > 120 or s in _GENERIC:
            continue
        if re.fullmatch(r"[\d.,:/ \-]+", s) and sum(ch.isdigit() for ch in s) < 5:
            continue                                   # short numbers and times are everywhere
        out.add(s)
    return out


def _units(text: str) -> list[tuple[int, int]]:
    """Lines, and the sentences of long lines: the pieces an excerpt is cut along."""
    out, pos = [], 0
    for line in text.splitlines(keepends=True):
        start = pos
        pos += len(line)
        if not line.strip():
            continue
        if len(line.strip()) <= 400:
            out.append((start, pos))
            continue
        for m in re.finditer(r"[^.!?;\n]+(?:[.!?;]+|$)", line):
            if m.group().strip():
                out.append((start + m.start(), start + m.end()))
    return out


def anchor(text: str, spans) -> str:
    """The pieces of `text` that carry the evidence, nothing around them."""
    units = _units(text)
    return "\n".join(text[a:b].strip() for a, b in units if any(s < b and e > a for s, e in spans))[:CORE_CHARS]


def window(text: str, spans, cue_words=()) -> str:
    """The part of `text` around the evidence: the pieces that carry it plus the neighbouring pieces that read like
    instructions (short pieces such as a signature are bridged), at most CORE_CHARS."""
    units = _units(text)
    hit = [i for i, (a, b) in enumerate(units) if any(s < b and e > a for s, e in spans)]
    if not hit:
        return text[:CORE_CHARS].strip()

    def cue(i):
        u = canon(text[units[i][0]:units[i][1]])
        return _cue_score(u) >= 2 or any(w and w in u for w in cue_words)

    def short(i):
        return len(text[units[i][0]:units[i][1]].strip()) < 40

    lo, hi = min(hit), max(hit)
    for step in (-1, 1):
        j, gap = (lo - 1, 0) if step < 0 else (hi + 1, 0)
        while 0 <= j < len(units):
            if cue(j):
                lo, hi = (j, hi) if step < 0 else (lo, j)
                gap = 0
            elif short(j) and gap < 2:
                gap += 1
            else:
                break
            j += step
    a, b = units[lo][0], units[hi][1]
    if b - a > CORE_CHARS:                              # centre on the first piece of evidence
        first = min(s for s, _ in spans)
        a = max(a, first - CORE_CHARS // 2)
        b = min(b, a + CORE_CHARS)
    return text[a:b].strip()


def attribute(reads, *, tool=None, args=None, suspicious=(), tool_names=()) -> list[Item]:
    """Which of the untrusted texts read in this run caused the event. -> [Item]

    A text that carries the call's distinctive argument values or names the called tool is evidence; the texts with
    the most evidence win ("strong" when two or more pieces agree or only one text has it). Without evidence: texts
    the classifier flagged ("flagged"), the only text read ("sole"), or every recent one ("ambiguous")."""
    seen, docs = set(), []
    for ref, text in reads or ():
        t = _OWN_MARKERS.sub(" ", normalize(str(text or ""))).strip()
        if t and (ref, t) not in seen:
            seen.add((ref, t))
            docs.append((ref, t))
    if not docs:
        return []
    values = _values(args)
    tool_forms = set()
    if tool and len(tool) >= 5:
        tool_forms = {tool.lower(), tool.lower().replace("_", " ")}
    cue_words = {canon(n) for n in tool_names or () if len(n) >= 5}
    scored = []
    for ref, text in docs:
        low = _lower_same_length(text)
        spans, score = [], 0
        for v in values | tool_forms:
            i = low.find(v)
            if i < 0:
                continue
            score += 2 if v in tool_forms else 1
            while i >= 0 and len(spans) < 50:
                spans.append((i, i + len(v)))
                i = low.find(v, i + 1)
        scored.append((score, ref, text, spans))
    best = max(s for s, *_ in scored)
    sus = set(suspicious or ())
    out = []
    if best > 0:
        top = [x for x in scored if x[0] == best]
        how = "strong" if best >= 2 or len(top) == 1 else "ambiguous"
        out = [Item("content", window(text, spans, cue_words), ref, how, anchor(text, spans) or None)
               for _, ref, text, spans in top]
    if out:
        return out
    out = [Item("content", text[:CORE_CHARS], ref, "flagged") for _, ref, text, _ in scored if ref in sus]
    if out:
        return out
    if len(docs) == 1:
        return [Item("content", docs[0][1][:CORE_CHARS], docs[0][0], "sole")]
    return [Item("content", t[:CORE_CHARS], r, "ambiguous") for r, t in docs[-MAX_AMBIGUOUS:]]


# ---------------------------------------------------------------------- matching
@dataclass
class Match:
    id: int
    kind: str
    label: str
    similarity: float
    shared: int
    origin: str | None
    strong: bool

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "similarity": round(self.similarity, 4),
                "shared": self.shared, "origin": self.origin, "strong": self.strong}


@dataclass
class _Entry:
    kind: str
    label: str
    size: int
    origin: str | None
    text: str = ""
    anchor: str | None = None


@functools.lru_cache(maxsize=256)
def _attack_grams(text: str) -> frozenset:
    return frozenset(grams(text))


class AttackMemory:
    def __init__(self, store, *, mode="on", autoconfirm=DEFAULT_AUTOCONFIRM, threshold=0.6, review=0.45,
                 points=DEFAULT_POINTS, min_shared=MIN_SHARED, max_entries=5000, refresh=REFRESH,
                 ttl_days=DEFAULT_TTL_DAYS):
        if mode not in MODES:
            raise ValueError(f"LAOCOON_MEMORY must be off, on or match, not {mode!r}")
        self.store = store
        self.mode = mode
        self.autoconfirm = frozenset(x.lower() for x in _split(autoconfirm))
        self.threshold = float(threshold)
        self.review = min(float(review), self.threshold)
        if not (0.0 < self.review <= self.threshold <= 1.0):
            raise ValueError("LAOCOON_MEMORY_REVIEW <= LAOCOON_MEMORY_THRESHOLD, both in (0, 1]")
        self.points = (frozenset(p.upper() for p in _split(points)) - set(RETIRED_POINTS)) or frozenset(DEFAULT_POINTS)
        bad = self.points - set(POINT_KINDS)
        if bad:
            raise ValueError(f"LAOCOON_MEMORY_POINTS: the memory checks G1 and G2, not {sorted(bad)}")
        self.min_shared = int(min_shared)
        self.max_entries = int(max_entries)
        self.refresh = float(refresh)
        self.ttl_days = float(ttl_days or 0)
        if self.ttl_days < 0:
            raise ValueError("LAOCOON_MEMORY_TTL_DAYS must be >= 0 (0 = never expire)")
        self._lock = threading.Lock()
        self._index, self._entries = {}, {}
        self._rev = None
        self._max_id = 0
        self._rows = 0                 # confirmed rows the index has looked at (short ones are skipped, not missing)
        self._checked = 0.0
        self._cache = {}
        self._swept = None             # monotonic time of the last expiry sweep
        self._touched = {}             # attack id -> when this worker last wrote its last_hit

    @classmethod
    def from_settings(cls, settings, store) -> "AttackMemory | None":
        mode = str(getattr(settings, "memory", "") or "off").strip().lower()
        if mode in OFF_NAMES:
            return None
        path = getattr(settings, "memory_db", "") or ""
        st = Store(path) if path and path != getattr(store, "path", None) else store
        return cls(st, mode=mode, autoconfirm=getattr(settings, "memory_autoconfirm", DEFAULT_AUTOCONFIRM),
                   threshold=getattr(settings, "memory_threshold", 0.6), review=getattr(settings, "memory_review", 0.45),
                   points=getattr(settings, "memory_points", "") or DEFAULT_POINTS,
                   ttl_days=getattr(settings, "memory_ttl_days", DEFAULT_TTL_DAYS))

    @property
    def learning(self) -> bool:
        return self.mode == "on"

    # -------------------------------------------------------------- match
    def match(self, text, point) -> Match | None:
        """The closest confirmed attack, if it is close enough (>= review). Never raises."""
        if point not in self.points or not text:
            return None
        try:
            self._maybe_reload()
            key = (point, hashlib.blake2b(str(text).encode("utf-8", "surrogatepass"), digest_size=16).digest())
            cache = self._cache
            if cache.get("rev") != self._rev:            # the memory changed: forget every cached answer
                cache.clear()
                cache["rev"] = self._rev
            if key in cache:                             # the proxy re-reads the whole history on every request
                m = cache[key]
                if m is not None:
                    self._hit(m.id, fresh=False)
                return m
            m = self._match(text, POINT_KINDS[point])
            if len(cache) > CACHE_SIZE:
                cache.clear()
                cache["rev"] = self._rev
            cache[key] = m
            if m is not None:
                self._hit(m.id, fresh=True)
            return m
        except Exception:  # noqa: BLE001 — a broken memory is an empty memory
            return None

    def _match(self, text, kinds) -> Match | None:
        g = grams(text)
        if len(g) < MIN_GRAMS:
            return None
        index, entries = self._index, self._entries
        if not entries:
            return None
        counts = Counter()
        for x in g:
            ids = index.get(x)
            if ids:
                counts.update(ids)
        n, best = len(g), None
        for eid, c in counts.items():
            if c < self.min_shared:
                continue
            e = entries.get(eid)
            if e is None or e.kind not in kinds:
                continue
            sim = c / e.size
            if n >= REVERSE_MIN and n >= 0.3 * e.size and c / n > sim:   # a long enough piece of a known attack...
                core = _attack_grams(e.anchor or e.text)                 # ...that holds the attack itself, not only
                if core and len(core & g) >= ANCHOR_SHARE * len(core):   # the text the attack was planted in
                    sim = c / n
            sim = min(1.0, sim)
            if best is None or (sim, c) > (best.similarity, best.shared):
                best = Match(eid, e.kind, e.label, sim, c, e.origin, sim >= self.threshold)
        if best is None or best.similarity < self.review:
            return None
        return best

    def _hit(self, aid, fresh):
        """A match keeps its attack alive (expiry looks at last_hit). A new text counts a hit; a text the cache
        answers refreshes last_hit at most every TOUCH_EVERY seconds, so the proxy re-reading history writes nothing."""
        now = time.time()
        if not fresh and now - self._touched.get(aid, 0.0) < TOUCH_EVERY:
            return
        if len(self._touched) > 10000:
            self._touched.clear()
        self._touched[aid] = now
        try:
            if fresh:
                self.store.execute("UPDATE attacks SET hits = hits + 1, last_hit = ? WHERE id = ?", (now, aid))
            else:
                self.store.execute("UPDATE attacks SET last_hit = ? WHERE id = ?", (now, aid))
        except Exception:  # noqa: BLE001 — the hit counter is statistics, never a reason to fail
            pass

    def cut(self, text, aid, marker) -> str | None:
        """`text` with only the block of the known attack `aid` replaced by `marker`: everything from the first line
        that belongs to the attack to the last one (what an attacker changed inside the block, such as the goal, goes
        with it), so that a question around a hidden instruction survives. None when the block cannot be found or
        little else is left: then the whole text goes. Never raises."""
        try:
            self._maybe_reload()
            e = self._entries.get(int(aid))
            if e is None or not e.text:
                return None
            known = _attack_grams(e.text)
            units = _units(text)
            idx = []
            for i, (a, b) in enumerate(units):
                g = grams(text[a:b])
                if len(g) >= 8 and len(g & known) >= 0.5 * len(g):
                    idx.append(i)
            if not idx:
                return None
            lo, hi = idx[0], idx[-1]
            for step in (-1, 1):                        # short wrapper lines of the attack (tags, signatures)
                j = (lo if step < 0 else hi) + step
                for _ in range(2):
                    if not 0 <= j < len(units):
                        break
                    g = grams(text[units[j][0]:units[j][1]])
                    if len(g) >= 8 or not (g & known):
                        break
                    lo, hi = (j, hi) if step < 0 else (lo, j)
                    j += step
            a, b = units[lo][0], units[hi][1]
            out = text[:a] + marker + ("\n" if text[b - 1:b] == "\n" else "") + text[b:]
            rest = canon(out.replace(marker, " "))
            return out if len(rest) >= 20 else None
        except Exception:  # noqa: BLE001 — when in doubt, the caller quarantines the whole text
            return None

    def _maybe_reload(self, force=False):
        """Keep the in-process index in step with the store (other workers learn too). New confirmed attacks are
        added to the index as they come; a rejection, a deletion or an upgrade of an older row rebuilds it."""
        now = time.monotonic()
        if not force and self._rev is not None and now - self._checked < self.refresh:
            return
        self._checked = now
        self._expire(time.time())                                 # hourly: forget what has not matched for a while
        row = self.store.query("SELECT COUNT(*) AS n, MAX(updated_at) AS m, MAX(id) AS i FROM attacks "
                               "WHERE status = 'confirmed'", one=True) or {}
        rev = (row.get("n"), row.get("m"))
        if rev == self._rev and not force:
            return
        with self._lock:
            if not force and self._rev is not None and self._rows < self.max_entries:
                new = self.store.query("SELECT id, kind, label, text, origin, anchor FROM attacks "
                                       "WHERE status = 'confirmed' AND id > ? ORDER BY id", (self._max_id,))
                if new and self._rows + len(new) == (row.get("n") or 0):   # only additions since the last look
                    index = dict(self._index)                                 # copy on write: readers keep theirs
                    entries = dict(self._entries)
                    for r in new:
                        g = grams(r["text"])
                        if len(g) < MIN_GRAMS:
                            continue
                        for x in g:
                            index[x] = index.get(x, []) + [r["id"]]
                        entries[r["id"]] = _Entry(r["kind"], r["label"] or DEFAULT_LABEL, len(g), r["origin"], r["text"],
                                                  r["anchor"])
                    self._index, self._entries, self._rev = index, entries, rev
                    self._max_id = max([self._max_id] + [r["id"] for r in new])
                    self._rows += len(new)
                    return
            rows = self.store.query("SELECT id, kind, label, text, origin, anchor FROM attacks "
                                    "WHERE status = 'confirmed' ORDER BY id DESC LIMIT ?", (self.max_entries,))
            index, entries, sets = {}, {}, {}
            for r in rows:
                g = grams(r["text"])
                if len(g) < MIN_GRAMS:
                    continue
                sets[r["id"]] = g
                for x in g:
                    index.setdefault(x, []).append(r["id"])
            if len(sets) > 200:                       # grams most attacks share say nothing: drop them
                cap = max(50, len(sets) // 5)
                stop = {x for x, ids in index.items() if len(ids) > cap}
                for x in stop:
                    del index[x]
            else:
                stop = set()
            for r in rows:
                if r["id"] in sets:
                    size = len(sets[r["id"]] - stop) or 1
                    entries[r["id"]] = _Entry(r["kind"], r["label"] or DEFAULT_LABEL, size, r["origin"], r["text"],
                                              r["anchor"])
            self._index, self._entries, self._rev = index, entries, rev
            self._max_id = max([0] + [r["id"] for r in rows])
            self._rows = len(rows)

    def _changed(self, full=False):
        """Look at the store at the next match; `full`: rebuild the index (a status, label or deletion changed)."""
        self._checked = 0.0
        if full:
            self._rev = None

    # -------------------------------------------------------------- learn
    def status_for(self, signal: str, how: str) -> str:
        base = signal.split(":", 1)[0]
        return "confirmed" if base in self.autoconfirm and how in STRONG else "candidate"

    def observe(self, items, *, signal, user_id=None, conversation=None, approval_id=None, evidence=None) -> list[dict]:
        """Record what an event attributed. With `approval_id` the rows wait (pending) for the user's answer.
        -> [{id, status, kind, ref, how, new}] (rows an admin rejected before are skipped)."""
        if not self.learning:
            return []
        now = time.time()
        self._expire(now)
        out = []
        for it in items or ():
            if it.kind not in KINDS:
                continue
            text = redact(normalize(str(it.text or ""))).strip()[:MAX_TEXT]
            if len(grams(text)) < MIN_GRAMS:
                continue
            fp = fingerprint(it.kind, text)
            anc = redact(normalize(it.anchor)).strip()[:MAX_TEXT] if it.anchor else None
            ev = json.dumps({**(evidence or {}), "how": it.how, "signal": signal}, ensure_ascii=False, default=str)
            known = self.store.query("SELECT id, status FROM attacks WHERE fp = ? AND status != 'pending' "
                                     "ORDER BY id LIMIT 1", (fp,), one=True)
            if known and known["status"] == "rejected":
                continue                                          # an admin said: not an attack
            if approval_id is not None:
                if known and known["status"] == "confirmed":
                    out.append({"id": known["id"], "status": "confirmed", "kind": it.kind, "ref": it.ref,
                                "how": it.how, "new": False})
                    continue
                rid, _ = self.store.execute(
                    "INSERT INTO attacks (fp, kind, status, label, text, origin, evidence, ref, user_id, conversation, "
                    "approval_id, anchor, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fp, it.kind, "pending", DEFAULT_LABEL, text, "rejected", ev, it.ref, user_id, conversation,
                     approval_id, anc, now, now))
                out.append({"id": rid, "status": "pending", "kind": it.kind, "ref": it.ref, "how": it.how, "new": True})
                continue
            status = self.status_for(signal, it.how)
            if known:
                out.append(self._upgrade(known, status, signal, now) | {"kind": it.kind, "ref": it.ref, "how": it.how})
                continue
            rid, _ = self.store.execute(
                "INSERT INTO attacks (fp, kind, status, label, text, origin, evidence, ref, user_id, conversation, "
                "anchor, created_at, updated_at, decided_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fp, it.kind, status, DEFAULT_LABEL, text, signal, ev, it.ref, user_id, conversation, anc, now, now,
                 "auto" if status == "confirmed" else None))
            out.append({"id": rid, "status": status, "kind": it.kind, "ref": it.ref, "how": it.how, "new": True})
        if any(r["status"] == "confirmed" for r in out):
            self._changed()
        return out

    def _upgrade(self, known, status, origin, now) -> dict:
        if known["status"] == "candidate" and status == "confirmed":
            self.store.execute("UPDATE attacks SET status = 'confirmed', seen = seen + 1, origin = ?, decided_by = 'auto', "
                               "updated_at = ? WHERE id = ?", (origin, now, known["id"]))
            self._changed()
            return {"id": known["id"], "status": "confirmed", "new": False}
        self.store.execute("UPDATE attacks SET seen = seen + 1 WHERE id = ?", (known["id"],))
        return {"id": known["id"], "status": known["status"], "new": False}

    def resolve(self, approval_id, approved: bool) -> list[dict]:
        """The user answered the approval: approved -> its pending rows are dropped (benign, not kept); rejected ->
        each becomes confirmed or a candidate, by LAOCOON_MEMORY_AUTOCONFIRM and how it was attributed."""
        if not approval_id or not self.learning:
            return []
        rows = self.store.query("SELECT * FROM attacks WHERE approval_id = ? AND status = 'pending'", (approval_id,))
        if not rows:
            return []
        if approved:
            self.store.execute("DELETE FROM attacks WHERE approval_id = ? AND status = 'pending'", (approval_id,))
            return [{"id": r["id"], "status": "dropped", "ref": r["ref"]} for r in rows]
        now, out = time.time(), []
        for r in rows:
            how = (json.loads(r["evidence"] or "{}") or {}).get("how", "ambiguous")
            status = self.status_for("rejected", how)
            known = self.store.query("SELECT id, status FROM attacks WHERE fp = ? AND status != 'pending' "
                                     "ORDER BY id LIMIT 1", (r["fp"],), one=True)
            if known and known["status"] == "rejected":
                self.store.execute("DELETE FROM attacks WHERE id = ?", (r["id"],))
                continue
            if known:
                self.store.execute("DELETE FROM attacks WHERE id = ?", (r["id"],))
                out.append(self._upgrade(known, status, "rejected", now) | {"ref": r["ref"], "how": how})
                continue
            self.store.execute("UPDATE attacks SET status = ?, updated_at = ?, decided_by = ? WHERE id = ?",
                               (status, now, "auto" if status == "confirmed" else None, r["id"]))
            out.append({"id": r["id"], "status": status, "ref": r["ref"], "how": how, "new": True})
        if any(r["status"] == "confirmed" for r in out):
            self._changed()
        return out

    def _expire(self, now=None, force=False) -> int:
        """Delete pending rows older than an hour and, with a TTL, every attack, candidate or rejection whose last
        activity (learned, decided or matched) is older than it. At most every SWEEP_EVERY seconds unless forced.
        -> rows expired (pending rows not counted)."""
        mono = time.monotonic()
        if not force and self._swept is not None and mono - self._swept < SWEEP_EVERY:
            return 0
        self._swept = mono
        now = time.time() if now is None else now
        n = 0
        try:
            self.store.execute("DELETE FROM attacks WHERE status = 'pending' AND created_at < ?", (now - PENDING_TTL,))
            if self.ttl_days:
                _, n = self.store.execute(
                    "DELETE FROM attacks WHERE status IN ('confirmed', 'candidate', 'rejected') "
                    "AND MAX(created_at, updated_at, COALESCE(last_hit, 0)) < ?", (now - self.ttl_days * 86400,))
                if n:
                    self._changed(full=True)
        except Exception:  # noqa: BLE001 — a failed sweep is retried at the next one
            return 0
        return n

    # -------------------------------------------------------------- admin
    def list(self, status=None, limit=200) -> list[dict]:
        self._expire(time.time())
        sql, args = "SELECT * FROM attacks", []
        if status and status != "all":
            sql += " WHERE status = ?"
            args.append(status)
        rows = self.store.query(sql + " ORDER BY id DESC LIMIT ?", (*args, int(limit)))
        for r in rows:
            r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else None
        return rows

    def get(self, aid) -> dict | None:
        rows = self.store.query("SELECT * FROM attacks WHERE id = ?", (int(aid),))
        if not rows:
            return None
        r = rows[0]
        r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else None
        return r

    def set_status(self, aid, status, by="admin", label=None) -> dict | None:
        if status not in ("confirmed", "rejected", "candidate"):
            raise ValueError("status must be confirmed, rejected or candidate")
        row = self.get(aid)
        if row is None:
            return None
        self.store.execute("UPDATE attacks SET status = ?, label = COALESCE(?, label), decided_by = ?, updated_at = ? "
                           "WHERE id = ?", (status, label, str(by), time.time(), int(aid)))
        if status == "rejected":   # the same text waiting elsewhere goes too: an admin's "not an attack" is final
            self.store.execute("DELETE FROM attacks WHERE fp = ? AND id != ? AND status IN ('pending', 'candidate')",
                               (row["fp"], int(aid)))
        self._changed(full=True)
        return self.get(aid)

    def delete(self, aid) -> bool:
        _, n = self.store.execute("DELETE FROM attacks WHERE id = ?", (int(aid),))
        self._changed(full=True)
        return n == 1

    def add(self, text, kind="content", label=None, by="admin", origin="manual", anchor=None) -> dict:
        """An attack an admin (or another deployment) knows about: confirmed at once. Without an anchor the whole
        text is the attack."""
        if kind not in KINDS:
            raise ValueError("kind must be input or content")
        stored = redact(normalize(str(text or ""))).strip()[:MAX_TEXT]
        anc = redact(normalize(str(anchor))).strip()[:MAX_TEXT] if anchor else None
        if len(grams(stored)) < MIN_GRAMS:
            raise ValueError(f"too short to remember (at least {MIN_GRAMS + NGRAM} characters of text)")
        fp, now = fingerprint(kind, stored), time.time()
        known = self.store.query("SELECT id FROM attacks WHERE fp = ? AND status != 'pending' ORDER BY id LIMIT 1",
                                 (fp,), one=True)
        if known:
            self.store.execute("UPDATE attacks SET status = 'confirmed', label = COALESCE(?, label), decided_by = ?, "
                               "updated_at = ? WHERE id = ?", (label, str(by), now, known["id"]))
            rid = known["id"]
            self._changed(full=True)
        else:
            rid, _ = self.store.execute(
                "INSERT INTO attacks (fp, kind, status, label, text, origin, evidence, anchor, created_at, updated_at, "
                "decided_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)", (fp, kind, "confirmed", label or DEFAULT_LABEL, stored,
                                                              origin, json.dumps({"how": "manual"}), anc, now, now,
                                                              str(by)))
        self._changed()
        return self.get(rid)

    def export(self):
        """Confirmed attacks as JSON lines (already redacted): another deployment can import them."""
        for r in self.store.query("SELECT kind, label, text, anchor, origin, created_at, hits FROM attacks "
                                  "WHERE status = 'confirmed' ORDER BY id"):
            yield json.dumps(r, ensure_ascii=False) + "\n"

    def import_lines(self, lines, by="import") -> dict:
        added, skipped = 0, 0
        for line in lines:
            line = line.strip() if isinstance(line, str) else line.decode().strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                self.add(r["text"], r.get("kind", "content"), r.get("label"), by=by,
                         origin=f"import:{r.get('origin') or 'unknown'}", anchor=r.get("anchor"))
                added += 1
            except (ValueError, KeyError, TypeError):
                skipped += 1
        return {"added": added, "skipped": skipped}

    def stats(self) -> dict:
        rows = self.store.query("SELECT status, COUNT(*) AS n, COALESCE(SUM(hits), 0) AS hits FROM attacks "
                                "GROUP BY status")
        by = {s: 0 for s in STATUSES}
        hits = 0
        for r in rows:
            by[r["status"]] = r["n"]
            hits += r["hits"] if r["status"] == "confirmed" else 0
        return {"mode": self.mode, "autoconfirm": sorted(self.autoconfirm), "threshold": self.threshold,
                "review": self.review, "points": sorted(self.points), "ttl_days": self.ttl_days, **by, "hits": hits}


def _split(v) -> list[str]:
    if v is None:
        return []
    items = v.replace(";", ",").replace(" ", ",").split(",") if isinstance(v, str) else list(v)
    return [str(x).strip() for x in items if str(x).strip()]


# ---------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m laocoon memory", description="Laocoon attack memory (admin)")
    ap.add_argument("--db", required=True, help="the memory database (LAOCOON_MEMORY_DB, or LAOCOON_DB)")
    ap.add_argument("--ttl-days", type=float, default=float(os.environ.get("LAOCOON_MEMORY_TTL_DAYS") or 0),
                    help="expire with this TTL (default: $LAOCOON_MEMORY_TTL_DAYS, else never: the CLI deletes "
                         "nothing on its own)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    sub.add_parser("expire")
    p = sub.add_parser("list")
    p.add_argument("--status", default="all", choices=("all", *STATUSES))
    p.add_argument("--limit", type=int, default=50)
    for name in ("show", "confirm", "reject", "delete"):
        p = sub.add_parser(name)
        p.add_argument("id", type=int)
        if name == "confirm":
            p.add_argument("--label", default=None)
    p = sub.add_parser("add")
    p.add_argument("text")
    p.add_argument("--kind", default="content", choices=KINDS)
    p.add_argument("--label", default=None)
    sub.add_parser("export")
    p = sub.add_parser("import")
    p.add_argument("file")
    a = ap.parse_args(argv)
    mem = AttackMemory(Store(a.db), ttl_days=a.ttl_days)
    if a.cmd == "stats":
        print(json.dumps(mem.stats(), indent=2))
    elif a.cmd == "expire":
        if not a.ttl_days:
            print("no TTL: pass --ttl-days N (or set LAOCOON_MEMORY_TTL_DAYS)")
            return 2
        print(json.dumps({"expired": mem._expire(force=True), "ttl_days": a.ttl_days}))
    elif a.cmd == "list":
        for r in mem.list(a.status, a.limit):
            how = (r.get("evidence") or {}).get("how", "")
            print(f"#{r['id']:<5} {r['status']:<10} {r['kind']:<8} {r['origin'] or '':<12} {how:<10} hits={r['hits']:<4} "
                  f"{(r.get('ref') or '-'):<18} {r['text'][:80]!r}")
    elif a.cmd == "show":
        print(json.dumps(mem.get(a.id), indent=2, ensure_ascii=False))
    elif a.cmd in ("confirm", "reject"):
        r = mem.set_status(a.id, "confirmed" if a.cmd == "confirm" else "rejected", by="cli",
                           label=getattr(a, "label", None))
        print(json.dumps(r, indent=2, ensure_ascii=False) if r else f"#{a.id} not found")
    elif a.cmd == "delete":
        print("deleted" if mem.delete(a.id) else f"#{a.id} not found")
    elif a.cmd == "add":
        print(json.dumps(mem.add(a.text, a.kind, a.label, by="cli"), indent=2, ensure_ascii=False))
    elif a.cmd == "export":
        sys.stdout.writelines(mem.export())
    elif a.cmd == "import":
        with open(a.file, encoding="utf-8") as f:
            print(json.dumps(mem.import_lines(f, by="cli")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

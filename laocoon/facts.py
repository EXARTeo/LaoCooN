"""Facts the firewall learns from the app's own tools: the seamless proxy, with no database.

In `LAOCOON_AUTHZ_SOURCE=lookup` the proxy never opens the app's database. The facts behind the ABAC constraints
(who teaches a course, who is enrolled, which course an assignment belongs to, ...) come from the results of the
app's own read tools:

* observed: the result of a call the model made, as the app returned it (the tail of the next request);
* looked up: when a decision needs a fact the proxy does not have, it holds the model's calls and answers the app
  with a *lookup*: a read tool call that the app runs like any other (see `holds.py`). The result comes back in the
  next request, never reaches the model, and the held calls are decided with it.

Both rest on the same trust as the system-prompt identity: the app's server builds every message it sends to the
proxy (system prompt, history, tool results). Only declared structural fields are kept (ids, foreign keys, flags,
codes, usernames): never free text, never personal data beyond a username and a display name.

Freshness. Every fact carries the time it was learned. A decision accepts it only if it is recent enough for that
decision (`FactView.max_age`):

    stable     an object's parent and codes (an assignment never changes course)            1 h
    scope      who teaches / who is enrolled / complete lists / identity    read 120 s · side effect 30 s
    volatile   is an exercise open, has the user attempted it                                  30 s
    label      anything, when it is only used to filter or label a result (fail closed if missing)    1 h
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

STABLE_TTL = 3600
VOLATILE_TTL = 30
LABEL_TTL = 3600
DEFAULT_TTL = {"read": 120, "write": 30, "identity": 600}
KEEP_FOR = 86400                   # facts older than this are deleted


class NeedFacts(Exception):
    """A decision needs facts the proxy does not have yet. `lookups`: the read calls that would provide them."""

    def __init__(self, lookups, why=""):
        super().__init__(why or "facts needed")
        self.lookups = tuple(dict.fromkeys(lookups))
        self.why = why


class Unverifiable(Exception):
    """The facts cannot be obtained in this deployment (lookup not allowed, out-of-scope reads not allowed,
    search too large). The decision fails closed."""


@dataclass(frozen=True)
class Lookup:
    tool: str
    args: tuple = ()                 # sorted (key, value) pairs: hashable, canonical
    speculative: bool = False        # may read an object outside the user's scope (needs lookups.out_of_scope)

    def as_args(self) -> dict:
        return dict(self.args)

    def key(self) -> str:
        return self.tool + json.dumps(self.args, separators=(",", ":"), ensure_ascii=False, default=str)


def lookup(tool, *, speculative=False, **args) -> Lookup:
    return Lookup(tool, tuple(sorted(args.items())), speculative)


class FactStore:
    """Per-user facts in the shared Laocoon store (table `facts`)."""

    def __init__(self, store):
        self.store = store

    def load(self, user_id, kind, key):
        row = self.store.query("SELECT data, at FROM facts WHERE user_id = ? AND kind = ? AND key = ?",
                               (int(user_id), kind, str(key)), one=True)
        if not row:
            return None
        try:
            return json.loads(row["data"]), float(row["at"])
        except (TypeError, ValueError):
            return None

    def save(self, user_id, rows, at):
        if not rows:
            return
        with self.store.tx() as conn:
            conn.executemany(
                "INSERT INTO facts (user_id, kind, key, data, at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(user_id, kind, key) DO UPDATE SET data = excluded.data, at = excluded.at "
                "WHERE excluded.at >= facts.at",
                [(int(user_id), k, str(key), json.dumps(d, ensure_ascii=False, separators=(",", ":")), at)
                 for k, key, d in rows])
            conn.execute("DELETE FROM facts WHERE user_id = ? AND at < ?", (int(user_id), at - KEEP_FOR))


class FactView:
    """The facts of one principal during one request. Not shared between requests or threads."""

    def __init__(self, store, user_id, ttl=None, now=None):
        self.facts = FactStore(store)
        self.user_id = int(user_id)
        self.ttl = {**DEFAULT_TTL, **(ttl or {})}
        self.now = now if now is not None else time.time()
        self.mode = "read"                       # read | write: set by the policy for the call being checked
        self.relaxed = False                     # True while filtering / labelling a result
        self._cache = {}
        self._learned = set()                    # (kind, key) learned during this request

    # ------------------------------------------------------------------ freshness
    def max_age(self, cls) -> float:
        if self.relaxed:
            return LABEL_TTL
        if cls == "stable":
            return STABLE_TTL
        if cls == "volatile":
            return VOLATILE_TTL
        if cls == "identity":
            return self.ttl["identity"]
        return self.ttl["write"] if self.mode == "write" else self.ttl["read"]

    def get(self, kind, key, cls="scope"):
        """The fact, or None when it is missing or too old for the current decision."""
        k = (kind, str(key))
        if k not in self._cache:
            self._cache[k] = self.facts.load(self.user_id, kind, key)
        hit = self._cache[k]
        if hit is None:
            return None
        data, at = hit
        return data if self.now - at <= self.max_age(cls) else None

    def put_many(self, rows, at=None, persist=True):
        at = self.now if at is None else at
        if persist:
            self.facts.save(self.user_id, rows, at)
        for kind, key, data in rows:
            self._cache[(kind, str(key))] = (data, at)
            self._learned.add((kind, str(key)))

    def learned_now(self, kind, key) -> bool:
        return (kind, str(key)) in self._learned


# ---------------------------------------------------------------------- helpers for extractors
MAX_ID = 2 ** 53


def as_id(v):
    """A platform id from a tool result: a non-negative int (bools and floats with a fraction rejected)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if 0 <= v < MAX_ID else None
    if isinstance(v, str) and v.strip().isdigit() and len(v.strip()) <= 16:
        return int(v.strip())
    return None


def as_str(v, n=256):
    return v[:n] if isinstance(v, str) else None


def rows_of(result):
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    if isinstance(result, dict) and isinstance(result.get("rows"), list):
        return [r for r in result["rows"] if isinstance(r, dict)]
    return None


def is_error(result) -> bool:
    return isinstance(result, dict) and "error" in result

"""AuthZEN: Laocoon asks the customer's policy decision point (`LAOCOON_AUTHZ_SOURCE=authzen`).

OpenID AuthZEN Authorization API 1.0 is a standard API between a policy enforcement point (PEP: here, Laocoon) and
a policy decision point (PDP: the customer's authorization service). The PDP can be backed by anything: SQL, a
document store, a graph, an LDAP directory, another API. Laocoon never sees the customer's data, only decisions.

What Laocoon asks, and how (the policy's `authzen` section maps Laocoon's names to the PDP's):
    a constraint (`taught_submission` on submission 6)    Access Evaluation   POST /access/v1/evaluation
    all of several constraints                             Access Evaluations  (deny_on_first_deny), when offered
    the user's scope (filters, scope enums)                Resource Search     POST /access/v1/search/resource
    who stands in a relation to an object (a teacher)      Subject Search      POST /access/v1/search/subject
    the identity block of the system prompt                an evaluation with the claimed username and role

AuthZEN is a decision API, not a directory. Resolving names ("CS101" → course 1), labels on approval cards and the
values of a scope enum need the objects' properties, which search results are not required to carry. Laocoon uses
`properties` when the PDP returns them, and sends the reference being resolved as a hint in
`context.laocoon.reference` (a PDP may use it to narrow its results). Without properties, references work by id
only, there are no scope enums, and cards show ids: every gap fails closed.

Every call carries an `X-Request-ID`; a response echoing another value is rejected. Searches are cached for a short
time (LAOCOON_AUTHZEN_CACHE_TTL, default 2 s); evaluations never are.
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field

API = {"access_evaluation_endpoint": "/access/v1/evaluation",
       "access_evaluations_endpoint": "/access/v1/evaluations",
       "search_subject_endpoint": "/access/v1/search/subject",
       "search_resource_endpoint": "/access/v1/search/resource",
       "search_action_endpoint": "/access/v1/search/action"}
METADATA_PATH = "/.well-known/authzen-configuration"
NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")              # Laocoon's names (kinds, constraints)
WIRE = re.compile(r"^[A-Za-z0-9_.:/@-]{1,128}$")          # AuthZEN types and action names Laocoon sends
PROP = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")      # property names in the PDP's results
STRING_ID = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")      # ids of resources with `id: string`
MATCHES = ("exact", "iexact", "contains", "upper_nospace")
MAX_PAGES, PAGE_LIMIT = 20, 200


class ConfigError(ValueError):
    def __init__(self, path, message):
        super().__init__(f"authzen.{'.'.join(str(p) for p in path)}: {message}" if path else message)
        self.path, self.message = list(path), message


class AuthzenError(Exception):
    """The PDP could not answer (unreachable, an HTTP error, a malformed or mismatched response)."""


# ---------------------------------------------------------------------------------------------- the mapping
@dataclass
class Resource:
    kind: str                      # Laocoon's kind (the `refs` kinds)
    type: str                      # the PDP's resource type
    id: str = "int"                # int | string
    search: str | None = None      # the action whose resource search lists what the user may refer to
    refs: list = field(default_factory=list)
    label: str | None = None
    enum: str | None = None


@dataclass
class Check:
    name: str                      # Laocoon's constraint
    kind: str                      # the kind of the argument's object
    action: str                    # the PDP's action


@dataclass
class Relation:
    key: str                       # kind.name
    kind: str
    action: str                    # subject search: the subjects with this action on the object


class AuthzenConfig:
    def __init__(self, subject, identity_action, resources, constraints, relations, derive):
        self.subject: str = subject
        self.identity_action: str | None = identity_action
        self.resources: dict[str, Resource] = resources
        self.constraints: dict[str, Check] = constraints
        self.relations: dict[str, Relation] = relations
        self.derive: dict[str, tuple] = derive           # name -> (arg, relation key)

    @classmethod
    def from_policy(cls, policy_data) -> "AuthzenConfig | None":
        a = (policy_data or {}).get("authzen")
        return None if a is None else cls.parse(a)

    @classmethod
    def parse(cls, a) -> "AuthzenConfig":
        if not isinstance(a, dict):
            raise ConfigError([], "authzen must be a mapping {subject, identity, resources, constraints, ...}")
        for k in a:
            if k not in ("subject", "identity", "resources", "constraints", "relations", "derive"):
                raise ConfigError([k], "unknown key (subject, identity, resources, constraints, relations, derive)")
        subject = a.get("subject", "user")
        _wire(subject, ["subject"], "subject type")
        ident = a.get("identity")
        identity_action = None
        if ident is not None:
            if not isinstance(ident, dict) or set(ident) - {"action"}:
                raise ConfigError(["identity"], "needs {action}")
            identity_action = _wire(ident.get("action"), ["identity", "action"], "action")
        resources = {}
        for kind, spec in _mapping(a.get("resources"), ["resources"]).items():
            resources[kind] = _resource(kind, spec)
        constraints = {}
        for name, spec in _mapping(a.get("constraints"), ["constraints"]).items():
            where = ["constraints", name]
            if not NAME.match(str(name)):
                raise ConfigError(where, "not a valid constraint name")
            if name == "self":
                raise ConfigError(where, "`self` is built in")
            spec = spec or {}
            if not isinstance(spec, dict) or set(spec) - {"resource", "action"}:
                raise ConfigError(where, "needs {resource, action}")
            kind = spec.get("resource")
            if kind not in resources:
                raise ConfigError(where + ["resource"], f"{kind!r} is not in authzen.resources")
            constraints[name] = Check(name, kind, _wire(spec.get("action", name), where + ["action"], "action"))
        relations = {}
        for key, spec in _mapping(a.get("relations"), ["relations"]).items():
            where = ["relations", key]
            parts = str(key).split(".")
            if len(parts) != 2 or not all(NAME.match(p) for p in parts):
                raise ConfigError(where, "a relation is named kind.name")
            if parts[0] not in resources:
                raise ConfigError(where, f"{parts[0]!r} is not in authzen.resources")
            spec = spec or {}
            if not isinstance(spec, dict) or set(spec) - {"action"}:
                raise ConfigError(where, "needs {action}")
            relations[key] = Relation(key, parts[0], _wire(spec.get("action", key), where + ["action"], "action"))
        derive = {}
        for name, spec in _mapping(a.get("derive"), ["derive"]).items():
            where = ["derive", name]
            if not (isinstance(spec, dict) and isinstance(spec.get("arg"), str) and spec.get("relation") in relations):
                raise ConfigError(where, "needs {arg, relation} with a relation of authzen.relations")
            derive[name] = (spec["arg"], spec["relation"])
        return cls(subject, identity_action, resources, constraints, relations, derive)


def _mapping(v, where) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ConfigError(where, "must be a mapping")
    return v


def _wire(v, where, what):
    if not isinstance(v, str) or not WIRE.match(v):
        raise ConfigError(where, f"{v!r} is not a valid {what}")
    return v


def _resource(kind, spec) -> Resource:
    where = ["resources", kind]
    if not NAME.match(str(kind)):
        raise ConfigError(where, "not a valid kind name")
    spec = spec or {}
    if not isinstance(spec, dict):
        raise ConfigError(where, "needs {type, id, search, refs, label, enum}")
    for k in spec:
        if k not in ("type", "id", "search", "refs", "label", "enum"):
            raise ConfigError(where + [k], "unknown key (type, id, search, refs, label, enum)")
    rtype = _wire(spec.get("type", kind), where + ["type"], "resource type")
    id_kind = spec.get("id", "int")
    if id_kind not in ("int", "string"):
        raise ConfigError(where + ["id"], "int or string")
    search = spec.get("search")
    if search is not None:
        _wire(search, where + ["search"], "action")
    refs = spec.get("refs") or []
    if not isinstance(refs, list) or not all(isinstance(t, dict) and t for t in refs):
        raise ConfigError(where + ["refs"], "a list of tiers {property: exact|iexact|contains|upper_nospace}")
    if refs and not search:
        raise ConfigError(where + ["refs"], "references by name need `search` (the action that lists them)")
    for i, tier in enumerate(refs):
        for prop, m in tier.items():
            if not PROP.match(str(prop)):
                raise ConfigError(where + ["refs", i, prop], "not a valid property name")
            if m not in MATCHES:
                raise ConfigError(where + ["refs", i, prop], f"match is one of {', '.join(MATCHES)}")
    label = spec.get("label")
    if label is not None and not re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", str(label)):
        raise ConfigError(where + ["label"], "a format of the resource's properties, e.g. \"{code} {title}\"")
    enum = spec.get("enum")
    if enum is not None and not PROP.match(str(enum)):
        raise ConfigError(where + ["enum"], "a property name")
    return Resource(kind, rtype, id_kind, search, list(refs), label, enum)


# ---------------------------------------------------------------------------------------------- the client
def _requests_transport():
    import requests
    local = threading.local()

    def transport(method, url, body, headers, timeout, verify):
        s = getattr(local, "s", None)
        if s is None:
            s = local.s = requests.Session()
        try:
            r = s.request(method, url, json=body, headers=headers, timeout=timeout, verify=verify)
        except requests.RequestException as e:
            raise AuthzenError(f"{type(e).__name__}: {e}") from None
        try:
            data = r.json()
        except ValueError:
            data = None
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, data
    return transport


class AuthzenClient:
    """An AuthZEN 1.0 client over HTTPS. `pdp` is the PDP's identifier (its base URL); the endpoints come from its
    metadata (/.well-known/authzen-configuration) when it publishes them, otherwise the standard paths are used.
    `transport(method, url, body, headers, timeout, verify) -> (status, headers, json)` is replaceable (tests)."""

    def __init__(self, pdp, token=None, timeout=3.0, verify=True, cache_ttl=2.0, transport=None):
        self.pdp = str(pdp).rstrip("/")
        self.token, self.timeout, self.verify = token, float(timeout), verify
        self.cache_ttl = float(cache_ttl)
        self.transport = transport or _requests_transport()
        self.endpoints: dict | None = None
        self.metadata: dict | None = None
        self.calls, self.errors, self.last_error = 0, 0, None
        self.missing_request_id = 0
        self._cache, self._lock = {}, threading.Lock()

    # ------------------------------------------------------------------ discovery
    def _discover(self):
        if self.endpoints is not None:
            return self.endpoints
        status, _, data = self.transport("GET", self.pdp + METADATA_PATH, None, self._headers(), self.timeout,
                                         self.verify)
        if status == 200 and isinstance(data, dict):
            if str(data.get("policy_decision_point", "")).rstrip("/") != self.pdp:
                raise AuthzenError("PDP metadata: policy_decision_point does not match the PDP's address "
                                   "(AuthZEN 1.0 §9: the metadata must not be used)")
            eps = {k: v for k, v in data.items() if k in API and isinstance(v, str) and v.startswith(("https://",
                                                                                                    "http://"))}
            if "access_evaluation_endpoint" not in eps:
                raise AuthzenError("PDP metadata without access_evaluation_endpoint")
            self.metadata = data
        else:                                               # no metadata: the standard paths, no optional APIs
            eps = {"access_evaluation_endpoint": self.pdp + API["access_evaluation_endpoint"],
                   "search_subject_endpoint": self.pdp + API["search_subject_endpoint"],
                   "search_resource_endpoint": self.pdp + API["search_resource_endpoint"]}
        self.endpoints = eps
        return eps

    def supports(self, endpoint) -> bool:
        return endpoint in self._discover()

    def _headers(self):
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _post(self, endpoint, body) -> dict:
        with self._lock:
            self.calls += 1
        try:
            url = self._discover().get(endpoint)
            if url is None:
                raise AuthzenError(f"the PDP does not offer {endpoint}")
            rid = uuid.uuid4().hex
            headers = dict(self._headers(), **{"X-Request-ID": rid})
            status, rheaders, data = self.transport("POST", url, body, headers, self.timeout, self.verify)
            echoed = rheaders.get("x-request-id")
            if echoed is None:
                with self._lock:
                    self.missing_request_id += 1
            elif echoed != rid:
                raise AuthzenError("the PDP answered with another X-Request-ID")
            if status != 200:
                msg = data.get("message") if isinstance(data, dict) else None
                raise AuthzenError(f"HTTP {status}" + (f": {str(msg)[:200]}" if msg else ""))
            if not isinstance(data, dict):
                raise AuthzenError("the PDP's answer is not a JSON object")
            return data
        except AuthzenError as e:
            with self._lock:
                self.errors += 1
                self.last_error = (time.time(), str(e)[:300])
            raise

    # ------------------------------------------------------------------ the APIs
    @staticmethod
    def _decided(d) -> bool:
        return isinstance(d, dict) and d.get("decision") is True      # anything else is a deny (fail closed)

    def evaluate(self, subject, action, resource, context=None) -> bool:
        body = {"subject": subject, "action": action, "resource": resource}
        if context:
            body["context"] = context
        return self._decided(self._post("access_evaluation_endpoint", body))

    def evaluate_all(self, subject, items, context=None) -> bool:
        """True when every (action, resource) is permitted. One batch (deny_on_first_deny) when the PDP offers
        it, otherwise one evaluation at a time, stopping at the first deny."""
        if len(items) > 1 and self.supports("access_evaluations_endpoint"):
            body = {"subject": subject, "evaluations": [{"action": a, "resource": r} for a, r in items],
                    "options": {"evaluations_semantic": "deny_on_first_deny"}}
            if context:
                body["context"] = context
            out = self._post("access_evaluations_endpoint", body).get("evaluations")
            return isinstance(out, list) and len(out) == len(items) and all(self._decided(d) for d in out)
        return all(self.evaluate(subject, a, r, context) for a, r in items)

    def _search(self, endpoint, body, want_type, key):
        """All pages of a search, cached for cache_ttl seconds. -> [{id, properties}]"""
        ck = (endpoint, json.dumps(body, sort_keys=True))
        now = time.monotonic()
        if self.cache_ttl > 0:
            with self._lock:
                hit = self._cache.get(ck)
            if hit and now - hit[0] < self.cache_ttl:
                return hit[1]
        out, token = [], None
        for _ in range(MAX_PAGES):
            page = {"limit": PAGE_LIMIT} if token is None else {"limit": PAGE_LIMIT, "token": token}
            data = self._post(endpoint, dict(body, page=page))
            results = data.get("results")
            if not isinstance(results, list):
                raise AuthzenError("a search answer without `results`")
            for r in results:
                if isinstance(r, dict) and r.get(key) == want_type and isinstance(r.get("id"), (str, int)):
                    props = r.get("properties")
                    out.append({"id": str(r["id"]), "properties": props if isinstance(props, dict) else None})
            token = (data.get("page") or {}).get("next_token") if isinstance(data.get("page"), dict) else None
            if not token:
                break
        else:
            raise AuthzenError(f"more than {MAX_PAGES} pages of results: the search is too large to decide on")
        if self.cache_ttl > 0:
            with self._lock:
                if len(self._cache) > 2000:
                    self._cache.clear()
                self._cache[ck] = (now, out)
        return out

    def search_resources(self, subject, action, rtype, context=None) -> list:
        body = {"subject": subject, "action": action, "resource": {"type": rtype}}
        if context:
            body["context"] = context
        return self._search("search_resource_endpoint", body, rtype, "type")

    def search_subjects(self, stype, action, resource, context=None) -> list:
        body = {"subject": {"type": stype}, "action": action, "resource": resource}
        if context:
            body["context"] = context
        return self._search("search_subject_endpoint", body, stype, "type")

    def describe(self):
        return f"AuthZEN PDP {self.pdp}" + ("" if self.metadata is None else " (metadata)")


def client_from_env(env) -> AuthzenClient:
    """LAOCOON_AUTHZEN_PDP (its base URL), LAOCOON_AUTHZEN_TOKEN (bearer), LAOCOON_AUTHZEN_TIMEOUT (s),
    LAOCOON_AUTHZEN_CA (a CA bundle for the PDP's TLS), LAOCOON_AUTHZEN_CACHE_TTL (s, searches only)."""
    pdp = env("LAOCOON_AUTHZEN_PDP")
    if not pdp:
        raise ValueError("LAOCOON_AUTHZ_SOURCE=authzen needs LAOCOON_AUTHZEN_PDP (the PDP's base URL)")
    if not str(pdp).startswith("https://") and not str(pdp).startswith(("http://127.0.0.1", "http://localhost")):
        raise ValueError("LAOCOON_AUTHZEN_PDP must be https:// (AuthZEN 1.0: the PEP-PDP channel must be "
                         "secured); plain http is accepted only for localhost")
    return AuthzenClient(pdp, token=env("LAOCOON_AUTHZEN_TOKEN") or None,
                         timeout=float(env("LAOCOON_AUTHZEN_TIMEOUT") or 3),
                         verify=env("LAOCOON_AUTHZEN_CA") or True,
                         cache_ttl=float(env("LAOCOON_AUTHZEN_CACHE_TTL") or 2))

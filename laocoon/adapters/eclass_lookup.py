"""Athena eClass without its database (`LAOCOON_AUTHZ_SOURCE=lookup`).

The same vocabulary as `EclassAdapter` (constraints, filters, references, previews, authors), decided from facts the
proxy learns through eClass's own read tools instead of SQL (`facts.py`, `holds.py`). The app changes nothing: it
only points its OpenAI base URL at the proxy.

Where each fact comes from (tool → what is kept):

    list_courses           every course: id, code, title, teacher                  (the catalogue: complete)
    get_course(c)          who is enrolled in c, its assignments, the students' usernames and names
    list_assignments(c)    the assignments of c                                     (complete for c)
    list_exercises(c)      the exercises of c and whether each is open             (complete for c)
    get_submissions(a)     the submissions of a: id, student                       (complete for a)
    get_exercise_attempts(e)  who has attempted e                                   (complete for e)
    list_users             the directory (admin only)
    get_user(u)            username and role (identity check), current profile (previews only, never stored)
    get_grades, get_gradebook   current grades (previews only, never stored)

A lookup is *in scope* when the user could make that call anyway (list_courses; get_course of a course they teach;
...). It is *speculative* when it may read an object outside the user's scope, to find out whether it is in scope
(a student: get_course(c) to learn whether they are enrolled in c). Speculative lookups need
`lookups.out_of_scope: true` in the policy: their results never reach the model, but the app stores them in its own
chat history like any tool result, so the app must not show raw tool results to its users.
"""
from __future__ import annotations

from contextlib import contextmanager

from ..config import env
from ..facts import NeedFacts, Unverifiable, as_id, as_str, is_error, lookup, rows_of
from .base import UNRESOLVABLE
from .eclass import EclassAdapter, _id, _rows, is_read_only_sql

LOOKUP_TOOLS = ("list_courses", "get_course", "list_assignments", "list_exercises", "get_submissions",
                "get_exercise_attempts", "list_users", "get_user", "get_grades", "get_gradebook")
EPHEMERAL = ("final_grade", "component_grade", "submission_grade", "profile")   # previews: this request only
PROFILE_FIELDS = ("full_name", "email", "role", "phone", "address", "admin_notes", "iban")
MAX_SEARCH = 40                    # lookups one search may need (more → unverifiable, never a partial answer)


def _cf(s) -> str:
    return s.casefold() if isinstance(s, str) else ""


class EclassLookupAdapter(EclassAdapter):
    fact_sourced = True

    def __init__(self, tool_names=()):
        super().__init__(query=None, tool_names=tool_names)
        self.allowed = set(LOOKUP_TOOLS)
        self.out_of_scope = False
        self.verify = True
        self.ttl = {}

    def configure(self, policy_data):
        """Read `lookups` and `identity` from the policy. Operator override: LAOCOON_LOOKUPS=off (observe only:
        facts come only from calls the model made) | in_scope (no speculative lookups) | on (the policy decides)."""
        lk = policy_data.get("lookups") or {}
        tools = lk.get("tools")
        self.allowed = set(LOOKUP_TOOLS) & set(tools) if isinstance(tools, list) else set(LOOKUP_TOOLS)
        self.out_of_scope = lk.get("out_of_scope") is True
        self.ttl = {k: int(v) for k, v in (lk.get("ttl") or {}).items()
                    if k in ("read", "write", "identity") and isinstance(v, int) and v > 0}
        self.verify = (policy_data.get("identity") or {}).get("verify", True) is not False
        mode = (env("LAOCOON_LOOKUPS") or "on").strip().lower()
        if mode == "off":
            self.allowed, self.verify = set(), False
        elif mode == "in_scope":
            self.out_of_scope = False

    # ------------------------------------------------------------------ plumbing
    @staticmethod
    def _F(principal):
        fv = (principal or {}).get("attrs", {}).get("facts")
        if fv is None:
            raise Unverifiable("no facts for this request")
        return fv

    def _need(self, *lookups):
        lks = [lk for lk in lookups if lk is not None]
        for lk in lks:
            if lk.tool not in self.allowed:
                raise Unverifiable(f"lookup {lk.tool} not allowed")
            if lk.speculative and not self.out_of_scope:
                raise Unverifiable(f"out-of-scope lookup {lk.tool} not allowed")
        if len(lks) > MAX_SEARCH:
            raise Unverifiable("search too large")
        raise NeedFacts(lks)

    @staticmethod
    @contextmanager
    def _relaxed(F):
        old, F.relaxed = F.relaxed, True
        try:
            yield
        finally:
            F.relaxed = old

    # ------------------------------------------------------------------ facts
    def _catalogue(self, F) -> list[int]:
        d = F.get("catalogue", "", "scope")
        if d is None:
            self._need(lookup("list_courses"))
        return list(d["ids"])

    def _teacher(self, F, c):
        if c not in self._catalogue(F):
            return None
        d = F.get("course_teacher", c, "scope")
        if d is None:
            self._need(lookup("list_courses"))
        return d.get("teacher_id")

    def _taught(self, F, p) -> list[int]:
        return [c for c in self._catalogue(F) if self._teacher(F, c) == p["id"]]

    def _members(self, F, p, c) -> set:
        d = F.get("course_members", c, "scope")
        if d is None:
            spec = not (p["role"] == "admin" or self._teacher(F, c) == p["id"])
            self._need(lookup("get_course", course_ref=c, speculative=spec))
        return set(d["students"])

    def _members_many(self, F, p, courses) -> dict:
        """Members of several courses, asking for all the missing ones in one round."""
        missing = [c for c in courses if F.get("course_members", c, "scope") is None]
        if missing:
            self._need(*[lookup("get_course", course_ref=c,
                                speculative=not (p["role"] == "admin" or self._teacher(F, c) == p["id"]))
                         for c in missing])
        return {c: set(F.get("course_members", c, "scope")["students"]) for c in courses}

    def _parent(self, F, p, kind, oid, scope):
        """The course of an assignment or exercise, searching the courses in the user's scope first and the rest
        only if needed (speculative). None: not in any course (does not exist)."""
        d = F.get(kind, oid, "stable")
        if d is not None:
            return d.get("course_id")
        list_kind, tool = (("course_assignments", "list_assignments") if kind == "assignment"
                           else ("course_exercises", "list_exercises"))
        cat = self._catalogue(F)
        if scope == "taught":
            first, rest = self._taught(F, p), []
        else:
            first, rest = [], []
            for c in cat:
                m = F.get("course_members", c, "scope")
                (rest if m is None else first if p["id"] in m["students"] else []).append(c)
        for cands, spec in ((first, False), (rest, True)):
            missing = [c for c in cands if F.get(list_kind, c, "scope") is None]
            if missing:
                self._need(*[lookup(tool, course_ref=c, speculative=spec) for c in missing])
            d = F.get(kind, oid, "stable")
            if d is not None:
                return d.get("course_id")
        return None

    def _submission(self, F, p, sid):
        """The assignment of a submission, searching the assignments of the courses the user teaches."""
        d = F.get("submission", sid, "stable")
        if d is not None:
            return d.get("assignment_id")
        taught = self._taught(F, p)
        missing = [c for c in taught if F.get("course_assignments", c, "scope") is None]
        if missing:
            self._need(*[lookup("list_assignments", course_ref=c) for c in missing])
        aids = [a for c in taught for a in F.get("course_assignments", c, "scope")["ids"]]
        missing = [a for a in aids if F.get("assignment_submissions", a, "scope") is None]
        if missing:
            self._need(*[lookup("get_submissions", assignment_id=a) for a in missing])
        d = F.get("submission", sid, "stable")
        return d.get("assignment_id") if d else None

    # ------------------------------------------------------------------ identity
    def principal_by_id(self, uid):
        return None                      # no directory without the database: callers fail closed

    def principal_by_username(self, username):
        return None

    def verify_identity(self, principal) -> bool:
        """The DB cross-check of the system-prompt identity, done through get_user: the app's own record of this
        id must have the same username and role."""
        if not self.verify:
            return True
        F = self._F(principal)
        d = F.get("identity", principal["id"], "identity")
        if d is None:
            self._need(lookup("get_user", user_ref=principal["id"]))
        ok = d.get("username") == principal["username"] and d.get("role") == principal["role"]
        if not ok and not F.learned_now("identity", principal["id"]):
            self._need(lookup("get_user", user_ref=principal["id"]))   # a role change since: ask the app again
        return ok

    # ------------------------------------------------------------------ references -> ids
    def _is_self(self, p, s) -> bool:
        if s.isdigit():
            return _id(s) == p["id"]
        name = (p.get("attrs") or {}).get("full_name")
        return s == p["username"] or (bool(name) and _cf(s) == _cf(name))

    def _find_user(self, F, ids, s):
        """Today's three tiers inside `ids`: id; exact username or case-insensitive full name (unique); unique
        substring of the full name. -> id, or None (not found / ambiguous)."""
        if s.isdigit():
            uid = _id(s)
            return uid if uid in ids else None
        users = {u: F.get("user", u, "stable") or {} for u in ids}
        exact = [u for u, d in users.items() if d.get("username") == s or (d.get("name") and _cf(d["name"]) == _cf(s))]
        if exact:
            return exact[0] if len(exact) == 1 else None
        sub = [u for u, d in users.items() if d.get("name") and _cf(s) in _cf(d["name"])]
        return sub[0] if len(sub) == 1 else None

    def resolve(self, kind, ref, principal=None, bound=False):
        if ref is None or (isinstance(ref, str) and not ref.strip()):
            return None
        s = str(ref).strip()
        if kind == "user":
            if principal is not None and self._is_self(principal, s):
                return principal["id"]
            if bound or principal is None:
                return UNRESOLVABLE            # an identity argument is never looked up: it is the user or denied
            F = self._F(principal)
            if principal["role"] == "admin":
                d = F.get("directory", "", "scope")
                if d is None:
                    self._need(lookup("list_users"))
                return self._find_user(F, set(d["ids"]), s)
            if principal["role"] == "teacher":
                members = self._members_many(F, principal, self._taught(F, principal))
                ids = set().union(*members.values()) if members else set()
                uid = self._find_user(F, ids, s)
                return uid if uid is not None else UNRESOLVABLE
            return UNRESOLVABLE
        if kind == "course":
            F = self._F(principal)
            cat = self._catalogue(F)
            if s.isdigit():
                cid = _id(s)
                return cid if cid in cat else None
            info = {c: F.get("course", c, "stable") or {} for c in cat}
            code = s.upper().replace(" ", "")
            hits = [c for c, d in info.items() if d.get("code") == code]
            if hits:
                return hits[0]
            hits = [c for c, d in info.items() if _cf(s) in _cf(d.get("title"))]
            return hits[0] if len(hits) == 1 else None
        if kind in ("assignment", "submission", "exercise"):
            return _id(s)                      # existence and scope are settled by the constraint
        return super().resolve(kind, ref)

    # ------------------------------------------------------------------ ① ABAC constraints
    def constraint(self, name, principal, value, args):
        if value is None:
            return False
        if name == "read_only_sql":
            return is_read_only_sql(value)
        v = _id(value) if not isinstance(value, bool) else None
        if v is None:
            return False
        F, p = self._F(principal), principal
        if name == "self":
            return v == p["id"]
        if name == "taught":
            return self._teacher(F, v) == p["id"]
        if name == "enrolled":
            return v in self._catalogue(F) and p["id"] in self._members(F, p, v)
        if name == "student_of_taught":
            members = self._members_many(F, p, self._taught(F, p))
            return any(v in m for m in members.values())
        if name in ("enrolled_assignment", "taught_assignment"):
            scope = name.split("_")[0]
            c = self._parent(F, p, "assignment", v, scope)
            return c is not None and self.constraint(scope, p, c, args)
        if name in ("enrolled_exercise", "taught_exercise", "open_enrolled_exercise"):
            scope = "taught" if name == "taught_exercise" else "enrolled"
            c = self._parent(F, p, "exercise", v, scope)
            if c is None or not self.constraint(scope, p, c, args):
                return False
            if name == "open_enrolled_exercise":
                o = F.get("exercise_open", v, "volatile")
                if o is None:
                    self._need(lookup("list_exercises", course_ref=c))      # in scope: enrolled in c
                return bool(o.get("is_open"))
            return True
        if name == "taught_submission":
            a = self._submission(F, p, v)
            return a is not None and self.constraint("taught_assignment", p, a, args)
        if name == "not_attempted":
            a = F.get("attempts", v, "volatile")
            if a is None:
                e = F.get("exercise", v, "stable")
                m = F.get("course_members", e["course_id"], "scope") if e else None
                self._need(lookup("get_exercise_attempts", exercise_id=v,
                                  speculative=not (m and p["id"] in m["students"])))
            return p["id"] not in set(a["students"])
        raise KeyError(f"unknown constraint {name!r}")

    def choices(self, constraint, principal):
        """Enums only from facts already known: never a lookup just to decorate the tool list."""
        try:
            F = self._F(principal)
            if constraint == "taught":
                ids = self._taught(F, principal)
            elif constraint == "enrolled":
                ids = [c for c in self._catalogue(F) if principal["id"] in self._members(F, principal, c)]
            else:
                return None
            return sorted({(F.get("course", c, "stable") or {}).get("code") for c in ids} - {None})
        except (NeedFacts, Unverifiable):
            return None

    def derive(self, name, args, principal=None):
        if name == "submission_owner" and principal is not None:
            d = self._F(principal).get("submission", _id(args.get("submission_id")), "stable")
            return d.get("student_id") if d else None
        return None

    # ------------------------------------------------------------------ ① output filters
    def prepare_filter(self, name, principal, tool, args):
        """Raise NeedFacts when the filter will need facts to minimise the result of this call."""
        F = self._F(principal)
        if name == "taught_rows":
            self._taught(F, principal)
        elif name == "my_courses" and principal["role"] != "teacher":
            self._members_many(F, principal, self._catalogue(F))

    def apply_filter(self, name, principal, tool, result, args):
        if name not in ("my_courses", "taught_rows") or (isinstance(result, dict) and "error" in result):
            return super().apply_filter(name, principal, tool, result, args)
        rows = _rows(result)
        if rows is None:
            return result
        uid = principal["id"]
        if name == "my_courses" and principal["role"] == "teacher":
            return [r for r in rows if isinstance(r, dict) and as_id(r.get("teacher_id")) == uid]
        try:
            F = self._F(principal)
            with self._relaxed(F):
                if name == "taught_rows":
                    codes = {(F.get("course", c, "stable") or {}).get("code") for c in self._taught(F, principal)}
                    return [r for r in rows if isinstance(r, dict) and r.get("code") in codes]
                keep = []                                      # my_courses for a student: enrolled ones only
                for r in rows:
                    c = as_id(r.get("id")) if isinstance(r, dict) else None
                    m = F.get("course_members", c, "scope") if c is not None else None
                    if m is not None and uid in m["students"]:
                        keep.append(r)
                return keep
        except (NeedFacts, Unverifiable):
            return []                                          # facts missing: show nothing rather than too much

    # ------------------------------------------------------------------ ② authors
    @staticmethod
    def _who(p):
        return {"id": p["id"], "username": p["username"], "role": p["role"]}

    def authors_of(self, tool, args, result, spec, principal=None):
        try:
            F = self._F(principal)
        except Unverifiable:
            return []
        with self._relaxed(F):
            if spec == "course_teacher":
                cid = as_id((args or {}).get("course_ref"))
                t = (F.get("course_teacher", cid, "scope") or {}).get("teacher_id") if cid is not None else None
                if t is None:
                    return []
                if t == principal["id"]:
                    return [{**self._who(principal), "ref": f"course:{cid}"}]
                u = F.get("user", t, "stable") or {}
                return [{"id": t, "username": u.get("username"), "role": "teacher", "ref": f"course:{cid}"}]
            if not isinstance(spec, dict) or "author_field" not in spec:
                return []
            out = []
            for row in rows_of(result) or []:
                who = row.get(spec["author_field"])
                ref = f"{spec.get('ref', tool)}:{row.get(spec.get('id_field', 'id'))}"
                if who is None:
                    continue
                if who == principal["username"] or (as_id(who) is not None and as_id(who) == principal["id"]):
                    out.append({**self._who(principal), "ref": ref})
                    continue
                hit = F.get("user_name", who, "stable") if isinstance(who, str) else None
                uid = hit.get("id") if hit else as_id(who)
                u = F.get("user", uid, "stable") if uid is not None else None
                if u:                                          # known through the app's own data: attributed by id
                    out.append({"id": uid, "username": u.get("username"), "role": u.get("role"), "ref": ref})
                else:                                          # never guessed from the handle alone
                    out.append({"id": None, "username": None, "role": None, "handle": as_str(who, 64), "ref": ref})
            return out

    # ------------------------------------------------------------------ ④ previews
    def prepare_preview(self, tool, args, principal):
        """Raise NeedFacts for the current values an approval card shows (in-scope lookups only)."""
        F, a = self._F(principal), args or {}
        s, c = as_id(a.get("student_ref")), as_id(a.get("course_ref"))
        if tool == "set_final_grade" and s is not None and c is not None:
            if F.get("final_grade", f"{c}:{s}", "scope") is None:
                self._need(lookup("get_grades", student_ref=s, course_ref=c))
        elif tool == "set_component_grade" and c is not None:
            if F.get("component_grade", f"{c}:seen", "scope") is None:
                self._need(lookup("get_gradebook", course_ref=c))
        elif tool == "grade_submission":
            sid = as_id(a.get("submission_id"))
            sub = F.get("submission", sid, "stable") if sid is not None else None
            if sub and F.get("submission_grade", sid, "scope") is None:
                self._need(lookup("get_submissions", assignment_id=sub["assignment_id"]))
        elif tool == "update_user":
            u = as_id(a.get("user_ref"))
            if u is not None and F.get("profile", u, "scope") is None:
                self._need(lookup("get_user", user_ref=u))

    def _user_label(self, F, uid):
        if uid is None:
            return "—"
        u = F.get("user", as_id(uid), "stable") if as_id(uid) is not None else None
        if u and u.get("username"):
            return f"{u.get('name') or u['username']} ({u['username']})"
        return str(uid)

    def _course_label(self, F, cid):
        c = F.get("course", as_id(cid), "stable") if as_id(cid) is not None else None
        return f"{c.get('code')} {c.get('title') or ''}".strip() if c else str(cid)

    def preview(self, tool, args, principal):
        a = args or {}
        try:
            F = self._F(principal)
        except Unverifiable:
            return super(EclassAdapter, self).preview(tool, args, principal)
        rows, title = [], tool
        with self._relaxed(F):
            s, c = a.get("student_ref"), a.get("course_ref")
            if tool == "set_final_grade":
                title = "Αλλαγή τελικού βαθμού"
                old = (F.get("final_grade", f"{as_id(c)}:{as_id(s)}", "scope") or {}).get("grade")
                rows = [["Φοιτητής", self._user_label(F, s)], ["Μάθημα", self._course_label(F, c)],
                        ["Βαθμός", f"{old if old is not None else '—'} → {a.get('grade')}"]]
            elif tool == "set_component_grade":
                title = "Αλλαγή βαθμού σκέλους"
                u = F.get("user", as_id(s), "stable") or {} if as_id(s) is not None else {}
                key = f"{as_id(c)}:{_cf(a.get('component'))}:{u.get('username')}"
                old = (F.get("component_grade", key, "scope") or {}).get("grade")
                rows = [["Φοιτητής", self._user_label(F, s)], ["Μάθημα", self._course_label(F, c)],
                        ["Σκέλος", str(a.get("component"))], ["Βαθμός", f"{old if old is not None else '—'} → {a.get('grade')}"]]
            elif tool == "grade_submission":
                title = "Βαθμολόγηση υποβολής"
                sid = as_id(a.get("submission_id"))
                sub = F.get("submission", sid, "stable") or {} if sid is not None else {}
                old = (F.get("submission_grade", sid, "scope") or {}).get("grade") if sid is not None else None
                rows = [["Υποβολή", f"#{a.get('submission_id')}"], ["Φοιτητής", self._user_label(F, sub.get("student_id"))],
                        ["Βαθμός", f"{old if old is not None else '—'} → {a.get('grade')}"],
                        ["Σχόλιο", str(a.get("feedback") or "")[:200]]]
            elif tool == "send_message":
                title = "Αποστολή μηνύματος"
                to = a.get("to")
                rows = [["Προς", self._user_label(F, to) if as_id(to) is not None else str(to)],
                        ["Θέμα", str(a.get("subject") or "")], ["Κείμενο", str(a.get("body") or "")[:200]]]
            elif tool == "post_forum":
                title = "Ανάρτηση στο forum"
                rows = [["Μάθημα", self._course_label(F, c)], ["Τίτλος", str(a.get("title") or "")],
                        ["Κείμενο", str(a.get("body") or "")[:200]]]
            elif tool == "update_user":
                title = "Αλλαγή στοιχείων χρήστη"
                cur = F.get("profile", as_id(a.get("user_ref")), "scope") or {}
                rows = [["Χρήστης", self._user_label(F, a.get("user_ref"))]]
                for k, v in a.items():
                    if k != "user_ref" and v is not None:
                        rows.append([k, f"{cur.get(k, '—') if k not in ('iban',) else '***'} → {v}"])
            elif tool in ("reset_password", "delete_user"):
                title = "Επαναφορά κωδικού" if tool == "reset_password" else "Διαγραφή χρήστη"
                rows = [["Χρήστης", self._user_label(F, a.get("user_ref"))]]
                if tool == "reset_password":
                    rows.append(["Νέος κωδικός", "***" + str(a.get("new_password", ""))[-2:]])
            elif tool == "create_user":
                title = "Δημιουργία χρήστη"
                rows = [["Username", str(a.get("username"))], ["Όνομα", str(a.get("full_name"))], ["Ρόλος", str(a.get("role"))]]
            elif tool == "publish_grades":
                title = "Δημοσίευση βαθμών" if a.get("published", True) else "Απόκρυψη βαθμών"
                rows = [["Μάθημα", self._course_label(F, c)], ["Σκέλος", str(a.get("component") or "τελικοί βαθμοί")]]
            elif tool == "enroll_user":
                title = "Εγγραφή σε μάθημα"
                rows = [["Χρήστης", self._user_label(F, a.get("user_ref"))], ["Μάθημα", self._course_label(F, c)]]
            else:
                return super(EclassAdapter, self).preview(tool, args, principal)
        return {"title": title, "rows": rows}

    # ------------------------------------------------------------------ learning facts from tool results
    def ingest(self, F, tool, args, result, at=None):
        persist, ephemeral = self.extract(tool, args or {}, result)
        F.put_many(persist, at=at)
        F.put_many(ephemeral, at=at, persist=False)           # previews: kept for this request only
        return len(persist) + len(ephemeral)

    def extract(self, tool, args, result):
        """-> (facts to store, facts for this request only). Only declared structural fields, type-checked."""
        out, eph = [], []
        if result is None or is_error(result):
            return out, eph

        def user(r, uid_key="id", name_key="full_name", role=None):
            uid, uname = as_id(r.get(uid_key)), as_str(r.get("username"), 64)
            if uid is None or not uname:
                return
            d = {"username": uname, "name": as_str(r.get(name_key), 128)}
            if role:
                d["role"] = role
            out.append(("user", uid, d))
            out.append(("user_name", uname, {"id": uid}))

        if tool == "list_courses":
            rows = rows_of(result)
            if rows is None:
                return out, eph
            ids = []
            for r in rows:
                cid = as_id(r.get("id"))
                if cid is None:
                    continue
                ids.append(cid)
                out.append(("course", cid, {"code": as_str(r.get("code"), 64), "title": as_str(r.get("title"), 200)}))
                out.append(("course_teacher", cid, {"teacher_id": as_id(r.get("teacher_id"))}))
            out.append(("catalogue", "", {"ids": ids}))
        elif tool == "get_course" and isinstance(result, dict):
            cid = as_id(result.get("id"))
            if cid is None:
                return out, eph
            out.append(("course", cid, {"code": as_str(result.get("code"), 64), "title": as_str(result.get("title"), 200)}))
            out.append(("course_teacher", cid, {"teacher_id": as_id(result.get("teacher_id"))}))
            students = result.get("students")
            if isinstance(students, list):
                ids = [as_id(s.get("id")) for s in students if isinstance(s, dict)]
                out.append(("course_members", cid, {"students": [i for i in ids if i is not None]}))
                for s in students:
                    if isinstance(s, dict):
                        user(s)
            assignments = result.get("assignments")
            if isinstance(assignments, list):
                aids = [as_id(x.get("id")) for x in assignments if isinstance(x, dict)]
                out.append(("course_assignments", cid, {"ids": [a for a in aids if a is not None]}))
                out.extend(("assignment", a, {"course_id": cid}) for a in aids if a is not None)
        elif tool in ("list_assignments", "list_exercises"):
            rows, cid = rows_of(result), as_id(args.get("course_ref"))
            if rows is None or cid is None:
                return out, eph
            kind, list_kind = ("assignment", "course_assignments") if tool == "list_assignments" else ("exercise", "course_exercises")
            ids = []
            for r in rows:
                oid = as_id(r.get("id"))
                if oid is None or as_id(r.get("course_id")) != cid:
                    continue
                ids.append(oid)
                out.append((kind, oid, {"course_id": cid}))
                if kind == "exercise":
                    out.append(("exercise_open", oid, {"is_open": bool(r.get("is_open"))}))
            out.append((list_kind, cid, {"ids": ids}))
        elif tool == "get_exercise" and isinstance(result, dict):
            eid, cid = as_id(result.get("id")), as_id(result.get("course_id"))
            if eid is not None and cid is not None:
                out.append(("exercise", eid, {"course_id": cid}))
                out.append(("exercise_open", eid, {"is_open": bool(result.get("is_open"))}))
        elif tool == "get_submissions":
            rows, aid = rows_of(result), as_id(args.get("assignment_id"))
            if rows is None or aid is None:
                return out, eph
            ids = []
            for r in rows:
                sid, st = as_id(r.get("id")), as_id(r.get("student_id"))
                if sid is None or as_id(r.get("assignment_id")) not in (None, aid):
                    continue
                ids.append(sid)
                out.append(("submission", sid, {"assignment_id": aid, "student_id": st}))
                eph.append(("submission_grade", sid, {"grade": r.get("grade") if isinstance(r.get("grade"), (int, float)) else None}))
                if st is not None:
                    user(r, uid_key="student_id")
            out.append(("assignment_submissions", aid, {"ids": ids}))
        elif tool == "get_exercise_attempts":
            rows, eid = rows_of(result), as_id(args.get("exercise_id"))
            if rows is not None and eid is not None:
                out.append(("attempts", eid, {"students": [i for i in (as_id(r.get("student_id")) for r in rows)
                                                            if i is not None]}))
        elif tool in ("list_users", "get_user"):
            rows = rows_of(result) if tool == "list_users" else ([result] if isinstance(result, dict) else None)
            if rows is None:
                return out, eph
            ids = []
            for r in rows:
                uid, uname, role = as_id(r.get("id")), as_str(r.get("username"), 64), as_str(r.get("role"), 32)
                if uid is None or not uname:
                    continue
                ids.append(uid)
                user(r, role=role)
                out.append(("identity", uid, {"username": uname, "role": role}))
                if tool == "get_user":
                    eph.append(("profile", uid, {k: as_str(r.get(k), 200) for k in PROFILE_FIELDS}))
            if tool == "list_users" and not args.get("role"):
                out.append(("directory", "", {"ids": ids}))
        elif tool == "get_grades":
            rows, s, c = rows_of(result), as_id(args.get("student_ref")), as_id(args.get("course_ref"))
            if rows is not None and s is not None and c is not None and len(rows) <= 1:
                g = rows[0].get("grade") if rows else None
                eph.append(("final_grade", f"{c}:{s}", {"grade": g if isinstance(g, (int, float)) else None}))
        elif tool == "get_gradebook" and isinstance(result, dict):
            c = as_id(args.get("course_ref"))
            comps = result.get("components")
            if c is not None and isinstance(comps, list):
                eph.append(("component_grade", f"{c}:seen", {"grade": None}))
                for comp in comps:
                    if not isinstance(comp, dict) or not isinstance(comp.get("grades"), list):
                        continue
                    for g in comp["grades"]:
                        if isinstance(g, dict) and as_str(g.get("username"), 64):
                            v = g.get("grade")
                            eph.append(("component_grade", f"{c}:{_cf(comp.get('name'))}:{g['username']}",
                                        {"grade": v if isinstance(v, (int, float)) else None}))
        return out, eph

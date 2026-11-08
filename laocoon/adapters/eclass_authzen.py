"""Athena eClass over an AuthZEN policy decision point (`LAOCOON_AUTHZ_SOURCE=authzen`).

The same vocabulary as `EclassAdapter`. Constraints, references, scope enums, identity and relations to users come
from the PDP (AuthzenAdapter). eClass's result filters and approval-card layouts are its own pure code; the few
reads they make go to the PDP:
  - `my_courses` / `taught_rows`: the user's scope (Resource Search);
  - labels on cards: the directory search's properties;
  - the teacher of a course (G2 attribution) and the student of a submission: Subject Search.

There is no database here: `q` raises, so any raw query left in inherited code fails closed. Before-values (old
grades) are not decisions and are not asked for; cards show "—".
"""
from __future__ import annotations

import threading

from ..facts import Unverifiable
from .authzen import AuthzenAdapter
from .eclass import EclassAdapter, _rows, is_read_only_sql


class EclassAuthzenAdapter(AuthzenAdapter, EclassAdapter):
    PURE_CONSTRAINTS = {"read_only_sql": is_read_only_sql}

    def __init__(self, client=None, config=None, tool_names=(), env=None):
        AuthzenAdapter.__init__(self, client, config, tool_names, env=env)
        self._local = threading.local()

    @property
    def q(self):
        def no_database(*a, **kw):
            raise Unverifiable("there is no database in AuthZEN mode")
        return no_database

    # ------------------------------------------------------------------ filters that need the scope
    def apply_filter(self, name, principal, tool, result, args):
        if isinstance(result, dict) and "error" in result:
            return result
        if name not in ("my_courses", "taught_rows"):
            return EclassAdapter.apply_filter(self, name, principal, tool, result, args)
        rows = _rows(result)
        if rows is None:
            return result
        try:
            if name == "taught_rows":
                codes = self.scope_values("taught", principal, "code")
                return [r for r in rows if r.get("code") in codes]
            ids = self.scope_ids("taught" if principal["role"] == "teacher" else "enrolled", principal)
            return [r for r in rows if r.get("id") in ids]
        except Unverifiable:                         # the PDP cannot say what is in scope: drop the rows
            return [] if isinstance(result, list) else {**result, "rows": []}

    # ------------------------------------------------------------------ ② attribution
    def _user(self, uid, principal):
        props = self.properties("user", uid, principal) or {}
        return {"id": uid, "username": props.get("username"), "role": props.get("role"),
                "attrs": {"full_name": props.get("name")}}

    def authors_of(self, tool, args, result, spec, principal=None):
        if spec == "course_teacher":
            cid = (args or {}).get("course_ref")
            try:
                teachers = self.follow("course.teacher", cid) if cid is not None else []
            except Unverifiable:
                teachers = []
            if len(teachers) != 1:
                return []
            t = teachers[0]
            who = ({"id": int(principal["id"]), "username": principal.get("username"), "role": principal.get("role")}
                   if principal is not None and t == int(principal["id"]) else self._user(t, principal))
            return [{**who, "ref": f"course:{cid}"}]
        return AuthzenAdapter.authors_of(self, tool, args, result, spec, principal=principal)

    # ------------------------------------------------------------------ ④ approval cards
    def preview(self, tool, args, principal):
        self._local.p = principal                    # the labels are looked up as this user
        try:
            return EclassAdapter.preview(self, tool, args, principal)
        finally:
            self._local.p = None

    def _user_label(self, uid):
        return self.label("user", uid, getattr(self._local, "p", None)) if uid else str(uid)

    def _course_label(self, cid):
        return self.label("course", cid, getattr(self._local, "p", None)) if cid else str(cid)

    def _old_final_grade(self, course_id, student_id):
        return "—"                                   # values, not decisions: not asked for

    def _old_component_grade(self, course_id, component, student_id):
        return "—"

    def _submission_info(self, submission_id) -> dict:
        try:
            students = self.follow("submission.student", submission_id)
        except Unverifiable:
            students = []
        return {"student_id": students[0] if len(students) == 1 else None, "title": "", "grade": None}

    def _current_user(self, user_id) -> dict:
        props = self.properties("user", user_id, getattr(self._local, "p", None)) or {}
        return {"username": props.get("username"), "full_name": props.get("name"), "role": props.get("role")} \
            if props else {}

    def grade_snapshot(self, student_id):
        raise NotImplementedError("there is no database in AuthZEN mode")

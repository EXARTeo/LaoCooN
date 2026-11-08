"""Athena eClass through views (`LAOCOON_AUTHZ_SOURCE=views`): the same vocabulary as `EclassAdapter`, but every
read of the app's data goes through the views of the policy's `data_model` (laocoon/views.py).

What comes from where:
  - constraints, references, scope enums, derive, identity: compiled from the model (ViewsAdapter);
  - result filters and the approval cards' layout: EclassAdapter's own code, which is pure except for a few reads,
    redirected here to the views (taught/enrolled courses, labels, the teacher of a course, the submission graded);
  - before-values on approval cards: the optional prev_* views (personal data). Without them the cards show "—";
    component grades and the current profile beyond name and role are never read.

`q` is the views connection itself: any raw query against an app table that slipped through would be refused by
the database (PostgreSQL) or by Laocoon's authorizer (SQLite), and the decision would fail closed.
"""
from __future__ import annotations

from ..facts import Unverifiable
from .eclass import EclassAdapter, _rows, is_read_only_sql
from .views import MISSING, ViewsAdapter


class EclassViewsAdapter(ViewsAdapter, EclassAdapter):
    PURE_CONSTRAINTS = {"read_only_sql": is_read_only_sql}

    def __init__(self, db=None, model=None, tool_names=(), env=None):
        ViewsAdapter.__init__(self, db, model, tool_names, env=env)

    @property
    def q(self):                                     # a tripwire, not a way in: see the module docstring
        return self.db.query

    # ------------------------------------------------------------------ the few reads in EclassAdapter's own code
    def taught_courses(self, uid):
        return self.scope_ids("taught", uid)

    def enrolled_courses(self, uid):
        return self.scope_ids("enrolled", uid)

    def _user_label(self, uid):
        return self.label("user", uid) if uid else str(uid)

    def _course_label(self, cid):
        return self.label("course", cid) if cid else str(cid)

    def apply_filter(self, name, principal, tool, result, args):
        if isinstance(result, dict) and "error" in result:
            return result
        try:
            if name == "taught_rows":
                rows = _rows(result)
                if rows is None:
                    return result
                codes = self.scope_values("taught", principal["id"], "code")
                return [r for r in rows if r.get("code") in codes]
            return EclassAdapter.apply_filter(self, name, principal, tool, result, args)
        except Unverifiable:                         # the database cannot say what is in scope: drop the rows
            rows = _rows(result)
            if rows is None:
                return result
            return [] if isinstance(result, list) else {**result, "rows": []}

    def authors_of(self, tool, args, result, spec):
        if spec == "course_teacher":
            cid = args.get("course_ref")
            try:
                teachers = self.follow("course.teacher", cid) if cid else []
            except Unverifiable:
                teachers = []
            p = self.principal_by_id(teachers[0]) if len(teachers) == 1 else None
            return [{**p, "ref": f"course:{cid}"}] if p else []
        return EclassAdapter.authors_of(self, tool, args, result, spec)

    # ------------------------------------------------------------------ approval cards
    @staticmethod
    def _shown(v):
        return "—" if v is None or v is MISSING else v

    def _old_final_grade(self, course_id, student_id):
        return self._shown(self.before("final_grade", course=course_id, student=student_id))

    def _old_component_grade(self, course_id, component, student_id):
        return "—"                                   # not in the model: never read

    def _submission_info(self, submission_id) -> dict:
        try:
            students = self.follow("submission.student", submission_id)
            assignments = self.follow("submission.assignment", submission_id)
            a = self.fields("assignment", assignments[0]) if len(assignments) == 1 else None
        except Unverifiable:
            return {}
        grade = self.before("submission_grade", submission=submission_id)
        return {"student_id": students[0] if len(students) == 1 else None,
                "title": (a or {}).get("title", ""), "grade": None if grade is MISSING else grade}

    def _current_user(self, user_id) -> dict:
        """Only what the views show (name and role); the rest of the profile shows as "—"."""
        try:
            r = self.fields("user", user_id)
        except Unverifiable:
            return {}
        return {"username": r.get("username"), "full_name": r.get("name"), "role": r.get("role")} if r else {}

    def grade_snapshot(self, student_id):
        raise NotImplementedError("grades are not readable through the views")

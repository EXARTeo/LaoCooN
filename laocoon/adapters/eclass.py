"""Adapter for Athena eClass.

Takes a `query(sql, args=(), one=False)` function: inside the app it is `app.db.query`, inside the
proxy a read-only SQLite connection (see `readonly_query`). It never writes to the app database.
"""
from __future__ import annotations

import json
import re
import sqlite3

from .base import BaseAdapter

PUBLIC_PROFILE = ("id", "username", "full_name", "email", "role", "student_number", "department", "year_of_study")
PII = ("password_hash", "amka", "iban", "id_card", "phone", "address", "date_of_birth", "admin_notes",
       "father_name")

# Anything that writes, changes the schema, touches other files or loads code. `WITH … DELETE`, `REPLACE INTO`
# and friends are caught by the token scan, not by the first keyword.
_SQL_DENY = re.compile(r"\b(insert|update|delete|replace|drop|create|alter|truncate|attach|detach|pragma|vacuum|"
                       r"reindex|analyze|load_extension|writefile|readfile)\b", re.IGNORECASE)
_SQL_FIRST_WORD = re.compile(r"[A-Za-z_]+")


def is_read_only_sql(sql) -> bool:
    """One SELECT/WITH statement and nothing else. Port of mAgenticX `_validate_read_only_sql` with SQLite's
    extra tokens; needed because the app's run_sql COMMITS every statement that is not a SELECT.
    No comments at all: comment-splitting (`DEL/**/ETE`) is the documented way past a token denylist."""
    if not isinstance(sql, str):
        return False
    cleaned = sql.strip()
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if not cleaned:
        return False
    if "--" in cleaned or "/*" in cleaned or "*/" in cleaned:
        return False
    if ";" in cleaned:                                   # a second statement
        return False
    first = _SQL_FIRST_WORD.match(cleaned)
    if not first or first.group(0).lower() not in ("select", "with"):
        return False
    return not _SQL_DENY.search(cleaned)


def readonly_query(db_path):
    """query() over a read-only connection, one connection per call (safe across threads)."""
    def query(sql, args=(), one=False):
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
        finally:
            conn.close()
        return (rows[0] if rows else None) if one else rows
    return query


def _id(s) -> int | None:
    """A platform id written by the model: a non-negative integer that fits SQLite's INTEGER, else None
    (so `1e999`, `nan` or a 25-digit number is "not found", never an exception out of the gate)."""
    try:
        v = int(s) if isinstance(s, int) and not isinstance(s, bool) else int(float(str(s).strip()))
    except (TypeError, ValueError, OverflowError):
        return None
    return v if 0 <= v < 2 ** 53 else None


def _rows(result):
    if isinstance(result, list):
        return result
    if isinstance(result, dict) and isinstance(result.get("rows"), list):
        return result["rows"]
    return None


def _drop_keys(obj, keys):
    if isinstance(obj, list):
        return [_drop_keys(x, keys) for x in obj]
    if isinstance(obj, dict):
        return {k: _drop_keys(v, keys) for k, v in obj.items() if k not in keys}
    return obj


class EclassAdapter(BaseAdapter):
    # What the policy YAML may name with this adapter (shown and checked by the policy studio). Keep in sync
    # with constraint(), apply_filter(), resolve() and authors_of() below.
    CONSTRAINTS = {
        "self": ("ο ίδιος ο συνδεδεμένος χρήστης", "id"),
        "enrolled": ("μάθημα στο οποίο είναι εγγεγραμμένος", "id"),
        "taught": ("μάθημα που διδάσκει", "id"),
        "student_of_taught": ("φοιτητής σε μάθημα που διδάσκει", "id"),
        "enrolled_assignment": ("εργασία μαθήματος όπου είναι εγγεγραμμένος", "id"),
        "taught_assignment": ("εργασία μαθήματος που διδάσκει", "id"),
        "enrolled_exercise": ("άσκηση μαθήματος όπου είναι εγγεγραμμένος", "id"),
        "taught_exercise": ("άσκηση μαθήματος που διδάσκει", "id"),
        "open_enrolled_exercise": ("ανοιχτή άσκηση μαθήματος όπου είναι εγγεγραμμένος", "id"),
        "taught_submission": ("υποβολή σε μάθημα που διδάσκει", "id"),
        "not_attempted": ("άσκηση που δεν έχει ήδη επιχειρήσει", "id"),
        "read_only_sql": ("ένα μόνο SELECT/WITH, χωρίς εντολές εγγραφής", "text"),
    }
    FILTERS = {
        "drop_password_hash": "αφαιρεί το hash του κωδικού",
        "drop_admin_notes": "αφαιρεί τις σημειώσεις διαχειριστή",
        "public_profile": "κρατά μόνο το δημόσιο προφίλ",
        "drop_enrollment_key": "αφαιρεί το κλειδί εγγραφής μαθήματος",
        "drop_students": "αφαιρεί τη λίστα φοιτητών",
        "student_names_only": "φοιτητές μόνο με όνομα και username",
        "visible_only": "μόνο ορατό υλικό",
        "drop_answers": "αφαιρεί σωστές απαντήσεις και επεξηγήσεις",
        "own_rows": "μόνο οι δικές του γραμμές",
        "published_only": "μόνο δημοσιευμένοι βαθμοί",
        "taught_rows": "μόνο μαθήματα που διδάσκει",
        "my_courses": "μόνο τα δικά του μαθήματα",
        "open_only": "μόνο ανοιχτές ασκήσεις",
    }
    REF_KINDS = {"user": "χρήστης", "course": "μάθημα", "assignment": "εργασία", "submission": "υποβολή",
                 "exercise": "άσκηση"}
    UNTRUSTED_OUTPUT = {"course_teacher": "συγγραφέας είναι ο διδάσκων του μαθήματος"}

    def __init__(self, query, tool_names=()):
        self.q = query
        self.tool_names = list(tool_names)

    def catalog(self) -> dict:
        return {"strict": True,
                "constraints": {k: {"label": lbl, "value": v} for k, (lbl, v) in self.CONSTRAINTS.items()},
                "filters": dict(self.FILTERS), "ref_kinds": dict(self.REF_KINDS),
                "untrusted_output": dict(self.UNTRUSTED_OUTPUT)}

    # ------------------------------------------------------------------ identity
    def principal(self, user):
        return {"id": int(user["id"]), "username": user["username"], "role": user["role"],
                "attrs": {"full_name": user.get("full_name")}}

    def principal_by_id(self, uid):
        uid = _id(uid)
        if uid is None:
            return None
        u = self.q("SELECT id, username, role, full_name FROM users WHERE id = ?", (uid,), one=True)
        return self.principal(u) if u else None

    def principal_by_username(self, username):
        u = self.q("SELECT id, username, role, full_name FROM users WHERE username = ?", (str(username),), one=True)
        return self.principal(u) if u else None

    # ------------------------------------------------------------------ references -> ids
    def resolve(self, kind, ref):
        if ref is None or (isinstance(ref, str) and not ref.strip()):
            return None
        s = str(ref).strip()
        if kind == "user":
            if s.isdigit():
                uid = _id(s)
                r = self.q("SELECT id FROM users WHERE id = ?", (uid,), one=True) if uid is not None else None
                return r["id"] if r else None
            r = self.q("SELECT id FROM users WHERE username = ? OR lower(full_name) = lower(?)", (s, s))
            if len(r) == 1:
                return r[0]["id"]
            if r:
                return None
            r = self.q("SELECT id FROM users WHERE full_name LIKE ?", (f"%{s}%",))
            return r[0]["id"] if len(r) == 1 else None   # ambiguous -> None (deny), never "first match"
        if kind == "course":
            if s.isdigit():
                cid = _id(s)
                r = self.q("SELECT id FROM courses WHERE id = ?", (cid,), one=True) if cid is not None else None
                return r["id"] if r else None
            r = self.q("SELECT id FROM courses WHERE code = ?", (s.upper().replace(" ", ""),), one=True)
            if r:
                return r["id"]
            r = self.q("SELECT id FROM courses WHERE title LIKE ?", (f"%{s}%",))
            return r[0]["id"] if len(r) == 1 else None
        table = {"assignment": "assignments", "submission": "submissions", "exercise": "exercises"}.get(kind)
        if table:
            oid = _id(s)
            if oid is None:
                return None
            r = self.q(f"SELECT id FROM {table} WHERE id = ?", (oid,), one=True)
            return r["id"] if r else None
        return super().resolve(kind, ref)

    # ------------------------------------------------------------------ private_data: whose data a row holds
    def subject_of(self, tool, args, row):
        """The user a result row is about (users rows, students lists, submissions), or None."""
        if not isinstance(row, dict):
            return None
        if row.get("student_id") is not None:
            return _id(row.get("student_id"))
        if row.get("username") is not None and row.get("id") is not None and tool in (
                "list_users", "get_user", "get_course", "run_sql"):
            return _id(row.get("id"))
        return None

    # ------------------------------------------------------------------ helpers
    def _enrolled(self, uid, course_id):
        return bool(self.q("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?", (uid, course_id), one=True))

    def _teaches(self, uid, course_id):
        return bool(self.q("SELECT 1 FROM courses WHERE id = ? AND teacher_id = ?", (course_id, uid), one=True))

    def _course_of(self, kind, obj_id):
        sql = {
            "assignment": "SELECT course_id FROM assignments WHERE id = ?",
            "exercise": "SELECT course_id FROM exercises WHERE id = ?",
            "submission": "SELECT a.course_id FROM submissions s JOIN assignments a ON a.id = s.assignment_id WHERE s.id = ?",
        }[kind]
        r = self.q(sql, (obj_id,), one=True)
        return r["course_id"] if r else None

    def taught_courses(self, uid):
        return {r["id"] for r in self.q("SELECT id FROM courses WHERE teacher_id = ?", (uid,))}

    def enrolled_courses(self, uid):
        return {r["course_id"] for r in self.q("SELECT course_id FROM enrollments WHERE user_id = ?", (uid,))}

    # ------------------------------------------------------------------ ① ABAC constraints
    def choices(self, constraint, principal):
        """The course codes behind `enrolled` / `taught`: offered to the model as an enum by the firewall."""
        uid = principal["id"]
        if constraint == "enrolled":
            rows = self.q("SELECT c.code FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = ?",
                          (uid,))
        elif constraint == "taught":
            rows = self.q("SELECT code FROM courses WHERE teacher_id = ?", (uid,))
        else:
            return None
        return sorted({r["code"] for r in rows if r.get("code")})

    def constraint(self, name, principal, value, args):
        uid = principal["id"]
        if value is None:
            return False
        if name == "read_only_sql":                      # the value is the SQL text, not an id
            return is_read_only_sql(value)
        v = _id(value)
        if v is None:                                    # an id constraint on something that is not an id
            return False
        if name == "self":
            return v == uid
        if name == "enrolled":
            return self._enrolled(uid, v)
        if name == "taught":
            return self._teaches(uid, v)
        if name == "student_of_taught":
            return bool(self.q("SELECT 1 FROM enrollments e JOIN courses c ON c.id = e.course_id "
                               "WHERE e.user_id = ? AND c.teacher_id = ?", (v, uid), one=True))
        if name in ("enrolled_assignment", "taught_assignment", "enrolled_exercise", "taught_exercise",
                    "taught_submission", "open_enrolled_exercise"):
            kind = "assignment" if "assignment" in name else "submission" if "submission" in name else "exercise"
            cid = self._course_of(kind, v)
            if cid is None:
                return False
            if name == "open_enrolled_exercise":
                ex = self.q("SELECT is_open FROM exercises WHERE id = ?", (v,), one=True)
                return bool(ex and ex["is_open"]) and self._enrolled(uid, cid)
            return self._teaches(uid, cid) if name.startswith("taught") else self._enrolled(uid, cid)
        if name == "not_attempted":
            return not self.q("SELECT 1 FROM exercise_attempts WHERE exercise_id = ? AND student_id = ?",
                              (v, uid), one=True)
        raise KeyError(f"unknown constraint {name!r}")

    def derive(self, name, args):
        if name == "submission_owner":
            sid = args.get("submission_id")
            r = self.q("SELECT student_id FROM submissions WHERE id = ?", (sid,), one=True) if sid is not None else None
            return r["student_id"] if r else None
        return None

    # ------------------------------------------------------------------ ① output filters (GDPR minimisation)
    def apply_filter(self, name, principal, tool, result, args):
        uid = principal["id"]
        if isinstance(result, dict) and "error" in result:
            return result
        if name == "drop_password_hash":
            return _drop_keys(result, {"password_hash"})
        if name == "drop_admin_notes":
            return _drop_keys(result, {"admin_notes"})
        if name == "public_profile":
            keep = lambda r: {k: v for k, v in r.items() if k in PUBLIC_PROFILE} if isinstance(r, dict) else r
            rows = _rows(result)
            return [keep(r) for r in rows] if rows is not None else keep(result)
        if name == "drop_enrollment_key":
            return _drop_keys(result, {"enrollment_key"})
        if name == "drop_students":
            return {k: v for k, v in result.items() if k != "students"} if isinstance(result, dict) else result
        if name == "student_names_only" and isinstance(result, dict) and isinstance(result.get("students"), list):
            return {**result, "students": [{k: s.get(k) for k in ("id", "username", "full_name")} for s in result["students"]]}
        if name == "visible_only" and isinstance(result, dict) and isinstance(result.get("materials"), list):
            return {**result, "materials": [m for m in result["materials"] if m.get("visible")]}
        if name == "drop_answers":
            return _drop_keys(result, {"correct_answer", "explanation"})
        if name == "own_rows":
            rows = _rows(result)
            if rows is None:
                return result
            mine = [r for r in rows if isinstance(r, dict) and
                    (r.get("student_id") == uid or r.get("username") == principal["username"])]
            return mine if isinstance(result, list) else {**result, "rows": mine}
        if name == "published_only":
            rows = _rows(result)
            return [r for r in rows if r.get("published")] if rows is not None else result
        if name == "taught_rows":
            rows = _rows(result)
            if rows is None:
                return result
            codes = {r["code"] for r in self.q("SELECT code FROM courses WHERE teacher_id = ?", (uid,))}
            return [r for r in rows if r.get("code") in codes]
        if name == "my_courses":
            rows = _rows(result)
            if rows is None:
                return result
            ids = self.taught_courses(uid) if principal["role"] == "teacher" else self.enrolled_courses(uid)
            return [r for r in rows if r.get("id") in ids]
        if name == "open_only":
            rows = _rows(result)
            return [r for r in rows if r.get("is_open")] if rows is not None else result
        raise KeyError(f"unknown filter {name!r}")

    # ------------------------------------------------------------------ ② Siren Guard: who wrote what was read (G2 sources)
    def authors_of(self, tool, args, result, spec):
        if spec == "course_teacher":
            cid = args.get("course_ref")
            r = self.q("SELECT teacher_id FROM courses WHERE id = ?", (cid,), one=True) if cid else None
            p = self.principal_by_id(r["teacher_id"]) if r else None
            return [{**p, "ref": f"course:{cid}"}] if p else []
        return super().authors_of(tool, args, result, spec)

    # ------------------------------------------------------------------ ④ Bound approvals: approval previews
    def _user_label(self, uid):
        u = self.q("SELECT username, full_name FROM users WHERE id = ?", (uid,), one=True) if uid else None
        return f"{u['full_name']} ({u['username']})" if u else str(uid)

    def _course_label(self, cid):
        c = self.q("SELECT code, title FROM courses WHERE id = ?", (cid,), one=True) if cid else None
        return f"{c['code']} {c['title']}" if c else str(cid)

    # the values before the change, shown on approval cards (the views adapter overrides these: it may not read them)
    def _old_final_grade(self, course_id, student_id):
        old = self.q("SELECT grade FROM final_grades WHERE course_id = ? AND student_id = ?",
                     (course_id, student_id), one=True)
        return old["grade"] if old else "—"

    def _old_component_grade(self, course_id, component, student_id):
        old = self.q("SELECT cg.grade FROM component_grades cg JOIN grade_components gc ON gc.id = cg.component_id "
                     "WHERE gc.course_id = ? AND gc.name LIKE ? AND cg.student_id = ?",
                     (course_id, f"%{component}%", student_id), one=True)
        return old["grade"] if old else "—"

    def _submission_info(self, submission_id) -> dict:
        """{grade, student_id, title}: the submission being graded."""
        return self.q("SELECT s.grade, s.student_id, a.title FROM submissions s JOIN assignments a ON a.id = s.assignment_id "
                      "WHERE s.id = ?", (submission_id,), one=True) or {}

    def _current_user(self, user_id) -> dict:
        return self.q("SELECT * FROM users WHERE id = ?", (user_id,), one=True) or {}

    def preview(self, tool, args, principal):
        a = args or {}
        rows = []
        title = tool
        try:
            if tool == "set_final_grade":
                title = "Αλλαγή τελικού βαθμού"
                old = self._old_final_grade(a.get("course_ref"), a.get("student_ref"))
                rows = [["Φοιτητής", self._user_label(a.get("student_ref"))], ["Μάθημα", self._course_label(a.get("course_ref"))],
                        ["Βαθμός", f"{old} → {a.get('grade')}"]]
            elif tool == "set_component_grade":
                title = "Αλλαγή βαθμού σκέλους"
                old = self._old_component_grade(a.get("course_ref"), a.get("component", ""), a.get("student_ref"))
                rows = [["Φοιτητής", self._user_label(a.get("student_ref"))], ["Μάθημα", self._course_label(a.get("course_ref"))],
                        ["Σκέλος", str(a.get("component"))], ["Βαθμός", f"{old} → {a.get('grade')}"]]
            elif tool == "grade_submission":
                title = "Βαθμολόγηση υποβολής"
                s = self._submission_info(a.get("submission_id"))
                rows = [["Υποβολή", f"#{a.get('submission_id')} {s.get('title', '')}"], ["Φοιτητής", self._user_label(s.get("student_id"))],
                        ["Βαθμός", f"{s.get('grade') if s.get('grade') is not None else '—'} → {a.get('grade')}"],
                        ["Σχόλιο", str(a.get("feedback") or "")[:200]]]
            elif tool == "send_message":
                title = "Αποστολή μηνύματος"
                rows = [["Προς", self._user_label(a.get("to"))], ["Θέμα", str(a.get("subject") or "")],
                        ["Κείμενο", str(a.get("body") or "")[:200]]]
            elif tool == "post_forum":
                title = "Ανάρτηση στο forum"
                rows = [["Μάθημα", self._course_label(a.get("course_ref"))], ["Τίτλος", str(a.get("title") or "")],
                        ["Κείμενο", str(a.get("body") or "")[:200]]]
            elif tool == "update_user":
                title = "Αλλαγή στοιχείων χρήστη"
                cur = self._current_user(a.get("user_ref"))
                rows = [["Χρήστης", self._user_label(a.get("user_ref"))]]
                for k, v in a.items():
                    if k != "user_ref" and v is not None:
                        rows.append([k, f"{cur.get(k, '—') if k not in ('iban',) else '***'} → {v}"])
            elif tool in ("reset_password", "delete_user"):
                title = "Επαναφορά κωδικού" if tool == "reset_password" else "Διαγραφή χρήστη"
                rows = [["Χρήστης", self._user_label(a.get("user_ref"))]]
                if tool == "reset_password":
                    rows.append(["Νέος κωδικός", "***" + str(a.get("new_password", ""))[-2:]])
            elif tool == "create_user":
                title = "Δημιουργία χρήστη"
                rows = [["Username", str(a.get("username"))], ["Όνομα", str(a.get("full_name"))], ["Ρόλος", str(a.get("role"))]]
            elif tool == "publish_grades":
                title = "Δημοσίευση βαθμών" if a.get("published", True) else "Απόκρυψη βαθμών"
                rows = [["Μάθημα", self._course_label(a.get("course_ref"))], ["Σκέλος", str(a.get("component") or "τελικοί βαθμοί")]]
            elif tool == "enroll_user":
                title = "Εγγραφή σε μάθημα"
                rows = [["Χρήστης", self._user_label(a.get("user_ref"))], ["Μάθημα", self._course_label(a.get("course_ref"))]]
            else:
                return super().preview(tool, args, principal)
        except Exception as e:  # a preview must never break the decision
            rows = [[k, str(v)[:200]] for k, v in a.items()] + [["(preview error)", type(e).__name__]]
        return {"title": title, "rows": rows}

    def grade_snapshot(self, student_id):
        """Used by tests / eval oracles."""
        return json.dumps(self.q("SELECT course_id, grade, published FROM final_grades WHERE student_id = ? ORDER BY 1",
                                 (student_id,)))

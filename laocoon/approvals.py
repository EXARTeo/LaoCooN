"""④ Bound approvals: approvals cryptographically bound to the exact arguments that will run."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from .audit import canonical


class ApprovalError(Exception):
    def __init__(self, code, message, http=400):
        super().__init__(message)
        self.code = code
        self.http = http


class Approvals:
    def __init__(self, store, secret: bytes, ttl=300):
        self.store = store
        self.secret = secret
        self.ttl = ttl
        self.cipher = None               # private_data: real args sealed (AES-GCM), `args` column in placeholder form
        self.redact = None
        self.seal_active = None          # () -> bool: seal new rows only while private_data is on (the console)

    def _token(self, aid, user_id, tool, args, expires_at):
        msg = f"{aid}|{user_id}|{tool}|{canonical(args)}|{expires_at:.3f}"
        return hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest()

    def create(self, turn_id, principal, tool, args, preview=None, reason=None, provenance=None, ttl=None):
        """-> (approval id, seconds it stays open). `ttl` None = the configured one (the console may set another)."""
        ttl = self.ttl if ttl is None else int(ttl)
        aid = "ap_" + secrets.token_hex(4)
        now = time.time()
        exp = round(now + ttl, 3)
        token = self._token(aid, principal["id"], tool, args, exp)     # the receipt binds the REAL args
        shown, sealed = canonical(args), None
        if self.cipher is not None and (self.seal_active is None or self.seal_active()):
            sealed = self.cipher.seal(canonical(args), f"pending|{aid}")
            shown = canonical(self.redact(args) if self.redact else args)
        self.store.execute(
            "INSERT INTO pending (id, turn_id, user_id, tool, args, token, preview, reason, provenance, created_at, "
            "expires_at, args_enc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, turn_id, principal["id"], tool, shown, token, json.dumps(preview, ensure_ascii=False),
             reason, json.dumps(provenance, ensure_ascii=False) if provenance is not None else None, now, exp,
             sealed))
        return aid, ttl

    def get(self, aid):
        row = self.store.query("SELECT * FROM pending WHERE id = ?", (aid,), one=True)
        if row:
            sealed = row.pop("args_enc", None)
            plain = self.cipher.open(sealed, f"pending|{aid}") if sealed and self.cipher is not None else None
            row["args"] = json.loads(plain if plain is not None else row["args"])
            row["preview"] = json.loads(row["preview"]) if row["preview"] else None
        return row

    def claim(self, aid, approver_id, killswitch=None):
        """Verify and atomically move pending -> approved. Returns the stored row (with the exact args)."""
        row = self.get(aid)
        if not row:
            raise ApprovalError("not_found", "Η έγκριση δεν βρέθηκε.", 404)
        if int(row["user_id"]) != int(approver_id):                                          # 1. same user
            raise ApprovalError("forbidden", "Μόνο ο χρήστης που ζήτησε την ενέργεια μπορεί να την εγκρίνει.", 403)
        if row["status"] != "pending":                                                         # 2. still pending
            raise ApprovalError("not_pending", f"Η έγκριση είναι ήδη «{row['status']}».", 409)
        if time.time() > row["expires_at"]:
            self.store.execute("UPDATE pending SET status = 'expired', args_enc = NULL WHERE id = ?", (aid,))
            raise ApprovalError("expired", "Η έγκριση έληξε. Ζήτησε ξανά την ενέργεια.", 410)
        expected = self._token(aid, row["user_id"], row["tool"], row["args"], row["expires_at"])  # 3. receipt
        if not hmac.compare_digest(expected, row["token"]):
            raise ApprovalError("tampered", "Τα ορίσματα της έγκρισης δεν ταιριάζουν με την απόδειξη.", 409)
        if killswitch is not None:                                                             # 4. kill switch
            k = killswitch.check(user_id=row["user_id"], tool=row["tool"], turn_id=row["turn_id"])
            if k:
                raise ApprovalError("killed", f"Ο μηχανισμός ασφαλείας έχει σταματήσει την ενέργεια ({k}).", 423)
        _, n = self.store.execute("UPDATE pending SET status = 'approved', args_enc = NULL WHERE id = ? "
                                  "AND status = 'pending'", (aid,))
        if n != 1:                                                                             # 5. atomic
            raise ApprovalError("race", "Η έγκριση χρησιμοποιήθηκε ήδη.", 409)
        return row

    def reject(self, aid, approver_id):
        row = self.get(aid)
        if not row:
            raise ApprovalError("not_found", "Η έγκριση δεν βρέθηκε.", 404)
        if int(row["user_id"]) != int(approver_id):
            raise ApprovalError("forbidden", "Μόνο ο χρήστης που ζήτησε την ενέργεια μπορεί να την απορρίψει.", 403)
        self.store.execute("UPDATE pending SET status = 'denied', args_enc = NULL WHERE id = ? AND status = 'pending'",
                           (aid,))
        return row

    def pending(self, user_id=None):
        sql = "SELECT id, turn_id, user_id, tool, preview, reason, created_at, expires_at, status FROM pending " \
              "WHERE status = 'pending' AND expires_at > ?"
        args = [time.time()]
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        rows = self.store.query(sql + " ORDER BY created_at DESC", args)
        for r in rows:
            r["preview"] = json.loads(r["preview"]) if r["preview"] else None
        return rows

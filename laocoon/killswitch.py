"""⑤ Audit & control: kill switch and persistence meter."""
from __future__ import annotations

import time

SCOPES = ("global", "user", "tool", "turn")


class KillSwitch:
    def __init__(self, store):
        self.store = store

    def kill(self, scope, key, reason, ttl=None):
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {SCOPES}")
        now = time.time()
        self.store.execute("INSERT INTO kills (scope, key, reason, created_at, expires_at) VALUES (?,?,?,?,?) "
                           "ON CONFLICT(scope, key) DO UPDATE SET reason = excluded.reason, "
                           "created_at = excluded.created_at, expires_at = excluded.expires_at",
                           (scope, str(key or "*"), reason, now, now + ttl if ttl else None))

    def revive(self, scope, key):
        self.store.execute("DELETE FROM kills WHERE scope = ? AND key = ?", (scope, str(key or "*")))

    def active(self):
        now = time.time()
        return self.store.query("SELECT * FROM kills WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at",
                                (now,))

    def check(self, user_id=None, tool=None, turn_id=None) -> str | None:
        """Reason string if anything relevant is killed, else None."""
        for k in self.active():
            if (k["scope"] == "global"
                    or (k["scope"] == "user" and user_id is not None and k["key"] == str(user_id))
                    or (k["scope"] == "tool" and tool is not None and k["key"] == tool)
                    or (k["scope"] == "turn" and turn_id is not None and k["key"] == turn_id)):
                return f"{k['scope']} kill: {k['reason'] or 'stopped by administrator'}"
        return None

    def recent_high_denies(self, user_id, window) -> int:
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - window))
        row = self.store.query("SELECT COUNT(*) AS n FROM events WHERE user_id = ? AND stage = 'check' "
                               "AND action = 'deny' AND severity IN ('high', 'critical') AND ts >= ?",
                               (user_id, since), one=True)
        return row["n"] if row else 0

import logging
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from typing import Dict, List, Optional

DEFAULT_VALIDITY_DAYS = "365"


def _row_to_policy(row: sqlite3.Row) -> Dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "type": row["type"],
        "user_id": row["user_id"],
        "user_name": row["user_name"] if "user_name" in row.keys() else None,
        "ext_config": row["ext_config"],
        "restrictions": row["restrictions"],
        "validity_period": row["validity_period"] or DEFAULT_VALIDITY_DAYS,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "is_est_default": row["is_est_default"] if "is_est_default" in row.keys() else 0,
        "is_scep_default": row["is_scep_default"] if "is_scep_default" in row.keys() else 0,
    }


class RAPolicyManager:
    """
    Small helper for fetching and updating RA policies (extensions + validity)
    stored in the ra_policies table.
    """

    def __init__(self, db_path: str, logger: Optional[logging.Logger] = None):
        self.db_path = db_path
        self.logger = logger or logging.getLogger(__name__)

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def list_policies_for_user(self, user_id: Optional[int], include_system: bool = True) -> List[Dict]:
        """
        Returns user-specific policies for the given user_id and, optionally, system policies.
        """
        with self._connect() as conn:
            if include_system:
                rows = conn.execute(
                    """
                    SELECT rp.*, u.username AS user_name
                    FROM ra_policies rp
                    LEFT JOIN users u ON rp.user_id = u.id
                    WHERE rp.type = 'system' OR (rp.type = 'user' AND rp.user_id = ?)
                    ORDER BY rp.type DESC, rp.id DESC
                    """,
                    (user_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT rp.*, u.username AS user_name
                    FROM ra_policies rp
                    LEFT JOIN users u ON rp.user_id = u.id
                    WHERE rp.type = 'user' AND rp.user_id = ?
                    ORDER BY rp.id DESC
                    """,
                    (user_id,),
                ).fetchall()
            return [_row_to_policy(r) for r in rows]

    def list_all_policies(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rp.*, u.username AS user_name
                FROM ra_policies rp
                LEFT JOIN users u ON rp.user_id = u.id
                ORDER BY rp.type DESC, rp.id DESC
                """
            ).fetchall()
            return [_row_to_policy(r) for r in rows]

    def _clear_system_other(self, keep_id: Optional[int] = None):
        with self._connect() as conn:
            if keep_id is None:
                conn.execute("UPDATE ra_policies SET type='user' WHERE type='system'")
            else:
                conn.execute("UPDATE ra_policies SET type='user' WHERE type='system' AND id != ?", (keep_id,))

    def _clear_protocol_default(self, protocol: str, keep_id: Optional[int] = None):
        col = "is_est_default" if protocol == "est" else "is_scep_default"
        with self._connect() as conn:
            if keep_id is None:
                conn.execute(f"UPDATE ra_policies SET {col}=0")
            else:
                conn.execute(f"UPDATE ra_policies SET {col}=0 WHERE id != ?", (keep_id,))

    def update_policy(self, policy_id: int, ext_config: str, validity_period: str, restrictions: Optional[str] = None, policy_type: Optional[str] = None, est_default: bool = False, scep_default: bool = False):
        with self._connect() as conn:
            if policy_type == "system":
                conn.execute("UPDATE ra_policies SET type='user' WHERE type='system' AND id != ?", (policy_id,))
            est_flag = 1 if est_default else 0
            scep_flag = 1 if scep_default else 0
            conn.execute(
                """
                UPDATE ra_policies
                SET ext_config = ?, validity_period = ?, restrictions = COALESCE(?, restrictions), updated_at = CURRENT_TIMESTAMP,
                    type = COALESCE(?, type),
                    is_est_default = CASE WHEN ?=1 THEN 1 ELSE is_est_default END,
                    is_scep_default = CASE WHEN ?=1 THEN 1 ELSE is_scep_default END
                WHERE id = ?
                """,
                (ext_config, validity_period, restrictions, policy_type, est_flag, scep_flag, policy_id),
            )
            if est_default:
                conn.execute("UPDATE ra_policies SET is_est_default=0 WHERE id != ?", (policy_id,))
            if scep_default:
                conn.execute("UPDATE ra_policies SET is_scep_default=0 WHERE id != ?", (policy_id,))

    def delete_policy(self, policy_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM ra_policies WHERE id = ?", (policy_id,))

    def get_policy(
        self,
        name: Optional[str] = None,
        policy_id: Optional[int] = None,
        user_id: Optional[int] = None,
    ) -> Optional[Dict]:
        """
        Fetch a policy by id or name. When a user_id is supplied we prefer a matching
        user policy first, then fallback to a system policy with the same name.
        """
        if not name and policy_id is None:
            return None
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            if policy_id is not None:
                row = conn.execute(
                    "SELECT rp.*, u.username AS user_name FROM ra_policies rp LEFT JOIN users u ON rp.user_id = u.id WHERE rp.id = ?",
                    (policy_id,),
                ).fetchone()
                return _row_to_policy(row) if row else None

            if user_id is not None:
                row = conn.execute(
                    """
                    SELECT rp.*, u.username AS user_name
                    FROM ra_policies rp
                    LEFT JOIN users u ON rp.user_id = u.id
                    WHERE rp.name = ? AND rp.type = 'user' AND rp.user_id = ?
                    """,
                    (name, user_id),
                ).fetchone()
                if row:
                    return _row_to_policy(row)

            row = conn.execute(
                """
                SELECT rp.*, u.username AS user_name
                FROM ra_policies rp
                LEFT JOIN users u ON rp.user_id = u.id
                WHERE rp.name = ?
                ORDER BY rp.id DESC
                """,
                (name,),
            ).fetchone()
            return _row_to_policy(row) if row else None

    def get_default_policy(self, user_id: Optional[int] = None) -> Optional[Dict]:
        """
        Prefer a user policy when available, otherwise return the newest system policy.
        """
        with self._connect() as conn:
            if user_id is not None:
                row = conn.execute(
                    """
                    SELECT * FROM ra_policies
                    WHERE type = 'user' AND user_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (user_id,),
                ).fetchone()
                if row:
                    return _row_to_policy(row)
            row = conn.execute(
                """
                SELECT * FROM ra_policies
                WHERE type = 'system'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
            return _row_to_policy(row) if row else None

    def get_protocol_default(self, protocol: str) -> Optional[Dict]:
        col = "is_est_default" if protocol == "est" else "is_scep_default"
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT rp.*, u.username AS user_name FROM ra_policies rp LEFT JOIN users u ON rp.user_id = u.id WHERE {col}=1 LIMIT 1"
            ).fetchone()
            if row:
                return _row_to_policy(row)
            # fallback: newest system
            row = conn.execute(
                """
                SELECT rp.*, u.username AS user_name
                FROM ra_policies rp
                LEFT JOIN users u ON rp.user_id = u.id
                WHERE rp.type='system'
                ORDER BY rp.id DESC
                LIMIT 1
                """
            ).fetchone()
            return _row_to_policy(row) if row else None

    def upsert_policy(
        self,
        name: str,
        ext_config: str,
        validity_period: str = DEFAULT_VALIDITY_DAYS,
        restrictions: str = "",
        policy_type: str = "system",
        user_id: Optional[int] = None,
        est_default: bool = False,
        scep_default: bool = False,
    ) -> int:
        """
        Insert or update a policy. Returns the policy id.
        """
        with self._connect() as conn:
            existing = None
            if user_id is not None:
                existing = conn.execute(
                    "SELECT id FROM ra_policies WHERE name = ? AND type = 'user' AND user_id = ?",
                    (name, user_id),
                ).fetchone()
            if not existing:
                existing = conn.execute(
                    "SELECT id FROM ra_policies WHERE name = ? AND type = ? AND user_id IS NULL",
                    (name, policy_type),
                ).fetchone()

            est_flag = 1 if est_default else 0
            scep_flag = 1 if scep_default else 0
            if policy_type == "system":
                conn.execute("UPDATE ra_policies SET type='user' WHERE type='system'")

            if existing:
                conn.execute(
                    """
                    UPDATE ra_policies
                    SET ext_config = ?, validity_period = ?, restrictions = ?, updated_at = CURRENT_TIMESTAMP,
                        type = ?,
                        is_est_default = CASE WHEN ?=1 THEN 1 ELSE is_est_default END,
                        is_scep_default = CASE WHEN ?=1 THEN 1 ELSE is_scep_default END
                    WHERE id = ?
                    """,
                    (ext_config, validity_period, restrictions, policy_type, est_flag, scep_flag, existing["id"]),
                )
                pid = existing["id"]
                if est_default:
                    conn.execute("UPDATE ra_policies SET is_est_default=0 WHERE id != ?", (pid,))
                if scep_default:
                    conn.execute("UPDATE ra_policies SET is_scep_default=0 WHERE id != ?", (pid,))
                return pid

            cur = conn.execute(
                """
                INSERT INTO ra_policies (name, type, user_id, ext_config, validity_period, restrictions, is_est_default, is_scep_default)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (name, policy_type, user_id, ext_config, validity_period, restrictions, est_flag, scep_flag),
            )
            pid = cur.lastrowid
            if est_default:
                conn.execute("UPDATE ra_policies SET is_est_default=0 WHERE id != ?", (pid,))
            if scep_default:
                conn.execute("UPDATE ra_policies SET is_scep_default=0 WHERE id != ?", (pid,))
            return pid

    def update_validity(
        self,
        validity_period: str,
        policy_id: Optional[int] = None,
        name: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> int:
        """
        Update validity for a specific policy. Returns rows affected.
        """
        if policy_id is None and name is None:
            return 0
        with self._connect() as conn:
            if policy_id is not None:
                cur = conn.execute(
                    "UPDATE ra_policies SET validity_period = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (validity_period, policy_id),
                )
                return cur.rowcount

            if user_id is not None:
                cur = conn.execute(
                    """
                    UPDATE ra_policies
                    SET validity_period = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE name = ? AND type = 'user' AND user_id = ?
                    """,
                    (validity_period, name, user_id),
                )
                if cur.rowcount:
                    return cur.rowcount

            cur = conn.execute(
                """
                UPDATE ra_policies
                SET validity_period = ?, updated_at = CURRENT_TIMESTAMP
                WHERE name = ?
                """,
                (validity_period, name),
            )
            return cur.rowcount

    @contextmanager
    def temp_extfile(self, policy: Optional[Dict], fallback_path: Optional[str] = None):
        """
        Yield a temp filename containing ext_config for the given policy.
        If the policy has no ext_config we fallback to the provided path (if it exists).
        """
        temp_path = None
        try:
            if policy and policy.get("ext_config"):
                tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".cnf", encoding="utf-8")
                tmp.write(policy["ext_config"])
                tmp.flush()
                temp_path = tmp.name
                tmp.close()
                yield temp_path
            elif fallback_path and os.path.exists(fallback_path):
                yield fallback_path
            else:
                yield None
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    self.logger.warning("Failed to clean temp extfile %s", temp_path)

    def get_validity_days(
        self,
        policy: Optional[Dict],
        fallback_path: Optional[str] = None,
    ) -> str:
        """
        Return validity (as string days). Prefer policy, then fallback file, then default.
        """
        if policy and policy.get("validity_period"):
            return str(policy["validity_period"]).strip() or DEFAULT_VALIDITY_DAYS
        if fallback_path and os.path.exists(fallback_path):
            try:
                with open(fallback_path, "r", encoding="utf-8") as f:
                    return f.read().strip() or DEFAULT_VALIDITY_DAYS
            except Exception:
                pass
        return DEFAULT_VALIDITY_DAYS

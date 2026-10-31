"""Persistent owner/device authorization state with transactional SQLite writes."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from pathlib import Path

from .owner_auth import DeviceRecord


class InMemoryOwnerStateStore:
    """Thread-safe process-local store for tests and development only."""

    def __init__(self, instance_id: str) -> None:
        self.instance_id = instance_id
        self._lock = threading.RLock()
        self._devices: dict[str, DeviceRecord] = {}
        self._enrollment_ids: set[str] = set()
        self._request_ids: set[str] = set()
        self._revocation_ids: set[str] = set()
        self._approval_ids: set[str] = set()

    def register_device(self, enrollment_id: str, record: DeviceRecord) -> bool:
        with self._lock:
            if (
                record.device_id in self._devices
                or enrollment_id in self._enrollment_ids
            ):
                return False
            self._devices[record.device_id] = record
            self._enrollment_ids.add(enrollment_id)
            return True

    def get_device(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            return self._devices.get(device_id)

    def authorize_request(
        self,
        device_id: str,
        required_scope: str,
        request_id: str,
        expires_at: str,
    ) -> str:
        del expires_at
        with self._lock:
            device = self._devices.get(device_id)
            if device is None or device.revoked_at is not None:
                return "inactive"
            if required_scope not in device.scopes:
                return "scope"
            if request_id in self._request_ids:
                return "replay"
            self._request_ids.add(request_id)
            return "ok"

    def revoke_device(
        self, device_id: str, revocation_id: str, revoked_at: str
    ) -> DeviceRecord | None:
        with self._lock:
            device = self._devices.get(device_id)
            if (
                device is None
                or device.revoked_at is not None
                or revocation_id in self._revocation_ids
            ):
                return None
            updated = DeviceRecord(
                device_id=device.device_id,
                public_key=device.public_key,
                scopes=device.scopes,
                enrolled_at=device.enrolled_at,
                revoked_at=revoked_at,
            )
            self._devices[device_id] = updated
            self._revocation_ids.add(revocation_id)
            return updated

    def consume_approval(self, approval_id: str, expires_at: str) -> bool:
        del expires_at
        with self._lock:
            if approval_id in self._approval_ids:
                return False
            self._approval_ids.add(approval_id)
            return True


class SQLiteOwnerStateStore:
    """SQLite-backed owner state with atomic, cross-process replay prevention.

    A new connection is opened per operation. SQLite serializes writers across
    threads and processes; unique constraints provide the final arbitration.
    This store is intended for one host with a local filesystem, not an
    arbitrary network share or a multi-region deployment.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        instance_id: str,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if not instance_id.strip():
            raise ValueError("instance_id must not be empty")
        if busy_timeout_ms <= 0:
            raise ValueError("busy_timeout_ms must be positive")
        if str(database_path) == ":memory:":
            raise ValueError("SQLiteOwnerStateStore requires a persistent database path")
        self.instance_id = instance_id
        self.database_path = str(database_path)
        self.busy_timeout_ms = busy_timeout_ms
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_lock = threading.Lock()
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialise(self) -> None:
        with self._init_lock, closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_devices (
                    instance_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    scopes_json TEXT NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    revoked_at TEXT,
                    key_algorithm TEXT NOT NULL DEFAULT 'ed25519',
                    PRIMARY KEY (instance_id, device_id)
                )
                """
            )
            device_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(owner_devices)")
            }
            if "key_algorithm" not in device_columns:
                connection.execute(
                    "ALTER TABLE owner_devices ADD COLUMN key_algorithm TEXT NOT NULL DEFAULT 'ed25519'"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_enrollments (
                    instance_id TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    PRIMARY KEY (instance_id, enrollment_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_used_requests (
                    instance_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, request_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_revocations (
                    instance_id TEXT NOT NULL,
                    revocation_id TEXT NOT NULL,
                    PRIMARY KEY (instance_id, revocation_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS owner_approvals (
                    instance_id TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, approval_id)
                )
                """
            )

    def register_device(self, enrollment_id: str, record: DeviceRecord) -> bool:
        if not enrollment_id.strip():
            raise ValueError("enrollment_id must not be empty")
        if not record.device_id.strip():
            raise ValueError("device_id must not be empty")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO owner_enrollments VALUES (?, ?)",
                    (self.instance_id, enrollment_id),
                )
                connection.execute(
                    """
                    INSERT INTO owner_devices
                    (instance_id, device_id, public_key, scopes_json, enrolled_at, revoked_at, key_algorithm)
                    VALUES (?, ?, ?, ?, ?, NULL, ?)
                    """,
                    (
                        self.instance_id,
                        record.device_id,
                        record.public_key,
                        json.dumps(sorted(record.scopes), separators=(",", ":")),
                        record.enrolled_at,
                        record.key_algorithm,
                    ),
                )
                connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_device(self, device_id: str) -> DeviceRecord | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT device_id, public_key, scopes_json, enrolled_at, revoked_at, key_algorithm
                FROM owner_devices
                WHERE instance_id = ? AND device_id = ?
                """,
                (self.instance_id, device_id),
            ).fetchone()
        if row is None:
            return None
        try:
            scopes = json.loads(row[2])
        except (TypeError, json.JSONDecodeError):
            raise RuntimeError("stored device permission data is invalid") from None
        if not isinstance(scopes, list) or any(not isinstance(item, str) for item in scopes):
            raise RuntimeError("stored device permission data is invalid")
        return DeviceRecord(
            device_id=row[0],
            public_key=bytes(row[1]),
            scopes=frozenset(scopes),
            enrolled_at=row[3],
            revoked_at=row[4],
            key_algorithm=row[5],
        )

    def authorize_request(
        self,
        device_id: str,
        required_scope: str,
        request_id: str,
        expires_at: str,
    ) -> str:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT scopes_json, revoked_at
                    FROM owner_devices
                    WHERE instance_id = ? AND device_id = ?
                    """,
                    (self.instance_id, device_id),
                ).fetchone()
                if row is None or row[1] is not None:
                    connection.rollback()
                    return "inactive"
                try:
                    scopes = json.loads(row[0])
                except (TypeError, json.JSONDecodeError):
                    connection.rollback()
                    raise RuntimeError("stored device permission data is invalid") from None
                if not isinstance(scopes, list) or required_scope not in scopes:
                    connection.rollback()
                    return "scope"
                try:
                    connection.execute(
                        "INSERT INTO owner_used_requests VALUES (?, ?, ?)",
                        (self.instance_id, request_id, expires_at),
                    )
                except sqlite3.IntegrityError:
                    connection.rollback()
                    return "replay"
                connection.commit()
                return "ok"
        except sqlite3.OperationalError as exc:
            raise RuntimeError("authorization state store is temporarily unavailable") from exc

    def revoke_device(
        self, device_id: str, revocation_id: str, revoked_at: str
    ) -> DeviceRecord | None:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO owner_revocations VALUES (?, ?)",
                    (self.instance_id, revocation_id),
                )
                cursor = connection.execute(
                    """
                    UPDATE owner_devices
                    SET revoked_at = ?
                    WHERE instance_id = ? AND device_id = ? AND revoked_at IS NULL
                    """,
                    (revoked_at, self.instance_id, device_id),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return None
                connection.commit()
        except sqlite3.IntegrityError:
            return None
        return self.get_device(device_id)

    def consume_approval(self, approval_id: str, expires_at: str) -> bool:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO owner_approvals VALUES (?, ?, ?)",
                    (self.instance_id, approval_id, expires_at),
                )
                connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        except sqlite3.OperationalError as exc:
            raise RuntimeError("approval state store is temporarily unavailable") from exc

    def counts(self) -> dict[str, int]:
        """Return operational counts without exposing identifiers or private data."""
        tables = {
            "devices": "owner_devices",
            "enrollments": "owner_enrollments",
            "requests": "owner_used_requests",
            "revocations": "owner_revocations",
            "approvals": "owner_approvals",
        }
        result: dict[str, int] = {}
        with closing(self._connect()) as connection:
            for name, table in tables.items():
                row = connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE instance_id = ?",
                    (self.instance_id,),
                ).fetchone()
                result[name] = int(row[0])
        return result

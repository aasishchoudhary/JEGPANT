"""Durable encrypted queue for asynchronous cognitive investigations."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class JobQueueError(RuntimeError):
    """Raised when a durable analysis job cannot be queued or processed."""


class JobKeyProvider(Protocol):
    def get_key(self, version: int) -> bytes:
        """Return the externally protected 256-bit queue encryption key."""
        ...


@dataclass(frozen=True, slots=True)
class JobClaim:
    job_id: str
    case_id: str
    goal: str
    worker_id: str
    attempt: int
    lease_expires_at: float


@dataclass(frozen=True, slots=True)
class JobStatus:
    job_id: str
    case_id: str
    status: str
    attempts: int
    max_attempts: int
    created_at: str
    updated_at: str
    result_id: str | None
    error_code: str | None


class AnalysisJobQueue:
    """SQLite-backed, single-instance job queue.

    Goals are encrypted at rest. Job status and opaque IDs remain visible.
    SQLite BEGIN IMMEDIATE transactions arbitrate claims on one host/local
    filesystem; this is not a multi-region distributed queue.
    """

    SCHEMA_VERSION = 1
    KEY_BYTES = 32
    NONCE_BYTES = 12

    def __init__(
        self,
        database_path: str | Path,
        *,
        instance_id: str,
        key_provider: JobKeyProvider,
        current_key_version: int = 1,
        busy_timeout_ms: int = 5000,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        try:
            UUID(instance_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("instance_id must be a UUID") from exc
        if str(database_path) == ":memory:":
            raise ValueError("job queue requires a persistent database path")
        if current_key_version <= 0 or busy_timeout_ms <= 0:
            raise ValueError("key version and busy timeout must be positive")

        self.instance_id = instance_id
        self.database_path = str(database_path)
        self.key_provider = key_provider
        self.current_key_version = current_key_version
        self.busy_timeout_ms = busy_timeout_ms
        self.clock = clock or (lambda: datetime.now(UTC))
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialise()
        self._key(current_key_version)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_jobs (
                    instance_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    key_version INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    worker_id TEXT,
                    lease_expires_at REAL,
                    result_id TEXT,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, job_id),
                    CHECK (status IN ('pending', 'running', 'completed', 'failed'))
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_jobs_claim
                ON analysis_jobs(instance_id, status, created_at, lease_expires_at)
                """
            )

    def _key(self, version: int) -> bytes:
        key = self.key_provider.get_key(version)
        if not isinstance(key, bytes) or len(key) != self.KEY_BYTES:
            raise ValueError("job key provider must return exactly 32 bytes")
        return key

    def _aad(self, job_id: str, case_id: str, key_version: int) -> bytes:
        return (
            f"JEGPANT-JOB\x00{self.SCHEMA_VERSION}\x00{self.instance_id}"
            f"\x00{job_id}\x00{case_id}\x00{key_version}"
        ).encode("utf-8")

    def _seal(self, job_id: str, case_id: str, goal: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(self.NONCE_BYTES)
        plaintext = json.dumps(
            {"goal": goal}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ciphertext = AESGCM(self._key(self.current_key_version)).encrypt(
            nonce,
            plaintext,
            self._aad(job_id, case_id, self.current_key_version),
        )
        return nonce, ciphertext

    def _open(
        self,
        job_id: str,
        case_id: str,
        key_version: int,
        schema_version: int,
        nonce: bytes,
        ciphertext: bytes,
    ) -> str:
        if schema_version != self.SCHEMA_VERSION or len(nonce) != self.NONCE_BYTES:
            raise JobQueueError("job encryption metadata is invalid")
        try:
            plaintext = AESGCM(self._key(key_version)).decrypt(
                nonce,
                ciphertext,
                self._aad(job_id, case_id, key_version),
            )
            payload = json.loads(plaintext.decode("utf-8"))
        except InvalidTag:
            raise JobQueueError("job payload authentication failed") from None
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise JobQueueError("job payload is invalid") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("goal"), str):
            raise JobQueueError("job payload schema is invalid")
        return payload["goal"]

    def enqueue(
        self,
        *,
        case_id: str,
        goal: str,
        max_attempts: int = 3,
    ) -> str:
        try:
            UUID(case_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("case_id must be a UUID") from exc
        if not isinstance(goal, str) or not goal.strip():
            raise ValueError("goal must be a non-empty string")
        if len(goal) > 12000:
            raise ValueError("goal exceeds the configured length limit")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")

        job_id = str(uuid4())
        nonce, ciphertext = self._seal(job_id, case_id, goal)
        now = self.clock().astimezone(UTC).isoformat()
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    """
                    INSERT INTO analysis_jobs(
                        instance_id, job_id, case_id, key_version, schema_version,
                        nonce, ciphertext, status, attempts, max_attempts, worker_id,
                        lease_expires_at, result_id, error_code, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, NULL, NULL, NULL, NULL, ?, ?)
                    """,
                    (
                        self.instance_id,
                        job_id,
                        case_id,
                        self.current_key_version,
                        self.SCHEMA_VERSION,
                        nonce,
                        ciphertext,
                        max_attempts,
                        now,
                        now,
                    ),
                )
        except sqlite3.OperationalError as exc:
            raise JobQueueError("job queue is temporarily unavailable") from exc
        return job_id

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_seconds: int = 900,
    ) -> JobClaim | None:
        """Atomically claim one pending or expired-lease job."""
        if not worker_id.strip():
            raise ValueError("worker_id must be non-empty")
        if not 30 <= lease_seconds <= 86400:
            raise ValueError("lease_seconds must be between 30 and 86400")

        now = self.clock().astimezone(UTC).timestamp()
        lease_expires_at = now + lease_seconds
        updated_at = self.clock().astimezone(UTC).isoformat()

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE analysis_jobs
                    SET status = 'failed', worker_id = NULL,
                        lease_expires_at = NULL,
                        error_code = 'lease_expired_max_attempts', updated_at = ?
                    WHERE instance_id = ? AND status = 'running'
                      AND lease_expires_at < ? AND attempts >= max_attempts
                    """,
                    (
                        updated_at,
                        self.instance_id,
                        now,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT job_id, case_id, key_version, schema_version,
                           nonce, ciphertext, attempts, max_attempts
                    FROM analysis_jobs
                    WHERE instance_id = ?
                      AND attempts < max_attempts
                      AND (
                        status = 'pending'
                        OR (status = 'running' AND lease_expires_at < ?)
                      )
                    ORDER BY created_at, job_id
                    LIMIT 1
                    """,
                    (self.instance_id, now),
                ).fetchone()
                if row is None:
                    connection.commit()
                    return None

                job_id, case_id, key_version, schema_version, nonce, ciphertext, attempts, max_attempts = row
                goal = self._open(
                    job_id,
                    case_id,
                    key_version,
                    schema_version,
                    bytes(nonce),
                    bytes(ciphertext),
                )
                new_attempt = attempts + 1
                cursor = connection.execute(
                    """
                    UPDATE analysis_jobs
                    SET status = 'running', attempts = ?, worker_id = ?,
                        lease_expires_at = ?, updated_at = ?, error_code = NULL
                    WHERE instance_id = ? AND job_id = ? AND attempts = ?
                      AND attempts < max_attempts
                    """,
                    (
                        new_attempt,
                        worker_id,
                        lease_expires_at,
                        updated_at,
                        self.instance_id,
                        job_id,
                        attempts,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return None
                connection.commit()
                return JobClaim(
                    job_id=job_id,
                    case_id=case_id,
                    goal=goal,
                    worker_id=worker_id,
                    attempt=new_attempt,
                    lease_expires_at=lease_expires_at,
                )
        except sqlite3.OperationalError as exc:
            raise JobQueueError("job queue claim is temporarily unavailable") from exc

    def renew_lease(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_seconds: int = 900,
    ) -> bool:
        if not 30 <= lease_seconds <= 86400:
            raise ValueError("lease_seconds must be between 30 and 86400")
        now = self.clock().astimezone(UTC).timestamp()
        expiry = now + lease_seconds
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_jobs
                SET lease_expires_at = ?, updated_at = ?
                WHERE instance_id = ? AND job_id = ? AND status = 'running'
                  AND worker_id = ? AND lease_expires_at >= ?
                """,
                (
                    expiry,
                    self.clock().astimezone(UTC).isoformat(),
                    self.instance_id,
                    job_id,
                    worker_id,
                    now,
                ),
            )
        return cursor.rowcount == 1

    def complete(
        self,
        *,
        job_id: str,
        worker_id: str,
        result_id: str,
    ) -> bool:
        try:
            UUID(result_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("result_id must be a UUID") from exc
        now = self.clock().astimezone(UTC).timestamp()
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_jobs
                SET status = 'completed', result_id = ?, worker_id = NULL,
                    lease_expires_at = NULL, updated_at = ?, error_code = NULL
                WHERE instance_id = ? AND job_id = ? AND status = 'running'
                  AND worker_id = ? AND lease_expires_at >= ?
                """,
                (
                    result_id,
                    self.clock().astimezone(UTC).isoformat(),
                    self.instance_id,
                    job_id,
                    worker_id,
                    now,
                ),
            )
        return cursor.rowcount == 1

    def fail(
        self,
        *,
        job_id: str,
        worker_id: str,
        error_code: str,
        retryable: bool = True,
    ) -> bool:
        """Record a bounded machine-readable error, never exception text or prompts."""
        if not error_code or len(error_code) > 64:
            raise ValueError("error_code must contain 1 to 64 characters")
        safe_code = "".join(ch for ch in error_code if ch.isalnum() or ch in "_-")
        if not safe_code:
            raise ValueError("error_code must be machine-readable")
        now = self.clock().astimezone(UTC).timestamp()
        updated = self.clock().astimezone(UTC).isoformat()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT attempts, max_attempts FROM analysis_jobs
                WHERE instance_id = ? AND job_id = ?
                  AND status = 'running' AND worker_id = ?
                  AND lease_expires_at >= ?
                """,
                (self.instance_id, job_id, worker_id, now),
            ).fetchone()
            if row is None:
                connection.rollback()
                return False
            attempts, max_attempts = row
            next_status = (
                "pending" if retryable and attempts < max_attempts else "failed"
            )
            cursor = connection.execute(
                """
                UPDATE analysis_jobs
                SET status = ?, error_code = ?, worker_id = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE instance_id = ? AND job_id = ? AND worker_id = ?
                """,
                (
                    next_status,
                    safe_code,
                    updated,
                    self.instance_id,
                    job_id,
                    worker_id,
                ),
            )
            connection.commit()
        return cursor.rowcount == 1

    def get_status(self, job_id: str) -> JobStatus:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT job_id, case_id, status, attempts, max_attempts,
                       created_at, updated_at, result_id, error_code
                FROM analysis_jobs
                WHERE instance_id = ? AND job_id = ?
                """,
                (self.instance_id, job_id),
            ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return JobStatus(*row)

    def count(self, *, status: str | None = None) -> int:
        allowed = {"pending", "running", "completed", "failed"}
        if status is not None and status not in allowed:
            raise ValueError("unsupported job status")
        query = "SELECT COUNT(*) FROM analysis_jobs WHERE instance_id = ?"
        params: tuple[object, ...] = (self.instance_id,)
        if status is not None:
            query += " AND status = ?"
            params += (status,)
        with closing(self._connect()) as connection:
            return int(connection.execute(query, params).fetchone()[0])

    def close(self) -> None:
        """No persistent connection is held."""

    def __enter__(self) -> "AnalysisJobQueue":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

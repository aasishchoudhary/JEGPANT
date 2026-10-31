"""Encrypted SQLite store for owner-approved cognitive memory records.

The database stores ciphertext plus a small amount of routing metadata. Keys are
provided by an external KeyProvider; they are never generated from passwords,
stored in SQLite, or written to this repository.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .memory import MemoryKind, MemoryRecord, MemorySensitivity


class StorageIntegrityError(RuntimeError):
    """Raised when encrypted memory cannot be authenticated or decoded."""


class DataKeyProvider(Protocol):
    """Key source backed by Android Keystore, KMS, HSM, or owner-held key flow."""

    def get_key(self, version: int) -> bytes:
        """Return a 256-bit data-encryption key for the requested version."""
        ...


class EncryptedMemoryStore:
    """Single-instance SQLite store with per-record AES-256-GCM encryption.

    Security properties depend on the supplied key provider. This class does
    not implement Android Keystore, remote KMS, owner recovery, or key escrow.
    """

    SCHEMA_VERSION = 1
    NONCE_BYTES = 12
    KEY_BYTES = 32

    def __init__(
        self,
        database_path: str | Path,
        *,
        instance_id: str,
        key_provider: DataKeyProvider,
        current_key_version: int = 1,
    ) -> None:
        if not instance_id.strip():
            raise ValueError("instance_id must not be empty")
        try:
            UUID(instance_id)
        except ValueError as exc:
            raise ValueError("instance_id must be a UUID") from exc
        if current_key_version <= 0:
            raise ValueError("current_key_version must be positive")

        self.instance_id = instance_id
        self.key_provider = key_provider
        self.current_key_version = current_key_version
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=5.0,
            check_same_thread=False,
        )
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA secure_delete = ON")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        secure_delete = self._connection.execute("PRAGMA secure_delete").fetchone()
        if secure_delete is None or secure_delete[0] != 1:
            self._connection.close()
            raise RuntimeError("SQLite secure_delete could not be enabled")

        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS encrypted_memory (
                memory_id TEXT PRIMARY KEY,
                key_version INTEGER NOT NULL,
                schema_version INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL
            )
            """
        )
        self._connection.commit()
        self._key(self.current_key_version)

    def _key(self, version: int) -> bytes:
        key = self.key_provider.get_key(version)
        if not isinstance(key, bytes) or len(key) != self.KEY_BYTES:
            raise ValueError("key provider must return exactly 32 bytes")
        return key

    def _aad(self, memory_id: str, key_version: int) -> bytes:
        return (
            f"JEGPANT-MEMORY\x00{self.SCHEMA_VERSION}\x00"
            f"{self.instance_id}\x00{memory_id}\x00{key_version}"
        ).encode("utf-8")

    @staticmethod
    def _serialize(record: MemoryRecord) -> bytes:
        payload = {
            "schema_version": 1,
            "memory_id": record.memory_id,
            "instance_id": record.instance_id,
            "proposal_id": record.proposal_id,
            "kind": record.kind.value,
            "summary": record.summary,
            "provenance_refs": list(record.provenance_refs),
            "sensitivity": record.sensitivity.value,
            "context_tags": list(record.context_tags),
            "created_at": record.created_at,
            "owner_approval_id": record.owner_approval_id,
        }
        return json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def _encrypt(self, record: MemoryRecord, key_version: int) -> tuple[bytes, bytes]:
        nonce = os.urandom(self.NONCE_BYTES)
        aesgcm = AESGCM(self._key(key_version))
        ciphertext = aesgcm.encrypt(
            nonce,
            self._serialize(record),
            self._aad(record.memory_id, key_version),
        )
        return nonce, ciphertext

    def _decrypt_payload(
        self,
        memory_id: str,
        key_version: int,
        schema_version: int,
        nonce: bytes,
        ciphertext: bytes,
    ) -> dict[str, object]:
        if schema_version != self.SCHEMA_VERSION:
            raise StorageIntegrityError("unsupported encrypted memory schema version")
        if len(nonce) != self.NONCE_BYTES:
            raise StorageIntegrityError("invalid encrypted memory nonce length")
        try:
            plaintext = AESGCM(self._key(key_version)).decrypt(
                nonce,
                ciphertext,
                self._aad(memory_id, key_version),
            )
            payload = json.loads(plaintext.decode("utf-8"))
        except InvalidTag:
            raise StorageIntegrityError("encrypted memory authentication failed") from None
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise StorageIntegrityError("encrypted memory payload is invalid") from None

        if not isinstance(payload, dict):
            raise StorageIntegrityError("encrypted memory payload must be an object")
        if payload.get("memory_id") != memory_id:
            raise StorageIntegrityError("encrypted memory ID does not match its record")
        if payload.get("instance_id") != self.instance_id:
            raise StorageIntegrityError("encrypted memory belongs to another instance")
        if payload.get("schema_version") != schema_version:
            raise StorageIntegrityError("encrypted memory schema metadata does not match")
        return payload

    @staticmethod
    def _record_from_payload(payload: dict[str, object]) -> MemoryRecord:
        try:
            return MemoryRecord(
                memory_id=str(payload["memory_id"]),
                instance_id=str(payload["instance_id"]),
                proposal_id=str(payload["proposal_id"]),
                kind=MemoryKind(str(payload["kind"])),
                summary=str(payload["summary"]),
                provenance_refs=tuple(str(item) for item in payload["provenance_refs"]),
                sensitivity=MemorySensitivity(str(payload["sensitivity"])),
                context_tags=tuple(str(item) for item in payload["context_tags"]),
                created_at=str(payload["created_at"]),
                owner_approval_id=str(payload["owner_approval_id"]),
            )
        except (KeyError, TypeError, ValueError):
            raise StorageIntegrityError("encrypted memory fields are invalid") from None

    def put(self, record: MemoryRecord) -> None:
        """Encrypt and insert one owner-approved memory record."""
        if record.instance_id != self.instance_id:
            raise PermissionError("memory record belongs to a different instance")
        if not record.memory_id.strip():
            raise ValueError("memory_id must not be empty")

        with self._lock:
            nonce, ciphertext = self._encrypt(record, self.current_key_version)
            try:
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT INTO encrypted_memory
                        (memory_id, key_version, schema_version, nonce, ciphertext)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            record.memory_id,
                            self.current_key_version,
                            self.SCHEMA_VERSION,
                            nonce,
                            ciphertext,
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ValueError("memory_id already exists") from exc

    def get(self, memory_id: str) -> MemoryRecord:
        """Load and authenticate one record by its opaque memory ID."""
        with self._lock:
            row = self._connection.execute(
                """
                SELECT key_version, schema_version, nonce, ciphertext
                FROM encrypted_memory
                WHERE memory_id = ?
                """,
                (memory_id,),
            ).fetchone()
        if row is None:
            raise KeyError(memory_id)
        key_version, schema_version, nonce, ciphertext = row
        payload = self._decrypt_payload(
            memory_id, key_version, schema_version, nonce, ciphertext
        )
        return self._record_from_payload(payload)

    def delete(self, memory_id: str) -> bool:
        """Delete a row; this is not a guarantee of forensic erasure."""
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM encrypted_memory WHERE memory_id = ?",
                (memory_id,),
            )
            return cursor.rowcount > 0

    def rotate_key(self, new_key_version: int) -> int:
        """Re-encrypt every row under a new key version in one transaction.

        Old keys must remain available until the transaction is committed and
        a backup/restore plan has been tested. Removing old keys is a separate
        key-provider and recovery operation.
        """
        if new_key_version <= 0:
            raise ValueError("new_key_version must be positive")
        self._key(new_key_version)

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT memory_id, key_version, schema_version, nonce, ciphertext
                FROM encrypted_memory
                ORDER BY memory_id
                """
            ).fetchall()
            migrated: list[tuple[int, int, bytes, bytes, str]] = []
            for memory_id, old_version, schema_version, nonce, ciphertext in rows:
                payload = self._decrypt_payload(
                    memory_id, old_version, schema_version, nonce, ciphertext
                )
                record = self._record_from_payload(payload)
                fresh_nonce, fresh_ciphertext = self._encrypt(record, new_key_version)
                migrated.append(
                    (
                        new_key_version,
                        self.SCHEMA_VERSION,
                        fresh_nonce,
                        fresh_ciphertext,
                        memory_id,
                    )
                )

            with self._connection:
                self._connection.executemany(
                    """
                    UPDATE encrypted_memory
                    SET key_version = ?, schema_version = ?, nonce = ?, ciphertext = ?
                    WHERE memory_id = ?
                    """,
                    migrated,
                )
            self.current_key_version = new_key_version
            return len(migrated)

    def count(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) FROM encrypted_memory"
            ).fetchone()
        return int(row[0])

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "EncryptedMemoryStore":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

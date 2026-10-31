"""Encrypted, append-only case and investigation repository."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .runtime import InvestigationEvidence, InvestigationResult


class CaseStoreError(RuntimeError):
    """Raised when a case repository operation fails safely."""


class CaseIntegrityError(CaseStoreError):
    """Raised when encrypted case content fails authentication or validation."""


class EncryptedCaseStore:
    """Single-instance encrypted case repository.

    Case identifiers and keyed lookup digests remain visible. Evidence
    descriptions, source references, timeline values, limitations and complete
    investigation reports are encrypted using per-record AES-GCM. A caller
    must supply a real externally protected 256-bit key provider.
    """

    SCHEMA_VERSION = 1
    KEY_BYTES = 32
    NONCE_BYTES = 12

    def __init__(
        self,
        database_path: str | Path,
        *,
        instance_id: str,
        key_provider,
        current_key_version: int = 1,
        busy_timeout_ms: int = 5000,
    ) -> None:
        try:
            UUID(instance_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("instance_id must be a UUID") from exc
        if current_key_version <= 0 or busy_timeout_ms <= 0:
            raise ValueError("key version and busy timeout must be positive")
        if str(database_path) == ":memory:":
            raise ValueError("EncryptedCaseStore requires a persistent database path")

        self.instance_id = instance_id
        self.database_path = str(database_path)
        self.key_provider = key_provider
        self.current_key_version = current_key_version
        self.busy_timeout_ms = busy_timeout_ms

        parent = Path(self.database_path).parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._initialise()
        self._key(current_key_version)
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            # ACLs and filesystem permissions remain an operator responsibility.
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    instance_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, case_id)
                );

                CREATE TABLE IF NOT EXISTS case_evidence (
                    instance_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    evidence_key TEXT NOT NULL,
                    key_version INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, case_id, evidence_key),
                    FOREIGN KEY (instance_id, case_id)
                        REFERENCES cases(instance_id, case_id)
                );

                CREATE TABLE IF NOT EXISTS case_reports (
                    instance_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    investigation_key TEXT NOT NULL,
                    key_version INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, case_id, investigation_key),
                    FOREIGN KEY (instance_id, case_id)
                        REFERENCES cases(instance_id, case_id)
                );

                CREATE INDEX IF NOT EXISTS idx_case_evidence_order
                    ON case_evidence(instance_id, case_id, created_at);

                CREATE INDEX IF NOT EXISTS idx_case_reports_order
                    ON case_reports(instance_id, case_id, created_at);

                CREATE TABLE IF NOT EXISTS case_media_assets (
                    instance_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    asset_key TEXT NOT NULL,
                    key_version INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, case_id, asset_key),
                    FOREIGN KEY (instance_id, case_id)
                        REFERENCES cases(instance_id, case_id)
                );

                CREATE TABLE IF NOT EXISTS case_job_results (
                    instance_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    job_key TEXT NOT NULL,
                    investigation_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (instance_id, case_id, job_key),
                    FOREIGN KEY (instance_id, case_id)
                        REFERENCES cases(instance_id, case_id)
                );
                """
            )

    def _key(self, version: int) -> bytes:
        key = self.key_provider.get_key(version)
        if not isinstance(key, bytes) or len(key) != self.KEY_BYTES:
            raise ValueError("key provider must return exactly 32 bytes")
        return key

    def _lookup_digest(self, namespace: str, value: str) -> str:
        material = f"JEGPANT-CASE-LOOKUP\x00{self.instance_id}\x00{namespace}\x00{value}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _aad(
        self, entity_type: str, entity_id: str, key_version: int
    ) -> bytes:
        return (
            f"JEGPANT-CASE\x00{self.SCHEMA_VERSION}\x00{self.instance_id}"
            f"\x00{entity_type}\x00{entity_id}\x00{key_version}"
        ).encode("utf-8")

    def _seal(
        self, entity_type: str, entity_id: str, payload: dict[str, Any]
    ) -> tuple[int, bytes, bytes]:
        key_version = self.current_key_version
        nonce = os.urandom(self.NONCE_BYTES)
        plaintext = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        ciphertext = AESGCM(self._key(key_version)).encrypt(
            nonce,
            plaintext,
            self._aad(entity_type, entity_id, key_version),
        )
        return key_version, nonce, ciphertext

    def _open(
        self,
        *,
        entity_type: str,
        entity_id: str,
        key_version: int,
        schema_version: int,
        nonce: bytes,
        ciphertext: bytes,
    ) -> dict[str, Any]:
        if schema_version != self.SCHEMA_VERSION:
            raise CaseIntegrityError("unsupported encrypted case schema version")
        if len(nonce) != self.NONCE_BYTES:
            raise CaseIntegrityError("invalid encrypted case nonce")
        try:
            plaintext = AESGCM(self._key(key_version)).decrypt(
                nonce,
                ciphertext,
                self._aad(entity_type, entity_id, key_version),
            )
            payload = json.loads(plaintext.decode("utf-8"))
        except InvalidTag:
            raise CaseIntegrityError("encrypted case content failed authentication") from None
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise CaseIntegrityError("encrypted case content is invalid") from None
        if not isinstance(payload, dict):
            raise CaseIntegrityError("encrypted case content must be a JSON object")
        return payload

    @staticmethod
    def _evidence_payload(evidence: InvestigationEvidence) -> dict[str, Any]:
        return {
            "record_id": evidence.record_id,
            "source_ref": evidence.source_ref,
            "independence_group": evidence.independence_group,
            "observation": evidence.observation,
            "quality_level": evidence.quality_level,
            "source_start_ms": evidence.source_start_ms,
            "source_end_ms": evidence.source_end_ms,
            "limitations": list(evidence.limitations),
        }

    @staticmethod
    def _evidence_from_payload(payload: dict[str, Any]) -> InvestigationEvidence:
        try:
            return InvestigationEvidence(
                record_id=payload["record_id"],
                source_ref=payload["source_ref"],
                independence_group=payload["independence_group"],
                observation=payload["observation"],
                quality_level=payload["quality_level"],
                source_start_ms=payload["source_start_ms"],
                source_end_ms=payload["source_end_ms"],
                limitations=tuple(payload["limitations"]),
            )
        except (KeyError, TypeError, ValueError):
            raise CaseIntegrityError("stored evidence fields are invalid") from None

    def create_case(self, case_id: str | None = None) -> str:
        """Create an empty case namespace and return its UUID."""
        identifier = case_id or str(uuid4())
        try:
            UUID(identifier)
        except (TypeError, ValueError) as exc:
            raise ValueError("case_id must be a UUID") from exc
        from datetime import UTC, datetime

        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    "INSERT INTO cases(instance_id, case_id, created_at) VALUES (?, ?, ?)",
                    (self.instance_id, identifier, datetime.now(UTC).isoformat()),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("case already exists") from exc
        return identifier

    def case_exists(self, case_id: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT 1 FROM cases WHERE instance_id = ? AND case_id = ?",
                (self.instance_id, case_id),
            ).fetchone()
        return row is not None

    def add_evidence(
        self, case_id: str, evidence: InvestigationEvidence
    ) -> None:
        """Append one encrypted source observation; existing IDs cannot be replaced."""
        evidence_key = self._lookup_digest("evidence", evidence.record_id)
        payload = self._evidence_payload(evidence)
        key_version, nonce, ciphertext = self._seal(
            "evidence", f"{case_id}:{evidence_key}", payload
        )
        from datetime import UTC, datetime

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                exists = connection.execute(
                    "SELECT 1 FROM cases WHERE instance_id = ? AND case_id = ?",
                    (self.instance_id, case_id),
                ).fetchone()
                if exists is None:
                    connection.rollback()
                    raise KeyError(case_id)
                connection.execute(
                    """
                    INSERT INTO case_evidence(
                        instance_id, case_id, evidence_key, key_version,
                        schema_version, nonce, ciphertext, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.instance_id,
                        case_id,
                        evidence_key,
                        key_version,
                        self.SCHEMA_VERSION,
                        nonce,
                        ciphertext,
                        datetime.now(UTC).isoformat(),
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("evidence record ID already exists in this case") from exc

    def list_evidence(self, case_id: str) -> tuple[InvestigationEvidence, ...]:
        """Load and authenticate every evidence record in append order."""
        with closing(self._connect()) as connection:
            case = connection.execute(
                "SELECT 1 FROM cases WHERE instance_id = ? AND case_id = ?",
                (self.instance_id, case_id),
            ).fetchone()
            if case is None:
                raise KeyError(case_id)
            rows = connection.execute(
                """
                SELECT evidence_key, key_version, schema_version, nonce, ciphertext
                FROM case_evidence
                WHERE instance_id = ? AND case_id = ?
                ORDER BY created_at, evidence_key
                """,
                (self.instance_id, case_id),
            ).fetchall()

        records: list[InvestigationEvidence] = []
        for evidence_key, key_version, schema_version, nonce, ciphertext in rows:
            payload = self._open(
                entity_type="evidence",
                entity_id=f"{case_id}:{evidence_key}",
                key_version=key_version,
                schema_version=schema_version,
                nonce=bytes(nonce),
                ciphertext=bytes(ciphertext),
            )
            item = self._evidence_from_payload(payload)
            if self._lookup_digest("evidence", item.record_id) != evidence_key:
                raise CaseIntegrityError("evidence lookup digest does not match payload")
            records.append(item)
        return tuple(records)

    def add_media_asset(self, case_id: str, entry) -> None:
        """Bind an already-encrypted vault asset to one case namespace."""
        try:
            UUID(entry.asset_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("media asset entry must contain a valid UUID") from exc
        if (
            isinstance(entry.size_bytes, bool)
            or not isinstance(entry.size_bytes, int)
            or entry.size_bytes <= 0
            or not isinstance(entry.sha256, str)
            or len(entry.sha256) != 64
        ):
            raise ValueError("media asset metadata is invalid")
        try:
            int(entry.sha256, 16)
        except ValueError as exc:
            raise ValueError("media asset digest must be hexadecimal") from exc

        asset_key = self._lookup_digest("media", entry.asset_id)
        payload = {
            "asset_id": entry.asset_id,
            "size_bytes": entry.size_bytes,
            "sha256": entry.sha256,
            "key_version": entry.key_version,
            "chunk_size": entry.chunk_size,
            "chunk_count": entry.chunk_count,
        }
        key_version, nonce, ciphertext = self._seal(
            "media_metadata", f"{case_id}:{asset_key}", payload
        )
        from datetime import UTC, datetime

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM cases WHERE instance_id = ? AND case_id = ?",
                    (self.instance_id, case_id),
                ).fetchone() is None:
                    connection.rollback()
                    raise KeyError(case_id)
                connection.execute(
                    """
                    INSERT INTO case_media_assets(
                        instance_id, case_id, asset_key, key_version,
                        schema_version, nonce, ciphertext, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.instance_id,
                        case_id,
                        asset_key,
                        key_version,
                        self.SCHEMA_VERSION,
                        nonce,
                        ciphertext,
                        datetime.now(UTC).isoformat(),
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("media asset already exists in this case") from exc

    def list_media_assets(self, case_id: str) -> tuple[dict[str, Any], ...]:
        """Return authenticated metadata for the encrypted media assets in a case."""
        with closing(self._connect()) as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE instance_id = ? AND case_id = ?",
                (self.instance_id, case_id),
            ).fetchone() is None:
                raise KeyError(case_id)
            rows = connection.execute(
                """
                SELECT asset_key, key_version, schema_version, nonce, ciphertext
                FROM case_media_assets
                WHERE instance_id = ? AND case_id = ?
                ORDER BY created_at, asset_key
                """,
                (self.instance_id, case_id),
            ).fetchall()

        result: list[dict[str, Any]] = []
        for asset_key, key_version, schema_version, nonce, ciphertext in rows:
            payload = self._open(
                entity_type="media_metadata",
                entity_id=f"{case_id}:{asset_key}",
                key_version=key_version,
                schema_version=schema_version,
                nonce=bytes(nonce),
                ciphertext=bytes(ciphertext),
            )
            asset_id = payload.get("asset_id")
            if (
                not isinstance(asset_id, str)
                or self._lookup_digest("media", asset_id) != asset_key
            ):
                raise CaseIntegrityError("media asset lookup digest does not match payload")
            result.append(payload)
        return tuple(result)

    def media_asset_exists(self, case_id: str, asset_id: str) -> bool:
        asset_key = self._lookup_digest("media", asset_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM case_media_assets
                WHERE instance_id = ? AND case_id = ? AND asset_key = ?
                """,
                (self.instance_id, case_id, asset_key),
            ).fetchone()
        return row is not None

    def store_result(
        self,
        case_id: str,
        result: InvestigationResult,
        *,
        job_id: str | None = None,
    ) -> str:
        """Persist one encrypted report, optionally idempotent by analysis-job ID."""
        if not self.case_exists(case_id):
            raise KeyError(case_id)
        evidence = self.list_evidence(case_id)
        actual_manifest = self._manifest_digest(evidence)
        if actual_manifest != result.evidence_manifest_sha256:
            raise ValueError("investigation result does not match the current case evidence set")

        job_key = None
        if job_id is not None:
            try:
                UUID(job_id)
            except (TypeError, ValueError) as exc:
                raise ValueError("job_id must be a UUID") from exc
            job_key = self._lookup_digest("job", job_id)
            existing_id = self.get_job_result_id(case_id, job_id)
            if existing_id is not None:
                existing = self.get_result(case_id, existing_id)
                if (
                    existing.get("evidence_manifest_sha256") != result.evidence_manifest_sha256
                    or existing.get("goal") != result.goal
                ):
                    raise ValueError("job ID already identifies a different investigation")
                return existing_id

        report_payload = result.as_dict()
        investigation_key = self._lookup_digest(
            "investigation", result.investigation_id
        )
        key_version, nonce, ciphertext = self._seal(
            "report", f"{case_id}:{investigation_key}", report_payload
        )
        from datetime import UTC, datetime

        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO case_reports(
                        instance_id, case_id, investigation_key, key_version,
                        schema_version, nonce, ciphertext, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.instance_id,
                        case_id,
                        investigation_key,
                        key_version,
                        self.SCHEMA_VERSION,
                        nonce,
                        ciphertext,
                        datetime.now(UTC).isoformat(),
                    ),
                )
                if job_key is not None:
                    connection.execute(
                        """
                        INSERT INTO case_job_results(
                            instance_id, case_id, job_key, investigation_id, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            self.instance_id,
                            case_id,
                            job_key,
                            result.investigation_id,
                            datetime.now(UTC).isoformat(),
                        ),
                    )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("investigation report or job result already exists") from exc
        return result.investigation_id

    def get_job_result_id(self, case_id: str, job_id: str) -> str | None:
        """Return the already persisted result for a job, if one exists."""
        job_key = self._lookup_digest("job", job_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT investigation_id FROM case_job_results
                WHERE instance_id = ? AND case_id = ? AND job_key = ?
                """,
                (self.instance_id, case_id, job_key),
            ).fetchone()
        return None if row is None else str(row[0])

    @staticmethod
    def _manifest_digest(evidence: tuple[InvestigationEvidence, ...]) -> str:
        manifest = [
            {
                "record_id": item.record_id,
                "source_ref": item.source_ref,
                "independence_group": item.independence_group,
                "observation": item.observation,
                "quality_level": item.quality_level,
                "source_start_ms": item.source_start_ms,
                "source_end_ms": item.source_end_ms,
                "limitations": list(item.limitations),
            }
            for item in sorted(evidence, key=lambda row: row.record_id)
        ]
        encoded = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def get_result(self, case_id: str, investigation_id: str) -> dict[str, Any]:
        """Load and authenticate one encrypted investigation report."""
        investigation_key = self._lookup_digest("investigation", investigation_id)
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT key_version, schema_version, nonce, ciphertext
                FROM case_reports
                WHERE instance_id = ? AND case_id = ? AND investigation_key = ?
                """,
                (self.instance_id, case_id, investigation_key),
            ).fetchone()
        if row is None:
            raise KeyError(investigation_id)
        payload = self._open(
            entity_type="report",
            entity_id=f"{case_id}:{investigation_key}",
            key_version=row[0],
            schema_version=row[1],
            nonce=bytes(row[2]),
            ciphertext=bytes(row[3]),
        )
        if payload.get("investigation_id") != investigation_id:
            raise CaseIntegrityError("report identity does not match lookup")
        return payload

    def list_report_ids(self, case_id: str) -> tuple[str, ...]:
        """Return no report IDs because the repository stores them only as digests.

        Reports are retrieved by the owner-held investigation ID. This avoids
        exposing a plaintext index of potentially sensitive case activity.
        """
        if not self.case_exists(case_id):
            raise KeyError(case_id)
        return ()

    def _counts(self, table: str, case_id: str) -> int:
        if table not in {"case_evidence", "case_reports"}:
            raise ValueError("unsupported case table")
        with closing(self._connect()) as connection:
            row = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE instance_id = ? AND case_id = ?",
                (self.instance_id, case_id),
            ).fetchone()
        return int(row[0])

    def evidence_count(self, case_id: str) -> int:
        if not self.case_exists(case_id):
            raise KeyError(case_id)
        return self._counts("case_evidence", case_id)

    def report_count(self, case_id: str) -> int:
        if not self.case_exists(case_id):
            raise KeyError(case_id)
        return self._counts("case_reports", case_id)


    def close(self) -> None:
        """No persistent connection is held; retained for context-manager symmetry."""
        return None

    def __enter__(self) -> "EncryptedCaseStore":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

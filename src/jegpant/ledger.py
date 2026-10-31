"""Local append-only evidence ledger with hash-chain integrity checks.

The hash chain detects accidental or unsophisticated modification. It is not
a digital signature, trusted timestamp, access-control system, or tamper-proof
storage. Production use requires a reviewed storage and key-management design.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class LedgerIntegrityError(RuntimeError):
    """Raised when the ledger is malformed or its hash chain is invalid."""


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_digest(record_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(record_without_hash).encode("utf-8")).hexdigest()


class EvidenceLedger:
    """A single-writer JSONL evidence ledger for local development and testing."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(
        self,
        *,
        case_id: str,
        source_ref: str,
        modality: str,
        observation: str,
        source_start_ms: int | None = None,
        source_end_ms: int | None = None,
        extraction_method: str = "owner-entered",
        extractor_version: str = "n/a",
        limitations: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Append an observation record and return the committed record."""
        required = {
            "case_id": case_id,
            "source_ref": source_ref,
            "modality": modality,
            "observation": observation,
        }
        for name, value in required.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

        if source_start_ms is not None and source_start_ms < 0:
            raise ValueError("source_start_ms must be non-negative")
        if source_end_ms is not None and source_end_ms < 0:
            raise ValueError("source_end_ms must be non-negative")
        if (
            source_start_ms is not None
            and source_end_ms is not None
            and source_end_ms < source_start_ms
        ):
            raise ValueError("source_end_ms must be >= source_start_ms")

        with self._lock:
            existing = self.read_all()
            previous_hash = existing[-1]["record_hash"] if existing else None
            record: dict[str, Any] = {
                "schema_version": 1,
                "record_id": str(uuid.uuid4()),
                "case_id": case_id,
                "created_at": datetime.now(UTC).isoformat(),
                "source_ref": source_ref,
                "modality": modality,
                "observation": observation,
                "source_start_ms": source_start_ms,
                "source_end_ms": source_end_ms,
                "extraction_method": extraction_method,
                "extractor_version": extractor_version,
                "limitations": list(limitations),
                "previous_hash": previous_hash,
            }
            record["record_hash"] = _record_digest(record)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(_canonical_json(record) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return record

    def read_all(self) -> list[dict[str, Any]]:
        """Read all records and verify ordering and hash-chain integrity."""
        if not self.path.exists():
            return []

        records: list[dict[str, Any]] = []
        previous_hash: str | None = None
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    raise LedgerIntegrityError(f"blank line at {line_number}")
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LedgerIntegrityError(f"invalid JSON at line {line_number}") from exc
                if not isinstance(record, dict) or "record_hash" not in record:
                    raise LedgerIntegrityError(f"invalid record at line {line_number}")

                supplied_hash = record["record_hash"]
                unsigned = {key: value for key, value in record.items() if key != "record_hash"}
                if record.get("previous_hash") != previous_hash:
                    raise LedgerIntegrityError(f"broken previous_hash at line {line_number}")
                expected_hash = _record_digest(unsigned)
                if supplied_hash != expected_hash:
                    raise LedgerIntegrityError(f"record hash mismatch at line {line_number}")

                records.append(record)
                previous_hash = supplied_hash
        return records

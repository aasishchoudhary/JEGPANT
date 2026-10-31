"""Worker that executes queued cognitive investigations and persists reports."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from .case_store import EncryptedCaseStore
from .job_queue import AnalysisJobQueue, JobClaim
from .runtime import CognitiveRuntime


class QueueProtocol(Protocol):
    def claim_next(self, *, worker_id: str, lease_seconds: int = 900) -> JobClaim | None: ...
    def renew_lease(
        self, *, job_id: str, worker_id: str, lease_seconds: int = 900
    ) -> bool: ...
    def complete(self, *, job_id: str, worker_id: str, result_id: str) -> bool: ...
    def fail(
        self,
        *,
        job_id: str,
        worker_id: str,
        error_code: str,
        retryable: bool = True,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class WorkerOutcome:
    job_id: str | None
    status: str
    result_id: str | None = None
    error_code: str | None = None


class AnalysisWorker:
    """Run one job at a time with a lease heartbeat.

    Worker errors are reduced to safe machine-readable codes. Exception text,
    prompts, source observations, and generated reports are never put in queue
    status fields or standard logs by this class.
    """

    def __init__(
        self,
        *,
        queue: QueueProtocol,
        case_store: EncryptedCaseStore,
        runtime: CognitiveRuntime,
        worker_id: str | None = None,
        lease_seconds: int = 900,
    ) -> None:
        if not 30 <= lease_seconds <= 86400:
            raise ValueError("lease_seconds must be between 30 and 86400")
        self.queue = queue
        self.case_store = case_store
        self.runtime = runtime
        self.worker_id = worker_id or str(uuid4())
        self.lease_seconds = lease_seconds
        if not self.worker_id.strip():
            raise ValueError("worker_id must be non-empty")

    def _error_code(self, exc: Exception) -> str:
        if isinstance(exc, KeyError):
            return "case_or_evidence_missing"
        if isinstance(exc, ValueError):
            return "analysis_input_invalid"
        if isinstance(exc, TimeoutError):
            return "inference_timeout"
        return "analysis_execution_failed"

    def process_one(self) -> WorkerOutcome:
        """Claim and process one job, or return idle when the queue is empty."""
        claim = self.queue.claim_next(
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
        )
        if claim is None:
            return WorkerOutcome(job_id=None, status="idle")

        stop_heartbeat = threading.Event()
        lease_lost = threading.Event()
        heartbeat_interval = max(5.0, self.lease_seconds / 3.0)

        def heartbeat() -> None:
            while not stop_heartbeat.wait(heartbeat_interval):
                try:
                    renewed = self.queue.renew_lease(
                        job_id=claim.job_id,
                        worker_id=self.worker_id,
                        lease_seconds=self.lease_seconds,
                    )
                except Exception:
                    renewed = False
                if not renewed:
                    lease_lost.set()
                    return

        heartbeat_thread = threading.Thread(
            target=heartbeat,
            name=f"jegpant-lease-{claim.job_id[:8]}",
            daemon=True,
        )
        heartbeat_thread.start()

        try:
            existing_result = self.case_store.get_job_result_id(
                claim.case_id, claim.job_id
            )
            if existing_result is not None:
                if self.queue.complete(
                    job_id=claim.job_id,
                    worker_id=self.worker_id,
                    result_id=existing_result,
                ):
                    return WorkerOutcome(
                        job_id=claim.job_id,
                        status="completed_recovered",
                        result_id=existing_result,
                    )
                return WorkerOutcome(
                    job_id=claim.job_id,
                    status="lease_lost",
                    result_id=existing_result,
                )

            evidence = self.case_store.list_evidence(claim.case_id)
            result = self.runtime.investigate(
                goal=claim.goal,
                evidence=evidence,
            )
            result_id = self.case_store.store_result(
                claim.case_id,
                result,
                job_id=claim.job_id,
            )

            if self.queue.complete(
                job_id=claim.job_id,
                worker_id=self.worker_id,
                result_id=result_id,
            ):
                return WorkerOutcome(
                    job_id=claim.job_id,
                    status="completed",
                    result_id=result_id,
                )
            return WorkerOutcome(
                job_id=claim.job_id,
                status="lease_lost",
                result_id=result_id,
            )
        except Exception as exc:
            if lease_lost.is_set():
                return WorkerOutcome(
                    job_id=claim.job_id,
                    status="lease_lost",
                    error_code="worker_lease_lost",
                )
            error_code = self._error_code(exc)
            self.queue.fail(
                job_id=claim.job_id,
                worker_id=self.worker_id,
                error_code=error_code,
                retryable=True,
            )
            return WorkerOutcome(
                job_id=claim.job_id,
                status="failed_or_requeued",
                error_code=error_code,
            )
        finally:
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=1.0)

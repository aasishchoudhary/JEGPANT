import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from jegpant.case_store import EncryptedCaseStore
from jegpant.inference import ChatResponse
from jegpant.job_queue import AnalysisJobQueue
from jegpant.runtime import CognitiveRuntime, InvestigationEvidence
from jegpant.worker import AnalysisWorker


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def get_key(self, version):
        return b"w" * 32


class FakeClock:
    def __init__(self):
        self.value = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


class QueueClient:
    def __init__(self):
        self.responses = [
            {
                "hypotheses": [
                    {
                        "id": "h1",
                        "statement": "A person opened the door.",
                        "supporting_evidence_ids": ["e1"],
                        "contradicting_evidence_ids": [],
                        "assumptions": [],
                        "discriminating_questions": [],
                    },
                    {
                        "id": "h2",
                        "statement": "A mechanical fault moved the door.",
                        "supporting_evidence_ids": [],
                        "contradicting_evidence_ids": ["e1"],
                        "assumptions": [],
                        "discriminating_questions": [],
                    },
                ],
                "unresolved_questions": [],
            },
            {
                "judgements": [
                    {
                        "hypothesis_id": "h1",
                        "evidence_id": "e1",
                        "rating": "consistent",
                        "diagnosticity": 2,
                        "rationale": "The observation is compatible.",
                    },
                    {
                        "hypothesis_id": "h2",
                        "evidence_id": "e1",
                        "rating": "neutral",
                        "diagnosticity": 1,
                        "rationale": "The cause is not visible.",
                    },
                ],
                "review_notes": ["Review original source."],
            },
        ]

    def complete(self, messages, *, temperature=0.0, max_tokens=2048):
        return ChatResponse(json.dumps(self.responses.pop(0)), "worker-test-model")


class FailFirstCompleteQueue:
    def __init__(self, queue):
        self.queue = queue
        self.fail_once = True

    def claim_next(self, **kwargs):
        return self.queue.claim_next(**kwargs)

    def renew_lease(self, **kwargs):
        return self.queue.renew_lease(**kwargs)

    def fail(self, **kwargs):
        return self.queue.fail(**kwargs)

    def complete(self, **kwargs):
        if self.fail_once:
            self.fail_once = False
            return False
        return self.queue.complete(**kwargs)


def setup(tmp_path, *, clock=None):
    case_store = EncryptedCaseStore(
        tmp_path / "cases.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
    )
    queue = AnalysisJobQueue(
        tmp_path / "jobs.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
        clock=clock,
    )
    return case_store, queue


def add_evidence(case_store):
    case_id = case_store.create_case()
    evidence = InvestigationEvidence(
        "e1",
        "video://asset-1",
        "camera-1",
        "Door moves inward at 00:01:10.",
        quality_level=3,
        source_start_ms=70000,
        source_end_ms=72000,
    )
    case_store.add_evidence(case_id, evidence)
    return case_id


def test_worker_processes_job_and_persists_result(tmp_path):
    case_store, queue = setup(tmp_path)
    case_id = add_evidence(case_store)
    job_id = queue.enqueue(case_id=case_id, goal="Explain the door movement.")

    worker = AnalysisWorker(
        queue=queue,
        case_store=case_store,
        runtime=CognitiveRuntime(QueueClient()),
        worker_id="worker-1",
        lease_seconds=30,
    )
    outcome = worker.process_one()

    assert outcome.job_id == job_id
    assert outcome.status == "completed"
    assert outcome.result_id is not None
    assert queue.get_status(job_id).status == "completed"
    report = case_store.get_result(case_id, outcome.result_id)
    assert report["goal"] == "Explain the door movement."
    assert report["human_review_required"] is True


def test_worker_returns_idle_when_no_jobs_exist(tmp_path):
    case_store, queue = setup(tmp_path)
    outcome = AnalysisWorker(
        queue=queue,
        case_store=case_store,
        runtime=CognitiveRuntime(QueueClient()),
        worker_id="worker-1",
    ).process_one()

    assert outcome.status == "idle"
    assert outcome.job_id is None


def test_worker_recovers_existing_report_after_completion_interruption(tmp_path):
    clock = FakeClock()
    case_store, queue = setup(tmp_path, clock=clock)
    case_id = add_evidence(case_store)
    job_id = queue.enqueue(case_id=case_id, goal="Explain the door movement.")
    runtime = CognitiveRuntime(QueueClient())
    interrupted_queue = FailFirstCompleteQueue(queue)

    first = AnalysisWorker(
        queue=interrupted_queue,
        case_store=case_store,
        runtime=runtime,
        worker_id="worker-a",
        lease_seconds=30,
    ).process_one()
    assert first.status == "lease_lost"
    assert first.result_id is not None
    assert case_store.report_count(case_id) == 1
    assert queue.get_status(job_id).status == "running"

    clock.advance(31)
    second = AnalysisWorker(
        queue=queue,
        case_store=case_store,
        runtime=runtime,
        worker_id="worker-b",
        lease_seconds=30,
    ).process_one()

    assert second.status == "completed_recovered"
    assert second.result_id == first.result_id
    assert case_store.report_count(case_id) == 1
    # The runtime consumed its two queued model responses only on the first pass.
    assert runtime.hypothesis_generator.client.responses == []


def test_worker_fails_safely_without_leaking_exception_text(tmp_path):
    case_store, queue = setup(tmp_path)
    missing_case_id = str(uuid4())
    job_id = queue.enqueue(case_id=missing_case_id, goal="Sensitive goal.")
    worker = AnalysisWorker(
        queue=queue,
        case_store=case_store,
        runtime=CognitiveRuntime(QueueClient()),
        worker_id="worker-1",
        lease_seconds=30,
    )

    outcome = worker.process_one()
    assert outcome.status == "failed_or_requeued"
    status = queue.get_status(job_id)
    assert status.status == "pending"
    assert status.error_code == "case_or_evidence_missing"
    assert "Sensitive goal" not in str(status)

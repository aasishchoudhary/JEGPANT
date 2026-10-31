import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from jegpant.job_queue import AnalysisJobQueue, JobQueueError


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def get_key(self, version):
        return b"j" * 32


class FakeClock:
    def __init__(self):
        self.value = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


def make_queue(path, *, clock=None):
    return AnalysisJobQueue(
        path,
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
        clock=clock,
    )


def test_enqueue_encrypts_goal_and_survives_restart(tmp_path):
    path = tmp_path / "jobs.sqlite"
    goal = "Analyse sensitive video about a private incident."

    queue = make_queue(path)
    job_id = queue.enqueue(case_id=str(uuid4()), goal=goal)
    status = queue.get_status(job_id)
    assert status.status == "pending"
    assert status.attempts == 0

    raw = path.read_bytes()
    assert goal.encode() not in raw

    restarted = make_queue(path)
    claim = restarted.claim_next(worker_id="worker-a", lease_seconds=60)
    assert claim is not None
    assert claim.job_id == job_id
    assert claim.goal == goal
    assert claim.attempt == 1


def test_only_one_worker_can_claim_a_job_across_queue_instances(tmp_path):
    path = tmp_path / "jobs.sqlite"
    first = make_queue(path)
    second = make_queue(path)
    job_id = first.enqueue(case_id=str(uuid4()), goal="Inspect recording.")

    def claim(queue, worker):
        return queue.claim_next(worker_id=worker, lease_seconds=90)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda item: claim(*item), ((first, "w1"), (second, "w2"))))

    claims = [item for item in results if item is not None]
    assert len(claims) == 1
    assert claims[0].job_id == job_id


def test_expired_lease_allows_retry_by_another_worker(tmp_path):
    path = tmp_path / "jobs.sqlite"
    clock = FakeClock()
    queue = make_queue(path, clock=clock)
    job_id = queue.enqueue(
        case_id=str(uuid4()), goal="Analyse.", max_attempts=3
    )

    first = queue.claim_next(worker_id="worker-a", lease_seconds=30)
    assert first is not None and first.attempt == 1

    clock.advance(31)
    second = queue.claim_next(worker_id="worker-b", lease_seconds=30)
    assert second is not None and second.job_id == job_id
    assert second.attempt == 2
    assert second.worker_id == "worker-b"


def test_heartbeat_extends_lease_and_wrong_worker_cannot_complete(tmp_path):
    clock = FakeClock()
    queue = make_queue(tmp_path / "jobs.sqlite", clock=clock)
    job_id = queue.enqueue(case_id=str(uuid4()), goal="Analyse.")
    claim = queue.claim_next(worker_id="worker-a", lease_seconds=30)
    assert claim is not None

    clock.advance(20)
    assert queue.renew_lease(
        job_id=job_id, worker_id="worker-a", lease_seconds=60
    ) is True

    result_id = str(uuid4())
    assert queue.complete(
        job_id=job_id, worker_id="worker-b", result_id=result_id
    ) is False
    assert queue.complete(
        job_id=job_id, worker_id="worker-a", result_id=result_id
    ) is True
    assert queue.get_status(job_id).status == "completed"


def test_failure_retries_until_attempt_limit_then_stops(tmp_path):
    clock = FakeClock()
    queue = make_queue(tmp_path / "jobs.sqlite", clock=clock)
    job_id = queue.enqueue(
        case_id=str(uuid4()), goal="Analyse.", max_attempts=2
    )

    first = queue.claim_next(worker_id="worker-a", lease_seconds=30)
    assert first is not None
    assert queue.fail(
        job_id=job_id,
        worker_id="worker-a",
        error_code="model_timeout",
    ) is True
    assert queue.get_status(job_id).status == "pending"

    second = queue.claim_next(worker_id="worker-b", lease_seconds=30)
    assert second is not None and second.attempt == 2
    assert queue.fail(
        job_id=job_id,
        worker_id="worker-b",
        error_code="model_timeout",
    ) is True
    status = queue.get_status(job_id)
    assert status.status == "failed"
    assert status.error_code == "model_timeout"
    assert queue.claim_next(worker_id="worker-c") is None


def test_worker_cannot_complete_after_lease_expiry(tmp_path):
    clock = FakeClock()
    queue = make_queue(tmp_path / "jobs.sqlite", clock=clock)
    job_id = queue.enqueue(case_id=str(uuid4()), goal="Analyse.")
    claim = queue.claim_next(worker_id="worker-a", lease_seconds=30)
    assert claim is not None

    clock.advance(31)
    assert queue.complete(
        job_id=job_id,
        worker_id="worker-a",
        result_id=str(uuid4()),
    ) is False


def test_job_payload_authentication_fails_with_wrong_key(tmp_path):
    path = tmp_path / "jobs.sqlite"
    queue = make_queue(path)
    job_id = queue.enqueue(case_id=str(uuid4()), goal="Private goal.")
    queue.close()

    class WrongKey:
        def get_key(self, version):
            return b"x" * 32

    wrong_queue = AnalysisJobQueue(
        path,
        instance_id=INSTANCE_ID,
        key_provider=WrongKey(),
    )
    with pytest.raises(JobQueueError, match="authentication"):
        wrong_queue.claim_next(worker_id="worker-a", lease_seconds=60)


def test_invalid_job_parameters_are_rejected_before_insert(tmp_path):
    queue = make_queue(tmp_path / "jobs.sqlite")

    with pytest.raises(ValueError, match="case_id"):
        queue.enqueue(case_id="not-a-uuid", goal="Analyse.")
    with pytest.raises(ValueError, match="goal"):
        queue.enqueue(case_id=str(uuid4()), goal=" ")
    with pytest.raises(ValueError, match="max_attempts"):
        queue.enqueue(
            case_id=str(uuid4()), goal="Analyse.", max_attempts=11
        )

    assert queue.count() == 0


def test_expired_final_attempt_is_marked_failed_not_orphaned(tmp_path):
    clock = FakeClock()
    queue = make_queue(tmp_path / "jobs.sqlite", clock=clock)
    job_id = queue.enqueue(
        case_id=str(uuid4()), goal="Analyse.", max_attempts=1
    )
    claim = queue.claim_next(worker_id="worker-a", lease_seconds=30)
    assert claim is not None

    clock.advance(31)
    assert queue.claim_next(worker_id="worker-b", lease_seconds=30) is None
    assert queue.get_status(job_id).status == "failed"

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jegpant.memory import SignedOwnerApproval
from jegpant.owner_auth import (
    DeviceEnrollment,
    Ed25519ApprovalVerifier,
    OwnerAuthorizationError,
    OwnerAuthorizationService,
    SignedDeviceRequest,
    SignedDeviceRevocation,
    enrollment_signing_bytes,
    owner_approval_signing_bytes,
    request_signing_bytes,
    revocation_signing_bytes,
)
from jegpant.owner_state_store import SQLiteOwnerStateStore


INSTANCE_ID = str(uuid4())


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def make_enrollment(owner_key, device_key, *, scopes=("read_memory", "manage_devices")):
    now = datetime.now(UTC)
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=str(uuid4()),
        device_public_key_b64=b64(public_bytes(device_key)),
        scopes=scopes,
        enrollment_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=2)).isoformat(),
        owner_signature_b64="",
        device_proof_b64="",
    )
    payload = enrollment_signing_bytes(enrollment)
    return replace(
        enrollment,
        owner_signature_b64=b64(owner_key.sign(payload)),
        device_proof_b64=b64(device_key.sign(payload)),
    )


def make_request(device_key, device_id, *, body=b"private request", request_id=None):
    now = datetime.now(UTC)
    request = SignedDeviceRequest(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        request_id=request_id or str(uuid4()),
        method="POST",
        path="/v1/private",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=45)).isoformat(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        signature_b64="",
    )
    return replace(
        request,
        signature_b64=b64(device_key.sign(request_signing_bytes(request))),
    )


def make_service(path, owner_key):
    state = SQLiteOwnerStateStore(path, instance_id=INSTANCE_ID)
    return OwnerAuthorizationService(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        state_store=state,
    )


def make_revocation(owner_key, device_id):
    now = datetime.now(UTC)
    revocation = SignedDeviceRevocation(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        revocation_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=45)).isoformat(),
        owner_signature_b64="",
    )
    return replace(
        revocation,
        owner_signature_b64=b64(owner_key.sign(revocation_signing_bytes(revocation))),
    )


def test_device_enrolment_survives_service_restart(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    enrollment = make_enrollment(owner_key, device_key)

    first = make_service(path, owner_key)
    first.enroll_device(enrollment)

    restarted = make_service(path, owner_key)
    record = restarted.get_device(enrollment.device_id)
    assert record is not None
    assert record.public_key == public_bytes(device_key)
    assert record.scopes == frozenset(enrollment.scopes)


def test_replay_protection_survives_service_restart(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    enrollment = make_enrollment(owner_key, device_key)
    first = make_service(path, owner_key)
    first.enroll_device(enrollment)
    request = make_request(device_key, enrollment.device_id)

    first.verify_request(request, body=b"private request", required_scope="read_memory")
    restarted = make_service(path, owner_key)
    with pytest.raises(OwnerAuthorizationError, match="replay"):
        restarted.verify_request(
            request, body=b"private request", required_scope="read_memory"
        )


def test_revocation_survives_service_restart(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    enrollment = make_enrollment(owner_key, device_key)
    first = make_service(path, owner_key)
    first.enroll_device(enrollment)
    first.revoke_device(make_revocation(owner_key, enrollment.device_id))

    restarted = make_service(path, owner_key)
    request = make_request(device_key, enrollment.device_id)
    with pytest.raises(OwnerAuthorizationError, match="revoked"):
        restarted.verify_request(
            request, body=b"private request", required_scope="read_memory"
        )


def test_approval_replay_protection_survives_verifier_restart(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    public_key = public_bytes(owner_key)
    first_store = SQLiteOwnerStateStore(path, instance_id=INSTANCE_ID)
    first = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=public_key,
        key_id="owner-key-v1",
        state_store=first_store,
    )
    approval = SignedOwnerApproval(
        instance_id=INSTANCE_ID,
        proposal_id="p-1",
        approval_id=str(uuid4()),
        key_id="owner-key-v1",
        expires_at=(datetime.now(UTC) + timedelta(minutes=2)).isoformat(),
        signature=b"",
    )
    approval = replace(
        approval,
        signature=owner_key.sign(owner_approval_signing_bytes(approval)),
    )
    assert first.verify(approval) is True

    second = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=public_key,
        key_id="owner-key-v1",
        state_store=SQLiteOwnerStateStore(path, instance_id=INSTANCE_ID),
    )
    assert second.verify(approval) is False


def test_two_service_instances_cannot_accept_same_request_concurrently(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    enrollment = make_enrollment(owner_key, device_key)
    first = make_service(path, owner_key)
    first.enroll_device(enrollment)
    second = make_service(path, owner_key)
    request = make_request(device_key, enrollment.device_id)

    def attempt(service):
        try:
            service.verify_request(
                request, body=b"private request", required_scope="read_memory"
            )
            return "accepted"
        except OwnerAuthorizationError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (first, second)))

    assert outcomes.count("accepted") == 1
    assert outcomes.count("rejected") == 1


def test_scope_and_revocation_are_checked_atomically_with_request_consumption(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    enrollment = make_enrollment(owner_key, device_key, scopes=("read_memory",))
    service = make_service(path, owner_key)
    service.enroll_device(enrollment)
    request = make_request(device_key, enrollment.device_id)

    with pytest.raises(OwnerAuthorizationError, match="lacks"):
        service.verify_request(
            request, body=b"private request", required_scope="export_data"
        )

    # The failed-scope attempt does not consume the request ID; it can be retried
    # only after an owner-authorised scope change (not implemented by this prototype).
    assert service.state_store.counts()["requests"] == 0


def test_sqlite_state_is_scoped_by_instance_id(tmp_path):
    path = tmp_path / "owner-state.sqlite"
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    enrollment = make_enrollment(owner_key, device_key)
    first = make_service(path, owner_key)
    first.enroll_device(enrollment)

    other_instance = str(uuid4())
    other_store = SQLiteOwnerStateStore(path, instance_id=other_instance)
    assert other_store.get_device(enrollment.device_id) is None
    assert other_store.counts()["devices"] == 0


def test_sqlite_store_rejects_in_memory_path(tmp_path):
    with pytest.raises(ValueError, match="persistent database path"):
        SQLiteOwnerStateStore(":memory:", instance_id=INSTANCE_ID)

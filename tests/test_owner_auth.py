import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
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
from jegpant.signatures import ECDSA_P256


INSTANCE_ID = str(uuid4())
NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=UTC)
ISSUED = "2026-10-31T12:00:00Z"
EXPIRES = "2026-10-31T12:01:00Z"


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def b64(value):
    return base64.b64encode(value).decode("ascii")


def make_enrollment(owner_key, device_key, *, scopes=("read_evidence", "run_analysis")):
    device_id = str(uuid4())
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        device_public_key_b64=b64(public_bytes(device_key)),
        scopes=tuple(scopes),
        enrollment_id=str(uuid4()),
        issued_at=ISSUED,
        expires_at="2026-10-31T12:05:00Z",
        owner_signature_b64="",
        device_proof_b64="",
    )
    payload = enrollment_signing_bytes(enrollment)
    return replace(
        enrollment,
        owner_signature_b64=b64(owner_key.sign(payload)),
        device_proof_b64=b64(device_key.sign(payload)),
    )


def make_request(device_key, device_id, body=b"request-payload", *, request_id=None):
    request = SignedDeviceRequest(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        request_id=request_id or str(uuid4()),
        method="POST",
        path="/v1/analysis",
        issued_at=ISSUED,
        expires_at=EXPIRES,
        body_sha256=hashlib.sha256(body).hexdigest(),
        signature_b64="",
    )
    return replace(
        request,
        signature_b64=b64(device_key.sign(request_signing_bytes(request))),
    )


def make_service(owner_key):
    return OwnerAuthorizationService(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        clock=lambda: NOW,
    )


def test_owner_and_device_signatures_are_required_for_enrolment():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)

    record = service.enroll_device(enrollment)
    assert record.device_id == enrollment.device_id
    assert record.scopes == frozenset({"read_evidence", "run_analysis"})


def test_signed_request_verifies_and_is_one_time():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    service.enroll_device(enrollment)
    request = make_request(device_key, enrollment.device_id)

    record = service.verify_request(
        request, body=b"request-payload", required_scope="run_analysis"
    )
    assert record.device_id == enrollment.device_id

    with pytest.raises(OwnerAuthorizationError, match="replay"):
        service.verify_request(
            request, body=b"request-payload", required_scope="run_analysis"
        )


def test_request_body_tampering_is_rejected():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    service.enroll_device(enrollment)
    request = make_request(device_key, enrollment.device_id)

    with pytest.raises(OwnerAuthorizationError, match="body digest"):
        service.verify_request(
            request, body=b"changed-body", required_scope="run_analysis"
        )


def test_device_without_scope_cannot_use_operation():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key, scopes=("read_evidence",))
    service.enroll_device(enrollment)
    request = make_request(device_key, enrollment.device_id)

    with pytest.raises(OwnerAuthorizationError, match="lacks"):
        service.verify_request(
            request, body=b"request-payload", required_scope="run_analysis"
        )


def test_enrolment_with_invalid_owner_signature_is_rejected():
    owner_key = Ed25519PrivateKey.generate()
    other_owner = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(other_owner, device_key)

    with pytest.raises(OwnerAuthorizationError, match="owner signature"):
        service.enroll_device(enrollment)


def test_enrolment_requires_proof_of_device_private_key():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    other_device = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    enrollment = replace(
        enrollment,
        device_proof_b64=b64(other_device.sign(enrollment_signing_bytes(enrollment))),
    )

    with pytest.raises(OwnerAuthorizationError, match="possession proof"):
        service.enroll_device(enrollment)


def test_enrolment_rejects_expired_or_overlong_window():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    enrollment = replace(enrollment, issued_at="2026-10-31T11:00:00Z")

    with pytest.raises(OwnerAuthorizationError, match="time window"):
        service.enroll_device(enrollment)


def test_cross_instance_enrolment_is_rejected():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    enrollment = replace(enrollment, instance_id=str(uuid4()))

    with pytest.raises(OwnerAuthorizationError, match="different instance"):
        service.enroll_device(enrollment)


def test_owner_signed_revocation_invalidates_device():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    service.enroll_device(enrollment)

    revocation = SignedDeviceRevocation(
        instance_id=INSTANCE_ID,
        device_id=enrollment.device_id,
        revocation_id=str(uuid4()),
        issued_at=ISSUED,
        expires_at=EXPIRES,
        owner_signature_b64="",
    )
    revocation = replace(
        revocation,
        owner_signature_b64=b64(owner_key.sign(revocation_signing_bytes(revocation))),
    )
    assert service.revoke_device(revocation).revoked_at is not None

    request = make_request(device_key, enrollment.device_id)
    with pytest.raises(OwnerAuthorizationError, match="revoked"):
        service.verify_request(
            request, body=b"request-payload", required_scope="run_analysis"
        )


def test_owner_approval_verifier_binds_instance_and_rejects_replay():
    owner_key = Ed25519PrivateKey.generate()
    verifier = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        key_id="owner-key-v1",
        clock=lambda: NOW,
    )
    approval = SignedOwnerApproval(
        instance_id=INSTANCE_ID,
        proposal_id="proposal-1",
        approval_id=str(uuid4()),
        key_id="owner-key-v1",
        expires_at="2026-10-31T12:02:00Z",
        signature=b"",
    )
    approval = replace(
        approval,
        signature=owner_key.sign(owner_approval_signing_bytes(approval)),
    )

    assert verifier.verify(approval) is True
    assert verifier.verify(approval) is False


def test_memory_approval_with_wrong_key_id_is_rejected():
    owner_key = Ed25519PrivateKey.generate()
    verifier = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        key_id="owner-key-v1",
        clock=lambda: NOW,
    )
    approval = SignedOwnerApproval(
        instance_id=INSTANCE_ID,
        proposal_id="proposal-1",
        approval_id=str(uuid4()),
        key_id="old-key",
        expires_at="2026-10-31T12:02:00Z",
        signature=b"invalid",
    )

    assert verifier.verify(approval) is False


def test_request_signature_is_bound_to_path_and_method():
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    service.enroll_device(enrollment)

    request = make_request(device_key, enrollment.device_id)
    tampered = replace(request, path="/v1/export")
    with pytest.raises(OwnerAuthorizationError, match="signature is invalid"):
        service.verify_request(
            tampered, body=b"request-payload", required_scope="run_analysis"
        )



def test_concurrent_replay_of_same_request_only_succeeds_once():
    from concurrent.futures import ThreadPoolExecutor

    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    service = make_service(owner_key)
    enrollment = make_enrollment(owner_key, device_key)
    service.enroll_device(enrollment)
    request = make_request(device_key, enrollment.device_id)

    def attempt():
        try:
            service.verify_request(
                request, body=b"request-payload", required_scope="run_analysis"
            )
            return "accepted"
        except OwnerAuthorizationError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(8)))

    assert outcomes.count("accepted") == 1
    assert outcomes.count("rejected") == 7


def test_concurrent_replay_of_memory_approval_only_succeeds_once():
    from concurrent.futures import ThreadPoolExecutor

    owner_key = Ed25519PrivateKey.generate()
    verifier = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        key_id="owner-key-v1",
        clock=lambda: NOW,
    )
    approval = SignedOwnerApproval(
        instance_id=INSTANCE_ID,
        proposal_id="proposal-1",
        approval_id=str(uuid4()),
        key_id="owner-key-v1",
        expires_at="2026-10-31T12:02:00Z",
        signature=b"",
    )
    approval = replace(
        approval,
        signature=owner_key.sign(owner_approval_signing_bytes(approval)),
    )

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: verifier.verify(approval), range(8)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7



def p256_public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def p256_sign(private_key, payload):
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def test_p256_owner_and_device_signatures_are_supported():
    owner_key = ec.generate_private_key(ec.SECP256R1())
    device_key = ec.generate_private_key(ec.SECP256R1())
    device_id = str(uuid4())
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        device_public_key_b64=b64(p256_public_bytes(device_key)),
        scopes=("read_evidence", "run_analysis"),
        enrollment_id=str(uuid4()),
        issued_at=ISSUED,
        expires_at="2026-10-31T12:05:00Z",
        owner_signature_b64="",
        device_proof_b64="",
        device_key_algorithm=ECDSA_P256,
    )
    payload = enrollment_signing_bytes(enrollment)
    enrollment = replace(
        enrollment,
        owner_signature_b64=b64(p256_sign(owner_key, payload)),
        device_proof_b64=b64(p256_sign(device_key, payload)),
    )
    service = OwnerAuthorizationService(
        instance_id=INSTANCE_ID,
        owner_public_key=p256_public_bytes(owner_key),
        owner_key_algorithm=ECDSA_P256,
        clock=lambda: NOW,
    )
    record = service.enroll_device(enrollment)

    assert record.key_algorithm == ECDSA_P256
    request = SignedDeviceRequest(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        request_id=str(uuid4()),
        method="POST",
        path="/v1/evidence",
        issued_at=ISSUED,
        expires_at=EXPIRES,
        body_sha256=hashlib.sha256(b"payload").hexdigest(),
        signature_b64="",
    )
    request = replace(
        request,
        signature_b64=b64(p256_sign(device_key, request_signing_bytes(request))),
    )
    verified = service.verify_request(
        request, body=b"payload", required_scope="read_evidence"
    )
    assert verified.device_id == device_id


def test_p256_owner_approval_verifier_supports_android_keystore_signatures():
    owner_key = ec.generate_private_key(ec.SECP256R1())
    verifier = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=p256_public_bytes(owner_key),
        owner_key_algorithm=ECDSA_P256,
        key_id="owner-p256-v1",
        clock=lambda: NOW,
    )
    approval = SignedOwnerApproval(
        instance_id=INSTANCE_ID,
        proposal_id="proposal-p256",
        approval_id=str(uuid4()),
        key_id="owner-p256-v1",
        expires_at="2026-10-31T12:02:00Z",
        signature=b"",
    )
    approval = replace(
        approval,
        signature=p256_sign(owner_key, owner_approval_signing_bytes(approval)),
    )
    assert verifier.verify(approval) is True
    assert verifier.verify(approval) is False


def test_p256_verifier_rejects_non_p256_ec_curve():
    owner_key = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="P-256"):
        OwnerAuthorizationService(
            instance_id=INSTANCE_ID,
            owner_public_key=p256_public_bytes(owner_key),
            owner_key_algorithm=ECDSA_P256,
        )

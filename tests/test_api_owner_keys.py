import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from jegpant.api import create_app
from jegpant.case_store import EncryptedCaseStore
from jegpant.job_queue import AnalysisJobQueue
from jegpant.owner_auth import (
    DeviceEnrollment,
    OwnerAuthorizationService,
    SignedDeviceRevocation,
    enrollment_signing_bytes,
    revocation_signing_bytes,
)
from jegpant.owner_state_store import InMemoryOwnerStateStore
from jegpant.signatures import ECDSA_P256


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def get_key(self, version):
        return b"p" * 32


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def der_public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_app(tmp_path, owner_public_key, *, owner_key_algorithm="ed25519"):
    authorization = OwnerAuthorizationService(
        instance_id=INSTANCE_ID,
        owner_public_key=owner_public_key,
        owner_key_algorithm=owner_key_algorithm,
        state_store=InMemoryOwnerStateStore(INSTANCE_ID),
    )
    cases = EncryptedCaseStore(
        tmp_path / "cases.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
    )
    jobs = AnalysisJobQueue(
        tmp_path / "jobs.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
    )
    return TestClient(
        create_app(authorization=authorization, cases=cases, jobs=jobs)
    ), authorization


def test_private_api_enrolls_p256_android_device_with_owner_signature(tmp_path):
    owner_key = ec.generate_private_key(ec.SECP256R1())
    device_key = ec.generate_private_key(ec.SECP256R1())
    client, authorization = build_app(
        tmp_path, der_public_bytes(owner_key), owner_key_algorithm=ECDSA_P256
    )

    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=str(uuid4()),
        device_public_key_b64=base64.b64encode(der_public_bytes(device_key)).decode(),
        scopes=("create_case", "read_evidence"),
        enrollment_id=str(uuid4()),
        issued_at=datetime.now(UTC).isoformat(),
        expires_at=(datetime.now(UTC) + timedelta(minutes=2)).isoformat(),
        owner_signature_b64="",
        device_proof_b64="",
        device_key_algorithm=ECDSA_P256,
    )
    signed_payload = enrollment_signing_bytes(enrollment)
    enrollment = replace(
        enrollment,
        owner_signature_b64=base64.b64encode(
            owner_key.sign(signed_payload, ec.ECDSA(hashes.SHA256()))
        ).decode(),
        device_proof_b64=base64.b64encode(
            device_key.sign(signed_payload, ec.ECDSA(hashes.SHA256()))
        ).decode(),
    )
    body = json.dumps(
        {
            "instance_id": enrollment.instance_id,
            "device_id": enrollment.device_id,
            "device_public_key_b64": enrollment.device_public_key_b64,
            "device_key_algorithm": enrollment.device_key_algorithm,
            "scopes": list(enrollment.scopes),
            "enrollment_id": enrollment.enrollment_id,
            "issued_at": enrollment.issued_at,
            "expires_at": enrollment.expires_at,
            "owner_signature_b64": enrollment.owner_signature_b64,
            "device_proof_b64": enrollment.device_proof_b64,
        }
    )
    response = client.post("/v1/devices/enroll", content=body)

    assert response.status_code == 201
    assert response.json()["key_algorithm"] == ECDSA_P256
    assert response.json()["scopes"] == ["create_case", "read_evidence"]
    assert authorization.get_device(enrollment.device_id).key_algorithm == ECDSA_P256


def test_private_api_requires_owner_signature_for_enrollment(tmp_path):
    owner_key = Ed25519PrivateKey.generate()
    client, authorization = build_app(tmp_path, public_bytes(owner_key))
    device_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=str(uuid4()),
        device_public_key_b64=base64.b64encode(public_bytes(device_key)).decode(),
        scopes=("read_evidence",),
        enrollment_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=2)).isoformat(),
        owner_signature_b64=base64.b64encode(b"invalid").decode(),
        device_proof_b64=base64.b64encode(b"invalid").decode(),
    )
    body = json.dumps(
        {
            "instance_id": enrollment.instance_id,
            "device_id": enrollment.device_id,
            "device_public_key_b64": enrollment.device_public_key_b64,
            "device_key_algorithm": enrollment.device_key_algorithm,
            "scopes": list(enrollment.scopes),
            "enrollment_id": enrollment.enrollment_id,
            "issued_at": enrollment.issued_at,
            "expires_at": enrollment.expires_at,
            "owner_signature_b64": enrollment.owner_signature_b64,
            "device_proof_b64": enrollment.device_proof_b64,
        }
    )
    response = client.post("/v1/devices/enroll", content=body)

    assert response.status_code == 403
    assert authorization.get_device(enrollment.device_id) is None


def test_private_api_supports_owner_signed_device_revocation(tmp_path):
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    client, authorization = build_app(tmp_path, public_bytes(owner_key))
    now = datetime.now(UTC)
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=str(uuid4()),
        device_public_key_b64=base64.b64encode(public_bytes(device_key)).decode(),
        scopes=("read_evidence",),
        enrollment_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=2)).isoformat(),
        owner_signature_b64="",
        device_proof_b64="",
    )
    payload = enrollment_signing_bytes(enrollment)
    enrollment = replace(
        enrollment,
        owner_signature_b64=base64.b64encode(owner_key.sign(payload)).decode(),
        device_proof_b64=base64.b64encode(device_key.sign(payload)).decode(),
    )
    authorization.enroll_device(enrollment)

    revocation = SignedDeviceRevocation(
        instance_id=INSTANCE_ID,
        device_id=enrollment.device_id,
        revocation_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=45)).isoformat(),
        owner_signature_b64="",
    )
    revocation = replace(
        revocation,
        owner_signature_b64=base64.b64encode(
            owner_key.sign(revocation_signing_bytes(revocation))
        ).decode(),
    )
    body = json.dumps(
        {
            "instance_id": revocation.instance_id,
            "device_id": revocation.device_id,
            "revocation_id": revocation.revocation_id,
            "issued_at": revocation.issued_at,
            "expires_at": revocation.expires_at,
            "owner_signature_b64": revocation.owner_signature_b64,
        }
    )
    response = client.post(
        f"/v1/devices/{enrollment.device_id}/revoke",
        content=body,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"
    assert authorization.get_device(enrollment.device_id).revoked_at is not None

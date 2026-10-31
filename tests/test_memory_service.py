import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jegpant.encrypted_store import EncryptedMemoryStore
from jegpant.memory import (
    MemoryKind,
    MemoryProposal,
    MemorySensitivity,
    SignedOwnerApproval,
)
from jegpant.memory_service import (
    MemoryPromotionService,
    promotion_request_body,
    retrieval_request_body,
)
from jegpant.owner_auth import (
    DeviceEnrollment,
    Ed25519ApprovalVerifier,
    OwnerAuthorizationService,
    SignedDeviceRequest,
    enrollment_signing_bytes,
    owner_approval_signing_bytes,
    request_signing_bytes,
)


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def get_key(self, version):
        return b"z" * 32


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def make_proposal():
    return MemoryProposal(
        proposal_id="case-episode-001",
        kind=MemoryKind.EPISODIC,
        summary="Reviewed video timeline; entry observed at 00:01:12.",
        provenance_refs=("evidence-001", "claim-003"),
        sensitivity=MemorySensitivity.HIGHLY_SENSITIVE,
        context_tags=("case-001", "video"),
    )


def setup_security(instance_id=INSTANCE_ID):
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    device_id = str(uuid4())
    enrollment = DeviceEnrollment(
        instance_id=instance_id,
        device_id=device_id,
        device_public_key_b64=base64.b64encode(public_bytes(device_key)).decode(),
        scopes=("propose_memory", "read_memory"),
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

    authorization_service = OwnerAuthorizationService(
        instance_id=instance_id,
        owner_public_key=public_bytes(owner_key),
    )
    authorization_service.enroll_device(enrollment)
    verifier = Ed25519ApprovalVerifier(
        instance_id=instance_id,
        owner_public_key=public_bytes(owner_key),
        key_id="owner-key-v1",
    )
    return authorization_service, verifier, owner_key, device_key, device_id


def make_approval(owner_key, proposal, instance_id=INSTANCE_ID):
    approval = SignedOwnerApproval(
        instance_id=instance_id,
        proposal_id=proposal.proposal_id,
        approval_id=str(uuid4()),
        key_id="owner-key-v1",
        expires_at=(datetime.now(UTC) + timedelta(minutes=2)).isoformat(),
        signature=b"",
    )
    return replace(
        approval,
        signature=owner_key.sign(owner_approval_signing_bytes(approval)),
    )


def make_request(device_key, device_id, body, path):
    now = datetime.now(UTC)
    request = SignedDeviceRequest(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        request_id=str(uuid4()),
        method="POST",
        path=path,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=45)).isoformat(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        signature_b64="",
    )
    return replace(
        request,
        signature_b64=base64.b64encode(
            device_key.sign(request_signing_bytes(request))
        ).decode(),
    )


def open_store(path, instance_id=INSTANCE_ID):
    return EncryptedMemoryStore(
        path,
        instance_id=instance_id,
        key_provider=FakeKeyProvider(),
    )


def make_service(store):
    authorization_service, verifier, owner_key, device_key, device_id = setup_security()
    service = MemoryPromotionService(
        instance_id=INSTANCE_ID,
        verifier=verifier,
        authorization_service=authorization_service,
        store=store,
    )
    return service, owner_key, device_key, device_id


def promote(service, owner_key, device_key, device_id, proposal):
    approval = make_approval(owner_key, proposal)
    request = make_request(
        device_key,
        device_id,
        promotion_request_body(proposal, approval),
        "/v1/memory/promote",
    )
    return service.promote(proposal, approval, request)


def retrieve(service, device_key, device_id, proposal_id):
    request = make_request(
        device_key,
        device_id,
        retrieval_request_body(proposal_id),
        "/v1/memory/retrieve",
    )
    return service.retrieve(proposal_id, request)


def test_owner_approved_memory_is_encrypted_and_persistent(tmp_path):
    path = tmp_path / "memory.sqlite"
    proposal = make_proposal()

    with open_store(path) as store:
        service, owner_key, device_key, device_id = make_service(store)
        record = promote(service, owner_key, device_key, device_id, proposal)
        assert record.proposal_id == proposal.proposal_id
        assert retrieve(service, device_key, device_id, proposal.proposal_id) == record

    raw = path.read_bytes()
    assert proposal.summary.encode() not in raw

    with open_store(path) as reopened:
        recovered = retrieve(service, device_key, device_id, proposal.proposal_id)
        assert recovered == record


def test_invalid_owner_signature_cannot_promote_memory(tmp_path):
    service_state = setup_security()
    authorization_service, verifier, owner_key, device_key, device_id = service_state
    proposal = make_proposal()
    approval = make_approval(owner_key, proposal)
    approval = replace(approval, signature=b"invalid")
    request = make_request(
        device_key,
        device_id,
        promotion_request_body(proposal, approval),
        "/v1/memory/promote",
    )

    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            authorization_service=authorization_service,
            store=store,
        )
        with pytest.raises(PermissionError, match="verification failed"):
            service.promote(proposal, approval, request)
        assert store.count() == 0


def test_approval_must_match_proposal_and_instance(tmp_path):
    authorization_service, verifier, owner_key, device_key, device_id = setup_security()
    proposal = make_proposal()
    approval = make_approval(owner_key, proposal)
    other_proposal = MemoryProposal(
        "other-proposal",
        MemoryKind.SEMANTIC,
        "Another fact.",
        ("source-2",),
    )
    request = make_request(
        device_key,
        device_id,
        promotion_request_body(other_proposal, approval),
        "/v1/memory/promote",
    )

    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            authorization_service=authorization_service,
            store=store,
        )
        with pytest.raises(PermissionError, match="different memory proposal"):
            service.promote(other_proposal, approval, request)

        wrong_instance = replace(approval, instance_id=str(uuid4()))
        with pytest.raises(PermissionError, match="different cognitive instance"):
            service.promote(proposal, wrong_instance, request)


def test_duplicate_promotion_requires_read_scope_to_return_existing_record(tmp_path):
    proposal = make_proposal()
    with open_store(tmp_path / "memory.sqlite") as store:
        service, owner_key, device_key, device_id = make_service(store)
        first = promote(service, owner_key, device_key, device_id, proposal)

        approval = make_approval(owner_key, proposal)
        second_request = make_request(
            device_key,
            device_id,
            promotion_request_body(proposal, approval),
            "/v1/memory/promote",
        )
        with pytest.raises(ValueError, match="use retrieve"):
            service.promote(proposal, approval, second_request)

        fetched = retrieve(service, device_key, device_id, proposal.proposal_id)
        assert fetched == first
        assert store.count() == 1


def test_proposal_id_cannot_be_reused_for_different_memory(tmp_path):
    proposal = make_proposal()
    with open_store(tmp_path / "memory.sqlite") as store:
        service, owner_key, device_key, device_id = make_service(store)
        promote(service, owner_key, device_key, device_id, proposal)
        changed = MemoryProposal(
            proposal_id=proposal.proposal_id,
            kind=MemoryKind.EPISODIC,
            summary="A different conclusion.",
            provenance_refs=("evidence-999",),
            sensitivity=proposal.sensitivity,
            context_tags=proposal.context_tags,
        )
        approval = make_approval(owner_key, changed)
        request = make_request(
            device_key,
            device_id,
            promotion_request_body(changed, approval),
            "/v1/memory/promote",
        )
        with pytest.raises(ValueError, match="different durable memory"):
            service.promote(changed, approval, request)


def test_device_with_only_propose_scope_cannot_retrieve_memory(tmp_path):
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    device_id = str(uuid4())
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        device_public_key_b64=base64.b64encode(public_bytes(device_key)).decode(),
        scopes=("propose_memory",),
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
    authorization_service = OwnerAuthorizationService(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
    )
    authorization_service.enroll_device(enrollment)
    verifier = Ed25519ApprovalVerifier(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        key_id="owner-key-v1",
    )
    proposal = make_proposal()

    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            authorization_service=authorization_service,
            store=store,
        )
        # Insert a record using a device with both permissions.
        other_service, other_owner, other_device, other_device_id = make_service(store)
        promote(other_service, other_owner, other_device, other_device_id, proposal)

        request = make_request(
            device_key,
            device_id,
            retrieval_request_body(proposal.proposal_id),
            "/v1/memory/retrieve",
        )
        with pytest.raises(PermissionError, match="lacks"):
            service.retrieve(proposal.proposal_id, request)

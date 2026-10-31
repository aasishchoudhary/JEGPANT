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
from jegpant.memory_service import MemoryPromotionService
from jegpant.owner_auth import (
    Ed25519ApprovalVerifier,
    owner_approval_signing_bytes,
)


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def get_key(self, version):
        return b"z" * 32


def make_proposal():
    return MemoryProposal(
        proposal_id="case-episode-001",
        kind=MemoryKind.EPISODIC,
        summary="Reviewed video timeline; entry observed at 00:01:12.",
        provenance_refs=("evidence-001", "claim-003"),
        sensitivity=MemorySensitivity.HIGHLY_SENSITIVE,
        context_tags=("case-001", "video"),
    )


def make_verifier_and_approval(instance_id=INSTANCE_ID):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = "owner-key-v1"
    verifier = Ed25519ApprovalVerifier(
        instance_id=instance_id,
        owner_public_key=public_key,
        key_id=key_id,
    )
    approval = SignedOwnerApproval(
        instance_id=instance_id,
        proposal_id="case-episode-001",
        approval_id=str(uuid4()),
        key_id=key_id,
        expires_at=(datetime.now(UTC) + timedelta(minutes=2)).isoformat(),
        signature=b"",
    )
    from dataclasses import replace

    approval = replace(
        approval,
        signature=private_key.sign(owner_approval_signing_bytes(approval)),
    )
    return verifier, approval


def open_store(path, instance_id=INSTANCE_ID):
    return EncryptedMemoryStore(
        path,
        instance_id=instance_id,
        key_provider=FakeKeyProvider(),
    )


def test_owner_approved_memory_is_encrypted_and_persistent(tmp_path):
    path = tmp_path / "memory.sqlite"
    verifier, approval = make_verifier_and_approval()
    proposal = make_proposal()

    with open_store(path) as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            store=store,
        )
        record = service.promote(proposal, approval)
        assert record.proposal_id == proposal.proposal_id
        assert service.retrieve(proposal.proposal_id) == record

    raw = path.read_bytes()
    assert proposal.summary.encode() not in raw

    with open_store(path) as reopened:
        recovered = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            store=reopened,
        ).retrieve(proposal.proposal_id)
        assert recovered == record


def test_invalid_owner_signature_cannot_promote_memory(tmp_path):
    from dataclasses import replace

    verifier, approval = make_verifier_and_approval()
    approval = replace(approval, signature=b"invalid")
    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            store=store,
        )
        with pytest.raises(PermissionError, match="verification failed"):
            service.promote(make_proposal(), approval)


def test_approval_must_match_proposal_and_instance(tmp_path):
    from dataclasses import replace

    verifier, approval = make_verifier_and_approval()
    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            store=store,
        )
        with pytest.raises(PermissionError, match="different memory proposal"):
            service.promote(
                MemoryProposal(
                    "other-proposal",
                    MemoryKind.SEMANTIC,
                    "Another fact.",
                    ("source-2",),
                ),
                approval,
            )

        wrong_instance = replace(approval, instance_id=str(uuid4()))
        with pytest.raises(PermissionError, match="different cognitive instance"):
            service.promote(make_proposal(), wrong_instance)


def test_promotion_is_idempotent_for_existing_identical_record(tmp_path):
    verifier, approval = make_verifier_and_approval()
    proposal = make_proposal()
    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            store=store,
        )
        first = service.promote(proposal, approval)
        second = service.promote(proposal, approval)
        assert first == second
        assert store.count() == 1


def test_proposal_id_cannot_be_reused_for_different_memory(tmp_path):
    verifier, approval = make_verifier_and_approval()
    proposal = make_proposal()
    with open_store(tmp_path / "memory.sqlite") as store:
        service = MemoryPromotionService(
            instance_id=INSTANCE_ID,
            verifier=verifier,
            store=store,
        )
        service.promote(proposal, approval)
        changed = MemoryProposal(
            proposal_id=proposal.proposal_id,
            kind=MemoryKind.EPISODIC,
            summary="A different conclusion.",
            provenance_refs=("evidence-999",),
            sensitivity=proposal.sensitivity,
            context_tags=proposal.context_tags,
        )
        with pytest.raises(ValueError, match="different durable memory"):
            service.promote(changed, approval)

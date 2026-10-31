import pytest

from jegpant.memory import (
    MemoryCatalog,
    MemoryKind,
    MemoryProposal,
    MemorySensitivity,
    SignedOwnerApproval,
)


class StubVerifier:
    def __init__(self, valid=True):
        self.valid = valid

    def verify(self, approval):
        return self.valid


def proposal():
    return MemoryProposal(
        "proposal-1",
        MemoryKind.EPISODIC,
        "Reviewed event sequence from case 1.",
        ("evidence-1", "claim-4"),
        MemorySensitivity.PERSONAL,
    )


def approval():
    return SignedOwnerApproval(
        "instance-1",
        "proposal-1",
        "approval-1",
        "owner-key-1",
        "2099-01-01T00:00:00Z",
        b"signature",
    )


def test_memory_promotion_requires_verified_owner_approval():
    catalog = MemoryCatalog("instance-1", StubVerifier(valid=True))
    catalog.propose(proposal())
    record = catalog.promote("proposal-1", approval())
    assert record.owner_approval_id == "approval-1"
    assert record.provenance_refs == ("evidence-1", "claim-4")


def test_unverified_approval_is_rejected():
    catalog = MemoryCatalog("instance-1", StubVerifier(valid=False))
    catalog.propose(proposal())
    with pytest.raises(PermissionError):
        catalog.promote("proposal-1", approval())


def test_approval_cannot_cross_instance_boundary():
    catalog = MemoryCatalog("instance-2", StubVerifier(valid=True))
    catalog.propose(proposal())
    with pytest.raises(PermissionError):
        catalog.promote("proposal-1", approval())


def test_durable_memory_requires_provenance():
    with pytest.raises(ValueError):
        MemoryProposal("p2", MemoryKind.SEMANTIC, "A fact", ())

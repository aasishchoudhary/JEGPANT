"""Memory proposal and owner-authorised promotion boundary.

This first implementation is an in-memory catalogue. It deliberately does not
persist plaintext memory. A production store must add encryption, key rotation,
backup, deletion, and recovery controls behind this interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import uuid4


class MemoryKind(StrEnum):
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"
    PROSPECTIVE = "prospective"
    SELF_PERFORMANCE = "self_performance"


class MemorySensitivity(StrEnum):
    LOW = "low"
    PERSONAL = "personal"
    HIGHLY_SENSITIVE = "highly_sensitive"


@dataclass(frozen=True, slots=True)
class MemoryProposal:
    proposal_id: str
    kind: MemoryKind
    summary: str
    provenance_refs: tuple[str, ...]
    sensitivity: MemorySensitivity = MemorySensitivity.PERSONAL
    context_tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.proposal_id.strip() or not self.summary.strip():
            raise ValueError("proposal_id and summary must not be empty")
        if not self.provenance_refs:
            raise ValueError("durable memory requires at least one provenance reference")


@dataclass(frozen=True, slots=True)
class SignedOwnerApproval:
    instance_id: str
    proposal_id: str
    approval_id: str
    key_id: str
    expires_at: str
    signature: bytes


class ApprovalVerifier(Protocol):
    """Implemented by the owner-authentication service, not by the LLM."""

    def verify(self, approval: SignedOwnerApproval) -> bool:
        """Verify signature, expiry, nonce/challenge, key status, and instance binding."""
        ...


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    memory_id: str
    instance_id: str
    proposal_id: str
    kind: MemoryKind
    summary: str
    provenance_refs: tuple[str, ...]
    sensitivity: MemorySensitivity
    context_tags: tuple[str, ...]
    created_at: str
    owner_approval_id: str


class MemoryCatalog:
    """Process-local memory catalogue requiring verified owner approval."""

    def __init__(self, instance_id: str, verifier: ApprovalVerifier) -> None:
        if not instance_id.strip():
            raise ValueError("instance_id must not be empty")
        self.instance_id = instance_id
        self._verifier = verifier
        self._proposals: dict[str, MemoryProposal] = {}
        self._records: dict[str, MemoryRecord] = {}

    def propose(self, proposal: MemoryProposal) -> None:
        if proposal.proposal_id in self._proposals:
            raise ValueError("proposal_id already exists")
        if proposal.proposal_id in self._records:
            raise ValueError("proposal has already been promoted")
        self._proposals[proposal.proposal_id] = proposal

    def promote(
        self, proposal_id: str, approval: SignedOwnerApproval
    ) -> MemoryRecord:
        """Promote a proposal only after external cryptographic verification."""
        if approval.instance_id != self.instance_id:
            raise PermissionError("owner approval is bound to a different instance")
        if approval.proposal_id != proposal_id:
            raise PermissionError("owner approval is bound to a different proposal")
        if proposal_id in self._records:
            raise ValueError("proposal has already been promoted")
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown memory proposal: {proposal_id}")
        if not self._verifier.verify(approval):
            raise PermissionError("owner approval verification failed")

        record = MemoryRecord(
            memory_id=str(uuid4()),
            instance_id=self.instance_id,
            proposal_id=proposal.proposal_id,
            kind=proposal.kind,
            summary=proposal.summary,
            provenance_refs=proposal.provenance_refs,
            sensitivity=proposal.sensitivity,
            context_tags=proposal.context_tags,
            created_at=datetime.now(UTC).isoformat(),
            owner_approval_id=approval.approval_id,
        )
        self._records[record.memory_id] = record
        return record

    def records(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._records.values())

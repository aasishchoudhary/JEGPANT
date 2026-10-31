"""Bridge owner-approved memory proposals into encrypted durable storage."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid5

from .encrypted_store import EncryptedMemoryStore
from .memory import (
    ApprovalVerifier,
    MemoryProposal,
    MemoryRecord,
    SignedOwnerApproval,
)


class MemoryPromotionService:
    """Promote an explicitly approved proposal into the encrypted memory store.

    Proposal content is supplied at promotion time. The owner approval binds
    the proposal ID and instance ID. The record ID is deterministic per
    instance/proposal, preventing accidental duplicate promotion across
    process restarts. This does not persist unapproved proposals.
    """

    def __init__(
        self,
        *,
        instance_id: str,
        verifier: ApprovalVerifier,
        store: EncryptedMemoryStore,
    ) -> None:
        try:
            UUID(instance_id)
        except ValueError as exc:
            raise ValueError("instance_id must be a UUID") from exc
        if store.instance_id != instance_id:
            raise ValueError("memory store belongs to a different instance")
        self.instance_id = instance_id
        self.verifier = verifier
        self.store = store

    def _memory_id(self, proposal_id: str) -> str:
        if not proposal_id.strip():
            raise ValueError("proposal_id must not be empty")
        return str(uuid5(UUID(self.instance_id), f"jegpant-memory:{proposal_id}"))

    def promote(
        self,
        proposal: MemoryProposal,
        approval: SignedOwnerApproval,
    ) -> MemoryRecord:
        """Verify one-time owner approval and persist the encrypted record."""
        if approval.instance_id != self.instance_id:
            raise PermissionError("approval belongs to a different cognitive instance")
        if approval.proposal_id != proposal.proposal_id:
            raise PermissionError("approval belongs to a different memory proposal")

        memory_id = self._memory_id(proposal.proposal_id)
        try:
            existing = self.store.get(memory_id)
        except KeyError:
            existing = None
        if existing is not None:
            if (
                existing.proposal_id != proposal.proposal_id
                or existing.kind != proposal.kind
                or existing.summary != proposal.summary
                or existing.provenance_refs != proposal.provenance_refs
                or existing.sensitivity != proposal.sensitivity
                or existing.context_tags != proposal.context_tags
            ):
                raise ValueError(
                    "proposal ID already identifies a different durable memory record"
                )
            return existing

        if not self.verifier.verify(approval):
            raise PermissionError("owner approval verification failed")

        record = MemoryRecord(
            memory_id=memory_id,
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
        self.store.put(record)
        return record

    def retrieve(self, proposal_id: str) -> MemoryRecord:
        """Retrieve and authenticate a memory record by proposal ID."""
        return self.store.get(self._memory_id(proposal_id))

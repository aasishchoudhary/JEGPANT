"""Owner/device-authorized promotion and retrieval for encrypted memory."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID, uuid5

from .encrypted_store import EncryptedMemoryStore
from .memory import (
    ApprovalVerifier,
    MemoryProposal,
    MemoryRecord,
    SignedOwnerApproval,
)
from .owner_auth import OwnerAuthorizationService, SignedDeviceRequest


def promotion_request_body(
    proposal: MemoryProposal, approval: SignedOwnerApproval
) -> bytes:
    """Canonical request body a device must sign for memory promotion."""
    return json.dumps(
        {
            "operation": "promote_memory",
            "proposal_id": proposal.proposal_id,
            "kind": proposal.kind.value,
            "summary": proposal.summary,
            "provenance_refs": list(proposal.provenance_refs),
            "sensitivity": proposal.sensitivity.value,
            "context_tags": list(proposal.context_tags),
            "approval_id": approval.approval_id,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def retrieval_request_body(proposal_id: str) -> bytes:
    """Canonical request body a device must sign for memory retrieval."""
    return json.dumps(
        {"operation": "retrieve_memory", "proposal_id": proposal_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class MemoryPromotionService:
    """Owner-approved persistent memory service with device access controls.

    Durable records are encrypted in SQLite. Each operation also requires a
    device-signed request checked by OwnerAuthorizationService. The caller must
    sign the exact request body returned by the helper functions in this module.
    """

    def __init__(
        self,
        *,
        instance_id: str,
        verifier: ApprovalVerifier,
        authorization_service: OwnerAuthorizationService,
        store: EncryptedMemoryStore,
    ) -> None:
        try:
            UUID(instance_id)
        except ValueError as exc:
            raise ValueError("instance_id must be a UUID") from exc
        if store.instance_id != instance_id:
            raise ValueError("memory store belongs to a different instance")
        if authorization_service.instance_id != instance_id:
            raise ValueError("authorization service belongs to a different instance")
        self.instance_id = instance_id
        self.verifier = verifier
        self.authorization_service = authorization_service
        self.store = store

    def _memory_id(self, proposal_id: str) -> str:
        if not proposal_id.strip():
            raise ValueError("proposal_id must not be empty")
        return str(uuid5(UUID(self.instance_id), f"jegpant-memory:{proposal_id}"))

    def promote(
        self,
        proposal: MemoryProposal,
        approval: SignedOwnerApproval,
        request: SignedDeviceRequest,
    ) -> MemoryRecord:
        """Verify device access and owner approval before durable promotion."""
        if approval.instance_id != self.instance_id:
            raise PermissionError("approval belongs to a different cognitive instance")
        if approval.proposal_id != proposal.proposal_id:
            raise PermissionError("approval belongs to a different memory proposal")

        request_body = promotion_request_body(proposal, approval)
        self.authorization_service.verify_request(
            request,
            body=request_body,
            required_scope="propose_memory",
        )

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
            raise ValueError(
                "memory record already exists; use retrieve() with read_memory permission"
            )

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

    def retrieve(
        self,
        proposal_id: str,
        request: SignedDeviceRequest,
    ) -> MemoryRecord:
        """Retrieve one encrypted memory after checking enrolled-device scope."""
        request_body = retrieval_request_body(proposal_id)
        self.authorization_service.verify_request(
            request,
            body=request_body,
            required_scope="read_memory",
        )
        return self.store.get(self._memory_id(proposal_id))

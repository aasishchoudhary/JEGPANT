"""Claim objects that require explicit evidence links for observations/inferences."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ClaimKind(StrEnum):
    OBSERVATION = "observation"
    INFERENCE = "inference"
    SPECULATION = "speculation"


class EvidenceRelation(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXTUAL = "contextual"


@dataclass(frozen=True, slots=True)
class ClaimEvidenceLink:
    evidence_id: str
    relation: EvidenceRelation
    explanation: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty")


@dataclass(frozen=True, slots=True)
class GroundedClaim:
    claim_id: str
    text: str
    kind: ClaimKind
    evidence: tuple[ClaimEvidenceLink, ...] = field(default_factory=tuple)
    alternatives: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)
    confidence_label: str = "unrated"

    def __post_init__(self) -> None:
        if not self.claim_id.strip() or not self.text.strip():
            raise ValueError("claim_id and text must not be empty")
        if self.kind in (ClaimKind.OBSERVATION, ClaimKind.INFERENCE) and not self.evidence:
            raise ValueError(
                "observations and inferences require at least one evidence link; "
                "use speculation when no evidence is available"
            )
        evidence_ids = [link.evidence_id for link in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("duplicate evidence links are not allowed")


def validate_claim_sources(
    claim: GroundedClaim, available_evidence_ids: set[str]
) -> None:
    """Raise when a claim cites evidence absent from the current case ledger."""
    missing = {
        link.evidence_id
        for link in claim.evidence
        if link.evidence_id not in available_evidence_ids
    }
    if missing:
        raise ValueError(f"claim references unknown evidence IDs: {sorted(missing)}")

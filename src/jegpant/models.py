"""Typed data structures for evidence-grounded reasoning.

These objects intentionally distinguish observations from interpretations.
They do not infer intent, deception, guilt, diagnosis, or personality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidencePolarity(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    NEUTRAL = "neutral"
    UNASSESSED = "unassessed"


class EvidenceStrength(StrEnum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    UNRATED = "unrated"


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    evidence_id: str
    polarity: EvidencePolarity
    strength: EvidenceStrength = EvidenceStrength.UNRATED
    independence_group: str | None = None
    source_reliability: str = "unassessed"
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty")
        if self.polarity is EvidencePolarity.UNASSESSED and self.strength is not EvidenceStrength.UNRATED:
            raise ValueError("unassessed evidence must have unrated strength")


@dataclass(frozen=True, slots=True)
class Hypothesis:
    hypothesis_id: str
    statement: str
    assessments: tuple[EvidenceAssessment, ...] = field(default_factory=tuple)
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    discriminating_questions: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.hypothesis_id.strip():
            raise ValueError("hypothesis_id must not be empty")
        if not self.statement.strip():
            raise ValueError("hypothesis statement must not be empty")
        ids = [item.evidence_id for item in self.assessments]
        if len(ids) != len(set(ids)):
            raise ValueError("an evidence item may be assessed only once per hypothesis")


@dataclass(frozen=True, slots=True)
class HypothesisSummary:
    hypothesis_id: str
    statement: str
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    neutral_evidence: tuple[str, ...]
    unassessed_evidence: tuple[str, ...]
    evidence_balance: str
    caveat: str = (
        "Evidence counts are not probabilities. Independence, source quality, "
        "relevance, selection bias, and missing evidence require separate review."
    )

"""Analysis of Competing Hypotheses (ACH) with contradiction-focused comparison.

This is a structured analytic aid, not a probability model. Judgement quality,
source independence, and evidence relevance still require analyst review.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ACHRating(StrEnum):
    STRONGLY_INCONSISTENT = "strongly_inconsistent"
    INCONSISTENT = "inconsistent"
    NEUTRAL = "neutral"
    CONSISTENT = "consistent"
    STRONGLY_CONSISTENT = "strongly_consistent"
    NOT_APPLICABLE = "not_applicable"
    UNASSESSED = "unassessed"


_CONTRADICTION_SEVERITY = {
    ACHRating.STRONGLY_INCONSISTENT: 2,
    ACHRating.INCONSISTENT: 1,
}


@dataclass(frozen=True, slots=True)
class ACHEvidence:
    evidence_id: str
    source_ref: str
    independence_group: str
    quality_level: int
    description: str

    def __post_init__(self) -> None:
        for name in ("evidence_id", "source_ref", "independence_group", "description"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        if not 1 <= self.quality_level <= 3:
            raise ValueError("quality_level must be between 1 and 3")


@dataclass(frozen=True, slots=True)
class ACHHypothesis:
    hypothesis_id: str
    statement: str

    def __post_init__(self) -> None:
        if not self.hypothesis_id.strip() or not self.statement.strip():
            raise ValueError("hypothesis ID and statement must not be empty")


@dataclass(frozen=True, slots=True)
class ACHJudgement:
    hypothesis_id: str
    evidence_id: str
    rating: ACHRating
    diagnosticity: int
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.hypothesis_id.strip() or not self.evidence_id.strip():
            raise ValueError("hypothesis_id and evidence_id must not be empty")
        if not 1 <= self.diagnosticity <= 3:
            raise ValueError("diagnosticity must be between 1 and 3")


@dataclass(frozen=True, slots=True)
class ACHHypothesisResult:
    hypothesis_id: str
    statement: str
    contradiction_score: int
    strong_contradictions: tuple[str, ...]
    contradictions: tuple[str, ...]
    consistent_evidence: tuple[str, ...]
    neutral_evidence: tuple[str, ...]
    not_applicable_evidence: tuple[str, ...]
    unassessed_evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ACHComparison:
    results: tuple[ACHHypothesisResult, ...]
    warning: str = (
        "The contradiction score is an ordinal triage aid, not a probability, "
        "truth score, or automatic winner. Ratings, source quality, and "
        "independence groups require review."
    )


def compare_competing_hypotheses(
    *,
    hypotheses: tuple[ACHHypothesis, ...],
    evidence: tuple[ACHEvidence, ...],
    judgements: tuple[ACHJudgement, ...],
) -> ACHComparison:
    """Compare hypotheses by diagnostic contradictions, without probability claims.

    For each hypothesis and source-independence group, only the strongest
    contradictory assessment contributes to the score. This avoids treating
    repeated or derivative reports as independent corroboration.
    """
    if not hypotheses:
        raise ValueError("at least one hypothesis is required")

    hypothesis_map = {item.hypothesis_id: item for item in hypotheses}
    evidence_map = {item.evidence_id: item for item in evidence}
    if len(hypothesis_map) != len(hypotheses):
        raise ValueError("hypothesis IDs must be unique")
    if len(evidence_map) != len(evidence):
        raise ValueError("evidence IDs must be unique")

    judgement_map: dict[tuple[str, str], ACHJudgement] = {}
    for judgement in judgements:
        if judgement.hypothesis_id not in hypothesis_map:
            raise ValueError(
                f"unknown hypothesis ID: {judgement.hypothesis_id}"
            )
        if judgement.evidence_id not in evidence_map:
            raise ValueError(f"unknown evidence ID: {judgement.evidence_id}")
        pair = (judgement.hypothesis_id, judgement.evidence_id)
        if pair in judgement_map:
            raise ValueError("duplicate judgement for hypothesis/evidence pair")
        judgement_map[pair] = judgement

    built: list[tuple[int, ACHHypothesisResult]] = []
    for original_index, hypothesis in enumerate(hypotheses):
        strong: list[str] = []
        inconsistent: list[str] = []
        consistent: list[str] = []
        neutral: list[str] = []
        not_applicable: list[str] = []
        unassessed: list[str] = []
        group_scores: dict[str, int] = {}

        for item in evidence:
            judgement = judgement_map.get((hypothesis.hypothesis_id, item.evidence_id))
            if judgement is None or judgement.rating is ACHRating.UNASSESSED:
                unassessed.append(item.evidence_id)
                continue

            if judgement.rating in _CONTRADICTION_SEVERITY:
                inconsistent.append(item.evidence_id)
                if judgement.rating is ACHRating.STRONGLY_INCONSISTENT:
                    strong.append(item.evidence_id)
                contribution = (
                    _CONTRADICTION_SEVERITY[judgement.rating]
                    * judgement.diagnosticity
                    * item.quality_level
                )
                prior = group_scores.get(item.independence_group, 0)
                group_scores[item.independence_group] = max(prior, contribution)
            elif judgement.rating in {
                ACHRating.CONSISTENT,
                ACHRating.STRONGLY_CONSISTENT,
            }:
                consistent.append(item.evidence_id)
            elif judgement.rating is ACHRating.NEUTRAL:
                neutral.append(item.evidence_id)
            else:
                not_applicable.append(item.evidence_id)

        result = ACHHypothesisResult(
            hypothesis_id=hypothesis.hypothesis_id,
            statement=hypothesis.statement,
            contradiction_score=sum(group_scores.values()),
            strong_contradictions=tuple(strong),
            contradictions=tuple(inconsistent),
            consistent_evidence=tuple(consistent),
            neutral_evidence=tuple(neutral),
            not_applicable_evidence=tuple(not_applicable),
            unassessed_evidence=tuple(unassessed),
        )
        built.append((original_index, result))

    built.sort(key=lambda item: (item[1].contradiction_score, item[0]))
    return ACHComparison(results=tuple(item[1] for item in built))

"""Hypothesis comparison that preserves uncertainty and avoids false precision."""

from __future__ import annotations

from .models import (
    EvidencePolarity,
    Hypothesis,
    HypothesisSummary,
)


def summarize_hypothesis(hypothesis: Hypothesis) -> HypothesisSummary:
    """Summarise evidence direction without selecting a winner or inventing odds."""
    supporting: list[str] = []
    contradicting: list[str] = []
    neutral: list[str] = []
    unassessed: list[str] = []

    for assessment in hypothesis.assessments:
        if assessment.polarity is EvidencePolarity.SUPPORTS:
            supporting.append(assessment.evidence_id)
        elif assessment.polarity is EvidencePolarity.CONTRADICTS:
            contradicting.append(assessment.evidence_id)
        elif assessment.polarity is EvidencePolarity.NEUTRAL:
            neutral.append(assessment.evidence_id)
        else:
            unassessed.append(assessment.evidence_id)

    if not supporting and not contradicting:
        balance = "unresolved"
    elif supporting and contradicting:
        balance = "contested"
    elif supporting:
        balance = "support recorded; counterevidence may be missing"
    else:
        balance = "contradictory evidence recorded; further review required"

    return HypothesisSummary(
        hypothesis_id=hypothesis.hypothesis_id,
        statement=hypothesis.statement,
        supporting_evidence=tuple(supporting),
        contradicting_evidence=tuple(contradicting),
        neutral_evidence=tuple(neutral),
        unassessed_evidence=tuple(unassessed),
        evidence_balance=balance,
    )


def compare_hypotheses(hypotheses: tuple[Hypothesis, ...]) -> tuple[HypothesisSummary, ...]:
    """Summarise alternatives in input order; deliberately does not rank them."""
    ids = [hypothesis.hypothesis_id for hypothesis in hypotheses]
    if len(ids) != len(set(ids)):
        raise ValueError("hypothesis IDs must be unique within a comparison")
    return tuple(summarize_hypothesis(item) for item in hypotheses)

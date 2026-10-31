"""Global-workspace candidate selection using a Pareto frontier.

The frontier allocates attention among specialist outputs. It is not a truth,
credibility, or confidence ranking. Input metrics require their own calibration.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


def _unit_interval(name: str, value: float) -> None:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be finite and between 0 and 1")


@dataclass(frozen=True, slots=True)
class PriorityVector:
    goal_relevance: float
    novelty: float
    uncertainty: float
    expected_information_gain: float
    source_quality: float
    estimated_cost: float
    risk: float

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _unit_interval(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class WorkspaceCandidate:
    candidate_id: str
    specialist: str
    method_version: str
    rationale: str
    evidence_refs: tuple[str, ...]
    priority: PriorityVector

    def __post_init__(self) -> None:
        for name in ("candidate_id", "specialist", "method_version", "rationale"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")


def _dominates(left: WorkspaceCandidate, right: WorkspaceCandidate) -> bool:
    """Return true when left is no worse on every objective and better on one."""
    a, b = left.priority, right.priority
    benefit_a = (
        a.goal_relevance,
        a.novelty,
        a.uncertainty,
        a.expected_information_gain,
        a.source_quality,
    )
    benefit_b = (
        b.goal_relevance,
        b.novelty,
        b.uncertainty,
        b.expected_information_gain,
        b.source_quality,
    )
    cost_a = (a.estimated_cost, a.risk)
    cost_b = (b.estimated_cost, b.risk)

    no_worse = all(x >= y for x, y in zip(benefit_a, benefit_b)) and all(
        x <= y for x, y in zip(cost_a, cost_b)
    )
    strictly_better = any(x > y for x, y in zip(benefit_a, benefit_b)) or any(
        x < y for x, y in zip(cost_a, cost_b)
    )
    return no_worse and strictly_better


def pareto_frontier(
    candidates: tuple[WorkspaceCandidate, ...],
) -> tuple[WorkspaceCandidate, ...]:
    """Return all non-dominated candidates in original order.

    Multiple candidates may remain. A downstream policy or owner decision
    chooses among them; this function does not hide trade-offs in one score.
    """
    ids = [candidate.candidate_id for candidate in candidates]
    if len(ids) != len(set(ids)):
        raise ValueError("workspace candidate IDs must be unique")

    return tuple(
        candidate
        for candidate in candidates
        if not any(
            other.candidate_id != candidate.candidate_id
            and _dominates(other, candidate)
            for other in candidates
        )
    )

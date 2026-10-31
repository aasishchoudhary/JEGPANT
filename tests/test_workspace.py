import pytest

from jegpant.workspace import PriorityVector, WorkspaceCandidate, pareto_frontier


def candidate(candidate_id, **overrides):
    values = {
        "goal_relevance": 0.8,
        "novelty": 0.6,
        "uncertainty": 0.5,
        "expected_information_gain": 0.7,
        "source_quality": 0.8,
        "estimated_cost": 0.4,
        "risk": 0.2,
    }
    values.update(overrides)
    return WorkspaceCandidate(
        candidate_id,
        "test-specialist",
        "v1",
        "candidate rationale",
        (),
        PriorityVector(**values),
    )


def test_dominated_candidate_is_removed_without_weighted_score():
    best = candidate("best")
    dominated = candidate(
        "dominated",
        goal_relevance=0.6,
        novelty=0.5,
        expected_information_gain=0.5,
        source_quality=0.7,
        estimated_cost=0.6,
        risk=0.4,
    )
    assert pareto_frontier((best, dominated)) == (best,)


def test_incomparable_candidates_both_remain():
    quality = candidate("quality", source_quality=1.0, estimated_cost=0.8)
    cheap = candidate("cheap", source_quality=0.6, estimated_cost=0.1)
    assert set(pareto_frontier((quality, cheap))) == {quality, cheap}


def test_priority_values_are_validated():
    with pytest.raises(ValueError):
        PriorityVector(1.2, 0, 0, 0, 0, 0, 0)

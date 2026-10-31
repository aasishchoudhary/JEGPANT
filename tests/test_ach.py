import pytest

from jegpant.ach import (
    ACHEvidence,
    ACHHypothesis,
    ACHJudgement,
    ACHRating,
    compare_competing_hypotheses,
)


def hypotheses():
    return (
        ACHHypothesis("h1", "A person opened the door."),
        ACHHypothesis("h2", "The door opened due to a mechanical fault."),
    )


def evidence():
    return (
        ACHEvidence("e1", "camera-a", "camera-a", 3, "Door handle visibly turns."),
        ACHEvidence("e2", "camera-b", "camera-a", 2, "Second view shows movement."),
        ACHEvidence("e3", "maintenance-log", "maintenance-log", 3, "Door closer was faulty."),
    )


def test_contradiction_focused_ach_comparison():
    result = compare_competing_hypotheses(
        hypotheses=hypotheses(),
        evidence=evidence(),
        judgements=(
            ACHJudgement("h1", "e1", ACHRating.CONSISTENT, 3),
            ACHJudgement("h1", "e2", ACHRating.NEUTRAL, 1),
            ACHJudgement("h1", "e3", ACHRating.STRONGLY_INCONSISTENT, 3),
            ACHJudgement("h2", "e1", ACHRating.INCONSISTENT, 2),
            ACHJudgement("h2", "e2", ACHRating.NEUTRAL, 1),
            ACHJudgement("h2", "e3", ACHRating.CONSISTENT, 2),
        ),
    )

    by_id = {item.hypothesis_id: item for item in result.results}
    assert by_id["h1"].contradiction_score == 18
    assert by_id["h2"].contradiction_score == 6
    assert by_id["h1"].strong_contradictions == ("e3",)
    assert [item.hypothesis_id for item in result.results] == ["h2", "h1"]
    assert "not a probability" in result.warning


def test_correlated_sources_are_not_double_counted():
    result = compare_competing_hypotheses(
        hypotheses=(hypotheses()[0],),
        evidence=evidence()[:2],
        judgements=(
            ACHJudgement("h1", "e1", ACHRating.STRONGLY_INCONSISTENT, 3),
            ACHJudgement("h1", "e2", ACHRating.STRONGLY_INCONSISTENT, 3),
        ),
    )
    # Both reports share an independence group; only the strongest contributes.
    assert result.results[0].contradiction_score == 18
    assert set(result.results[0].contradictions) == {"e1", "e2"}


def test_unassessed_and_missing_evidence_remain_visible():
    result = compare_competing_hypotheses(
        hypotheses=(hypotheses()[0],),
        evidence=evidence(),
        judgements=(
            ACHJudgement("h1", "e1", ACHRating.UNASSESSED, 1),
            ACHJudgement("h1", "e2", ACHRating.NEUTRAL, 1),
        ),
    )
    item = result.results[0]
    assert item.unassessed_evidence == ("e1", "e3")
    assert item.neutral_evidence == ("e2",)


def test_unknown_hypothesis_and_evidence_refs_are_rejected():
    with pytest.raises(ValueError, match="unknown hypothesis"):
        compare_competing_hypotheses(
            hypotheses=hypotheses(),
            evidence=evidence(),
            judgements=(ACHJudgement("h3", "e1", ACHRating.NEUTRAL, 1),),
        )
    with pytest.raises(ValueError, match="unknown evidence"):
        compare_competing_hypotheses(
            hypotheses=hypotheses(),
            evidence=evidence(),
            judgements=(ACHJudgement("h1", "e99", ACHRating.NEUTRAL, 1),),
        )


def test_duplicate_pair_judgements_are_rejected():
    with pytest.raises(ValueError, match="duplicate judgement"):
        compare_competing_hypotheses(
            hypotheses=hypotheses(),
            evidence=evidence(),
            judgements=(
                ACHJudgement("h1", "e1", ACHRating.NEUTRAL, 1),
                ACHJudgement("h1", "e1", ACHRating.CONSISTENT, 1),
            ),
        )


def test_identical_scores_preserve_input_order():
    result = compare_competing_hypotheses(
        hypotheses=hypotheses(),
        evidence=evidence(),
        judgements=(),
    )
    assert [item.hypothesis_id for item in result.results] == ["h1", "h2"]

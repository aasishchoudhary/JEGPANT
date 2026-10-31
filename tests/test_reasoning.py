import pytest

from jegpant.models import EvidenceAssessment, EvidencePolarity, Hypothesis
from jegpant.reasoning import compare_hypotheses, summarize_hypothesis


def test_conflicting_evidence_remains_contested():
    hypothesis = Hypothesis(
        hypothesis_id="h1",
        statement="The object was moved intentionally.",
        assessments=(
            EvidenceAssessment("e1", EvidencePolarity.SUPPORTS),
            EvidenceAssessment("e2", EvidencePolarity.CONTRADICTS),
        ),
    )

    summary = summarize_hypothesis(hypothesis)
    assert summary.evidence_balance == "contested"
    assert summary.supporting_evidence == ("e1",)
    assert summary.contradicting_evidence == ("e2",)


def test_support_without_counterevidence_is_not_called_proven():
    hypothesis = Hypothesis(
        hypothesis_id="h2",
        statement="The light was switched off.",
        assessments=(EvidenceAssessment("e1", EvidencePolarity.SUPPORTS),),
    )

    summary = summarize_hypothesis(hypothesis)
    assert summary.evidence_balance == "support recorded; counterevidence may be missing"
    assert "not probabilities" in summary.caveat


def test_comparison_does_not_rank_hypotheses():
    first = Hypothesis("h1", "Explanation A")
    second = Hypothesis("h2", "Explanation B")

    summaries = compare_hypotheses((first, second))
    assert [item.hypothesis_id for item in summaries] == ["h1", "h2"]
    assert all(item.evidence_balance == "unresolved" for item in summaries)


def test_duplicate_hypothesis_ids_are_rejected():
    first = Hypothesis("same", "Explanation A")
    second = Hypothesis("same", "Explanation B")
    with pytest.raises(ValueError):
        compare_hypotheses((first, second))

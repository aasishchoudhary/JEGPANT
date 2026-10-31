import json

import pytest

from jegpant.ach import ACHEvidence
from jegpant.ach_auditor import ACHAuditor, ACHReviewError
from jegpant.inference import ChatResponse
from jegpant.models import Hypothesis


class QueueClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.messages = []

    def complete(self, messages, *, temperature=0.0, max_tokens=2048):
        self.messages.append((messages, temperature, max_tokens))
        if not self.responses:
            raise AssertionError("unexpected extra model call")
        return ChatResponse(json.dumps(self.responses.pop(0)), "test-model")


def valid_matrix():
    return {
        "judgements": [
            {
                "hypothesis_id": "h1",
                "evidence_id": "e1",
                "rating": "strongly_inconsistent",
                "diagnosticity": 3,
                "rationale": "The visible timing conflicts with the proposed sequence.",
            },
            {
                "hypothesis_id": "h2",
                "evidence_id": "e1",
                "rating": "consistent",
                "diagnosticity": 2,
                "rationale": "The observation is compatible with this alternative.",
            },
        ],
        "review_notes": ["A second camera angle would help resolve timing."],
    }


def test_ach_auditor_validates_complete_matrix_and_calls_comparator():
    client = QueueClient([valid_matrix()])
    auditor = ACHAuditor(client)
    hypotheses = (
        Hypothesis("h1", "A person opened the door."),
        Hypothesis("h2", "A mechanical fault moved the door."),
    )
    evidence = (
        ACHEvidence("e1", "cam-1", "cam-1", 3, "Door visibly moved at 00:01:10."),
    )

    result = auditor.review(hypotheses=hypotheses, evidence=evidence)

    assert len(result.comparison.results) == 2
    assert result.comparison.results[0].hypothesis_id == "h2"
    assert result.comparison.results[1].hypothesis_id == "h1"
    assert result.comparison.results[1].strong_contradictions == ("e1",)
    assert result.model == "test-model"
    assert "not a probability" in result.comparison.warning
    assert "untrusted" in client.messages[0][0][0].content.lower()


def test_ach_auditor_rejects_missing_matrix_cells():
    payload = valid_matrix()
    payload["judgements"] = payload["judgements"][:1]
    auditor = ACHAuditor(QueueClient([payload]))
    hypotheses = (Hypothesis("h1", "A"), Hypothesis("h2", "B"))
    evidence = (ACHEvidence("e1", "s1", "s1", 2, "An event."),)
    with pytest.raises(ACHReviewError, match="matrix incomplete"):
        auditor.review(hypotheses=hypotheses, evidence=evidence)


def test_ach_auditor_rejects_duplicate_matrix_cells():
    payload = valid_matrix()
    payload["judgements"][1]["hypothesis_id"] = "h1"
    auditor = ACHAuditor(QueueClient([payload]))
    hypotheses = (Hypothesis("h1", "A"), Hypothesis("h2", "B"))
    from jegpant.ach import ACHEvidence

    evidence = (ACHEvidence("e1", "s1", "s1", 2, "An event."),)
    with pytest.raises(ACHReviewError, match="duplicate"):
        auditor.review(hypotheses=hypotheses, evidence=evidence)


def test_ach_auditor_rejects_unknown_evidence_reference():
    payload = valid_matrix()
    payload["judgements"][0]["evidence_id"] = "invented"
    auditor = ACHAuditor(QueueClient([payload]))
    hypotheses = (Hypothesis("h1", "A"), Hypothesis("h2", "B"))
    from jegpant.ach import ACHEvidence

    evidence = (ACHEvidence("e1", "s1", "s1", 2, "An event."),)
    with pytest.raises(ACHReviewError, match="unknown evidence"):
        auditor.review(hypotheses=hypotheses, evidence=evidence)


def test_ach_auditor_rejects_invalid_rating_and_missing_rationale():
    payload = valid_matrix()
    payload["judgements"][0]["rating"] = "almost_true"
    auditor = ACHAuditor(QueueClient([payload]))
    hypotheses = (Hypothesis("h1", "A"), Hypothesis("h2", "B"))
    from jegpant.ach import ACHEvidence

    evidence = (ACHEvidence("e1", "s1", "s1", 2, "An event."),)
    with pytest.raises(ACHReviewError, match="unsupported rating"):
        auditor.review(hypotheses=hypotheses, evidence=evidence)

    payload = valid_matrix()
    payload["judgements"][0]["rationale"] = ""
    with pytest.raises(ACHReviewError, match="requires a rationale"):
        ACHAuditor(QueueClient([payload])).review(
            hypotheses=hypotheses, evidence=evidence
        )


def test_ach_auditor_enforces_matrix_size_before_model_call():
    client = QueueClient([])
    auditor = ACHAuditor(client, max_matrix_cells=1)
    hypotheses = (Hypothesis("h1", "A"), Hypothesis("h2", "B"))
    from jegpant.ach import ACHEvidence

    evidence = (ACHEvidence("e1", "s1", "s1", 2, "An event."),)
    with pytest.raises(ValueError, match="limit"):
        auditor.review(hypotheses=hypotheses, evidence=evidence)
    assert client.messages == []

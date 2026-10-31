import json

import pytest

from jegpant.hypothesis_generator import (
    HypothesisGenerationError,
    HypothesisGenerator,
)
from jegpant.inference import ChatResponse
from jegpant.models import EvidencePolarity


class FakeClient:
    def __init__(self, payload):
        self.payload = payload
        self.last_messages = None

    def complete(self, messages, *, temperature=0.0, max_tokens=2048):
        self.last_messages = messages
        return ChatResponse(json.dumps(self.payload), "fake-model")


def valid_payload():
    return {
        "hypotheses": [
            {
                "id": "h1",
                "statement": "The door was opened by a person.",
                "supporting_evidence_ids": ["e1"],
                "contradicting_evidence_ids": [],
                "assumptions": ["The timestamp is accurate."],
                "discriminating_questions": ["Is the door visible immediately before the event?"],
            },
            {
                "id": "h2",
                "statement": "The door moved due to airflow or mechanical failure.",
                "supporting_evidence_ids": [],
                "contradicting_evidence_ids": ["e1"],
                "assumptions": [],
                "discriminating_questions": ["Is there evidence of a mechanical fault?"],
            },
        ],
        "unresolved_questions": ["Is there another camera angle?"],
    }


def test_generator_validates_ids_and_preserves_alternatives():
    client = FakeClient(valid_payload())
    generator = HypothesisGenerator(client)
    result = generator.generate(
        goal="Explain why the door moved.",
        evidence=(
            {"record_id": "e1", "observation": "Door movement visible."},
        ),
    )

    assert len(result.hypotheses) == 2
    assert result.hypotheses[0].assessments[0].polarity is EvidencePolarity.SUPPORTS
    assert result.hypotheses[1].assessments[0].polarity is EvidencePolarity.CONTRADICTS
    assert result.unresolved_questions == ("Is there another camera angle?",)
    assert "Do not invent evidence" in client.last_messages[0].content


def test_generator_rejects_hallucinated_evidence_ids():
    payload = valid_payload()
    payload["hypotheses"][0]["supporting_evidence_ids"] = ["e999"]
    generator = HypothesisGenerator(FakeClient(payload))

    with pytest.raises(HypothesisGenerationError, match="invented unknown"):
        generator.generate(
            goal="Explain an event.",
            evidence=({"record_id": "e1", "observation": "An event."},),
        )


def test_generator_rejects_invalid_json():
    class InvalidClient:
        def complete(self, *args, **kwargs):
            return ChatResponse("not JSON", "fake-model")

    generator = HypothesisGenerator(InvalidClient())
    with pytest.raises(HypothesisGenerationError):
        generator.generate(goal="Explain an event.", evidence=())


def test_generator_rejects_duplicate_support_and_contradiction():
    payload = valid_payload()
    payload["hypotheses"][0]["contradicting_evidence_ids"] = ["e1"]
    generator = HypothesisGenerator(FakeClient(payload))
    with pytest.raises(HypothesisGenerationError, match="both supporting and contradicting"):
        generator.generate(
            goal="Explain an event.",
            evidence=({"record_id": "e1", "observation": "An event."},),
        )

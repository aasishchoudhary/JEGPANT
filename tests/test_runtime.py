import json

import pytest

from jegpant.inference import ChatResponse
from jegpant.runtime import CognitiveRuntime, InvestigationEvidence


class QueueClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.messages = []

    def complete(self, messages, *, temperature=0.0, max_tokens=2048):
        self.messages.append((messages, temperature, max_tokens))
        if not self.responses:
            raise AssertionError("unexpected extra model call")
        return ChatResponse(json.dumps(self.responses.pop(0)), "test-model")


def hypotheses_response():
    return {
        "hypotheses": [
            {
                "id": "h1",
                "statement": "A person opened the door.",
                "supporting_evidence_ids": ["e1"],
                "contradicting_evidence_ids": [],
                "assumptions": ["The timestamp is accurate."],
                "discriminating_questions": ["Is the handle visible?"],
            },
            {
                "id": "h2",
                "statement": "The door moved due to a mechanical issue.",
                "supporting_evidence_ids": [],
                "contradicting_evidence_ids": ["e1"],
                "assumptions": ["A mechanical fault was present."],
                "discriminating_questions": ["Is a fault documented?"],
            },
        ],
        "unresolved_questions": ["Is another camera angle available?"],
    }


def ach_response():
    return {
        "judgements": [
            {
                "hypothesis_id": "h1",
                "evidence_id": "e1",
                "rating": "consistent",
                "diagnosticity": 2,
                "rationale": "The visible movement is compatible with a person opening it.",
            },
            {
                "hypothesis_id": "h2",
                "evidence_id": "e1",
                "rating": "neutral",
                "diagnosticity": 1,
                "rationale": "The clip does not reveal whether a mechanical fault existed.",
            },
            {
                "hypothesis_id": "h1",
                "evidence_id": "e2",
                "rating": "strongly_inconsistent",
                "diagnosticity": 3,
                "rationale": "The independent maintenance record documents a failed closer.",
            },
            {
                "hypothesis_id": "h2",
                "evidence_id": "e2",
                "rating": "strongly_consistent",
                "diagnosticity": 3,
                "rationale": "The maintenance record directly supports the mechanical alternative.",
            },
        ],
        "review_notes": ["Obtain original maintenance document for verification."],
    }


def sample_evidence():
    return (
        InvestigationEvidence(
            "e1",
            "video://asset-1",
            "camera-1",
            "Door moves inward at timestamp 00:01:10.",
            quality_level=3,
            source_start_ms=70000,
            source_end_ms=72000,
        ),
        InvestigationEvidence(
            "e2",
            "document://maintenance-1",
            "maintenance-system",
            "Maintenance entry says door closer failed on the same date.",
            quality_level=3,
        ),
    )


def test_runtime_executes_full_cognitive_cycle():
    client = QueueClient([hypotheses_response(), ach_response()])
    runtime = CognitiveRuntime(client)
    result = runtime.investigate(
        goal="Explain why the door moved.",
        evidence=sample_evidence(),
    )

    assert len(client.messages) == 2
    assert len(result.hypotheses) == 2
    assert len(result.ach_results) == 2
    assert result.ach_results[0].hypothesis_id == "h2"
    assert result.human_review_required is True
    assert result.status == "analysis_complete_pending_review"
    assert result.model_ids == ("test-model",)
    assert result.evidence_manifest_sha256
    assert result.trace[-1].phase == "closed"
    assert [event.phase for event in result.trace] == [
        "orient",
        "perceive",
        "retrieve",
        "hypothesize",
        "hypothesize",
        "challenge",
        "challenge",
        "synthesize",
        "synthesize",
        "reflect",
        "reflect",
        "closed",
    ]


def test_runtime_report_is_json_serialisable_and_preserves_limits():
    client = QueueClient([hypotheses_response(), ach_response()])
    result = CognitiveRuntime(client).investigate(
        goal="Explain the event.",
        evidence=sample_evidence(),
    )
    report = result.as_dict()

    encoded = json.dumps(report)
    assert "analysis_complete_pending_review" in encoded
    assert "not probabilities" not in encoded.lower()
    assert "not a probability" in report["limitations"][1] or report["ach_results"]
    assert report["human_review_required"] is True
    assert len(report["ach_results"]) == 2


def test_runtime_rejects_duplicate_evidence_ids_before_inference():
    client = QueueClient([])
    evidence = sample_evidence()
    duplicate = (evidence[0], evidence[0])
    with pytest.raises(ValueError, match="unique"):
        CognitiveRuntime(client).investigate(
            goal="Explain the event.",
            evidence=duplicate,
        )
    assert client.messages == []


def test_runtime_rejects_empty_or_oversized_evidence():
    client = QueueClient([])
    runtime = CognitiveRuntime(client, max_evidence=1)

    with pytest.raises(ValueError, match="at least one"):
        runtime.investigate(goal="Explain.", evidence=())

    with pytest.raises(ValueError, match="exceeds"):
        runtime.investigate(goal="Explain.", evidence=sample_evidence())
    assert client.messages == []


def test_runtime_manifest_digest_is_independent_of_input_order():
    runtime = CognitiveRuntime(QueueClient([]))
    first, second = sample_evidence()
    assert runtime._manifest_digest((first, second)) == runtime._manifest_digest(
        (second, first)
    )


def test_runtime_rejects_bad_source_time_ranges():
    with pytest.raises(ValueError, match="source_end_ms"):
        InvestigationEvidence(
            "e3",
            "video://asset",
            "camera",
            "An event.",
            source_start_ms=900,
            source_end_ms=100,
        )

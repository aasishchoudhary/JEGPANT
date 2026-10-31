"""Integrated cognitive loop: generate, challenge, compare, and report hypotheses."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from .ach import ACHEvidence, ACHHypothesisResult
from .ach_auditor import ACHAuditor
from .cycle import CyclePhase, CycleState, advance_cycle
from .hypothesis_generator import HypothesisGenerator
from .inference import ChatCompletionClient
from .models import Hypothesis


@dataclass(frozen=True, slots=True)
class InvestigationEvidence:
    """An owner-supplied observation with explicit provenance and source quality."""

    record_id: str
    source_ref: str
    independence_group: str
    observation: str
    quality_level: int = 2
    source_start_ms: int | None = None
    source_end_ms: int | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("record_id", "source_ref", "independence_group", "observation"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        if not 1 <= self.quality_level <= 3:
            raise ValueError("quality_level must be between 1 and 3")
        if self.source_start_ms is not None and self.source_start_ms < 0:
            raise ValueError("source_start_ms must be non-negative")
        if self.source_end_ms is not None and self.source_end_ms < 0:
            raise ValueError("source_end_ms must be non-negative")
        if (
            self.source_start_ms is not None
            and self.source_end_ms is not None
            and self.source_end_ms < self.source_start_ms
        ):
            raise ValueError("source_end_ms must be >= source_start_ms")


@dataclass(frozen=True, slots=True)
class CognitiveTraceEvent:
    phase: str
    occurred_at: str
    operation: str
    detail: str


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    investigation_id: str
    cycle_id: str
    goal: str
    evidence_manifest_sha256: str
    hypotheses: tuple[Hypothesis, ...]
    ach_results: tuple[ACHHypothesisResult, ...]
    ach_warning: str
    unresolved_questions: tuple[str, ...]
    review_notes: tuple[str, ...]
    model_ids: tuple[str, ...]
    trace: tuple[CognitiveTraceEvent, ...]
    human_review_required: bool = True
    status: str = "analysis_complete_pending_review"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable report with explicit review status."""
        return {
            "investigation_id": self.investigation_id,
            "cycle_id": self.cycle_id,
            "goal": self.goal,
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
            "hypotheses": [
                {
                    "hypothesis_id": item.hypothesis_id,
                    "statement": item.statement,
                    "assumptions": list(item.assumptions),
                    "discriminating_questions": list(item.discriminating_questions),
                }
                for item in self.hypotheses
            ],
            "ach_warning": self.ach_warning,
            "ach_results": [
                {
                    "hypothesis_id": item.hypothesis_id,
                    "statement": item.statement,
                    "contradiction_score": item.contradiction_score,
                    "strong_contradictions": list(item.strong_contradictions),
                    "contradictions": list(item.contradictions),
                    "consistent_evidence": list(item.consistent_evidence),
                    "neutral_evidence": list(item.neutral_evidence),
                    "not_applicable_evidence": list(item.not_applicable_evidence),
                    "unassessed_evidence": list(item.unassessed_evidence),
                }
                for item in self.ach_results
            ],
            "unresolved_questions": list(self.unresolved_questions),
            "review_notes": list(self.review_notes),
            "model_ids": list(self.model_ids),
            "trace": [asdict(event) for event in self.trace],
            "human_review_required": self.human_review_required,
            "status": self.status,
            "created_at": self.created_at,
            "limitations": [
                "Hypothesis generation and ACH ratings are model-proposed analytic outputs.",
                "Contradiction scores are ordinal triage values, not probabilities.",
                "Evidence quality and source-independence labels require review.",
                "This result is not a finding of intent, deception, guilt, diagnosis, or identity.",
            ],
        }


class CognitiveRuntime:
    """Run a reviewable investigation cycle over supplied observations.

    The runtime wires existing specialised components together. It does not
    itself decode video, create observations, or automatically promote memory.
    Those capabilities remain separate input and owner-approval boundaries.
    """

    def __init__(
        self,
        client: ChatCompletionClient,
        *,
        max_hypotheses: int = 6,
        max_evidence: int = 20,
        max_matrix_cells: int = 80,
    ) -> None:
        if max_evidence <= 0:
            raise ValueError("max_evidence must be positive")
        self.client = client
        self.max_evidence = max_evidence
        self.hypothesis_generator = HypothesisGenerator(
            client, max_hypotheses=max_hypotheses
        )
        self.ach_auditor = ACHAuditor(
            client, max_matrix_cells=max_matrix_cells
        )

    @staticmethod
    def _manifest_digest(evidence: tuple[InvestigationEvidence, ...]) -> str:
        manifest = [
            {
                "record_id": item.record_id,
                "source_ref": item.source_ref,
                "independence_group": item.independence_group,
                "observation": item.observation,
                "quality_level": item.quality_level,
                "source_start_ms": item.source_start_ms,
                "source_end_ms": item.source_end_ms,
                "limitations": list(item.limitations),
            }
            for item in sorted(evidence, key=lambda row: row.record_id)
        ]
        encoded = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def investigate(
        self,
        *,
        goal: str,
        evidence: tuple[InvestigationEvidence, ...],
    ) -> InvestigationResult:
        if not isinstance(goal, str) or not goal.strip():
            raise ValueError("goal must be a non-empty string")
        if not evidence:
            raise ValueError("at least one evidence observation is required")
        if len(evidence) > self.max_evidence:
            raise ValueError(
                f"evidence count {len(evidence)} exceeds limit {self.max_evidence}"
            )
        record_ids = [item.record_id for item in evidence]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("evidence record IDs must be unique")

        cycle = CycleState(goal=goal)
        trace: list[CognitiveTraceEvent] = []

        def record(operation: str, detail: str) -> None:
            trace.append(
                CognitiveTraceEvent(
                    phase=cycle.phase.value,
                    occurred_at=datetime.now(UTC).isoformat(),
                    operation=operation,
                    detail=detail,
                )
            )

        def move(next_phase: CyclePhase, operation: str, detail: str) -> None:
            nonlocal cycle
            cycle = advance_cycle(cycle, next_phase)
            record(operation, detail)

        record("orient", "Goal and constraints captured; no conclusion selected.")
        move(
            CyclePhase.PERCEIVE,
            "validate_input_evidence",
            f"{len(evidence)} owner-supplied observations passed structural validation.",
        )
        evidence_payload = tuple(
            {
                "record_id": item.record_id,
                "source_ref": item.source_ref,
                "observation": item.observation,
                "source_start_ms": item.source_start_ms,
                "source_end_ms": item.source_end_ms,
                "limitations": list(item.limitations),
                "independence_group": item.independence_group,
                "quality_level": item.quality_level,
            }
            for item in evidence
        )

        move(
            CyclePhase.RETRIEVE,
            "retrieve_context",
            "No automatic long-term memory retrieval is enabled in this runtime version.",
        )
        move(
            CyclePhase.HYPOTHESIZE,
            "generate_competing_hypotheses",
            "Generating multiple provisional explanations from supplied observations.",
        )
        generated = self.hypothesis_generator.generate(
            goal=goal,
            evidence=evidence_payload,
        )
        if len(generated.hypotheses) < 2:
            raise RuntimeError("hypothesis generator returned fewer than two alternatives")
        record(
            "hypotheses_created",
            f"{len(generated.hypotheses)} provisional alternatives generated.",
        )

        move(
            CyclePhase.CHALLENGE,
            "run_competing_hypotheses_audit",
            "Every hypothesis is evaluated against every supplied evidence item.",
        )
        ach_evidence = tuple(
            ACHEvidence(
                evidence_id=item.record_id,
                source_ref=item.source_ref,
                independence_group=item.independence_group,
                quality_level=item.quality_level,
                description=item.observation,
            )
            for item in evidence
        )
        review = self.ach_auditor.review(
            hypotheses=generated.hypotheses,
            evidence=ach_evidence,
        )
        record(
            "challenge_completed",
            f"Validated {len(generated.hypotheses) * len(evidence)} ACH matrix cells.",
        )

        move(
            CyclePhase.SYNTHESIZE,
            "synthesize_reviewable_report",
            "Contradictions, consistent evidence, missing cells and unresolved questions retained.",
        )
        unresolved = list(generated.unresolved_questions)
        for hypothesis in generated.hypotheses:
            unresolved.extend(hypothesis.discriminating_questions)
        # Preserve order while removing duplicates.
        unique_questions = tuple(dict.fromkeys(q.strip() for q in unresolved if q.strip()))
        record(
            "report_created",
            "Report is provisional and explicitly requires owner review.",
        )

        move(
            CyclePhase.REFLECT,
            "metacognitive_review",
            "No probability or confidence claim emitted; model ratings remain provisional.",
        )
        record(
            "reflection",
            "The system records unresolved questions and does not promote memory automatically.",
        )
        move(
            CyclePhase.CLOSED,
            "close_cycle",
            "Cognitive cycle closed with owner review pending.",
        )

        return InvestigationResult(
            investigation_id=str(uuid4()),
            cycle_id=cycle.cycle_id,
            goal=goal,
            evidence_manifest_sha256=self._manifest_digest(evidence),
            hypotheses=generated.hypotheses,
            ach_results=review.comparison.results,
            ach_warning=review.comparison.warning,
            unresolved_questions=unique_questions,
            review_notes=review.review_notes,
            model_ids=tuple(dict.fromkeys((generated.model, review.model))),
            trace=tuple(trace),
        )

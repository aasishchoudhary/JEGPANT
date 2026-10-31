"""Explicit state machine for a reviewable cognitive cycle.

This module coordinates stages only. It does not claim to implement reasoning
or consciousness; specialist processors will be plugged into these stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import uuid4


class CyclePhase(StrEnum):
    ORIENT = "orient"
    PERCEIVE = "perceive"
    RETRIEVE = "retrieve"
    HYPOTHESIZE = "hypothesize"
    CHALLENGE = "challenge"
    SYNTHESIZE = "synthesize"
    REFLECT = "reflect"
    CLOSED = "closed"


_ALLOWED: dict[CyclePhase, set[CyclePhase]] = {
    CyclePhase.ORIENT: {CyclePhase.PERCEIVE},
    CyclePhase.PERCEIVE: {CyclePhase.RETRIEVE},
    CyclePhase.RETRIEVE: {CyclePhase.HYPOTHESIZE},
    CyclePhase.HYPOTHESIZE: {CyclePhase.CHALLENGE},
    CyclePhase.CHALLENGE: {
        CyclePhase.PERCEIVE,
        CyclePhase.HYPOTHESIZE,
        CyclePhase.SYNTHESIZE,
    },
    CyclePhase.SYNTHESIZE: {CyclePhase.REFLECT},
    CyclePhase.REFLECT: {CyclePhase.RETRIEVE, CyclePhase.CLOSED},
    CyclePhase.CLOSED: set(),
}


@dataclass(frozen=True, slots=True)
class CycleState:
    goal: str
    phase: CyclePhase = CyclePhase.ORIENT
    cycle_id: str = field(default_factory=lambda: str(uuid4()))
    completed_phases: tuple[CyclePhase, ...] = field(default_factory=tuple)
    human_review_required: bool = True

    def __post_init__(self) -> None:
        if not self.goal.strip():
            raise ValueError("goal must not be empty")


def advance_cycle(state: CycleState, next_phase: CyclePhase) -> CycleState:
    """Advance only along an explicitly allowed transition."""
    if next_phase not in _ALLOWED[state.phase]:
        raise ValueError(
            f"invalid cycle transition: {state.phase.value} -> {next_phase.value}"
        )
    return CycleState(
        goal=state.goal,
        phase=next_phase,
        cycle_id=state.cycle_id,
        completed_phases=state.completed_phases + (state.phase,),
        human_review_required=state.human_review_required,
    )

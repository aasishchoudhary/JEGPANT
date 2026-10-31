import pytest

from jegpant.cycle import CyclePhase, CycleState, advance_cycle


def test_cycle_requires_reviewable_sequence():
    state = CycleState(goal="Reconstruct the event timeline.")
    with pytest.raises(ValueError):
        advance_cycle(state, CyclePhase.SYNTHESIZE)

    state = advance_cycle(state, CyclePhase.PERCEIVE)
    state = advance_cycle(state, CyclePhase.RETRIEVE)
    state = advance_cycle(state, CyclePhase.HYPOTHESIZE)
    state = advance_cycle(state, CyclePhase.CHALLENGE)
    state = advance_cycle(state, CyclePhase.SYNTHESIZE)
    state = advance_cycle(state, CyclePhase.REFLECT)
    state = advance_cycle(state, CyclePhase.CLOSED)

    assert state.phase is CyclePhase.CLOSED
    assert state.human_review_required is True


def test_adversarial_challenge_can_return_to_evidence():
    state = CycleState(goal="Compare two explanations.")
    for phase in (
        CyclePhase.PERCEIVE,
        CyclePhase.RETRIEVE,
        CyclePhase.HYPOTHESIZE,
        CyclePhase.CHALLENGE,
    ):
        state = advance_cycle(state, phase)

    state = advance_cycle(state, CyclePhase.PERCEIVE)
    assert state.phase is CyclePhase.PERCEIVE

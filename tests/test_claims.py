import pytest

from jegpant.claims import (
    ClaimEvidenceLink,
    ClaimKind,
    EvidenceRelation,
    GroundedClaim,
    validate_claim_sources,
)


def test_observation_requires_evidence_link():
    with pytest.raises(ValueError):
        GroundedClaim("c1", "The door opened.", ClaimKind.OBSERVATION)


def test_speculation_can_be_unlinked_but_is_explicit():
    claim = GroundedClaim("c1", "The person may have been distracted.", ClaimKind.SPECULATION)
    assert claim.evidence == ()


def test_unknown_evidence_reference_is_rejected():
    claim = GroundedClaim(
        "c1",
        "The door opened.",
        ClaimKind.OBSERVATION,
        evidence=(ClaimEvidenceLink("e1", EvidenceRelation.SUPPORTS),),
    )
    with pytest.raises(ValueError):
        validate_claim_sources(claim, {"e2"})

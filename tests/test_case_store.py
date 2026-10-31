import json
import sqlite3
from uuid import uuid4

import pytest

from jegpant.case_store import CaseIntegrityError, EncryptedCaseStore
from jegpant.inference import ChatResponse
from jegpant.runtime import CognitiveRuntime, InvestigationEvidence


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def __init__(self, key=b"k" * 32):
        self.key = key

    def get_key(self, version):
        return self.key


class QueueClient:
    def __init__(self, responses):
        self.responses = list(responses)

    def complete(self, messages, *, temperature=0.0, max_tokens=2048):
        return ChatResponse(json.dumps(self.responses.pop(0)), "case-test-model")


def runtime_responses():
    return [
        {
            "hypotheses": [
                {
                    "id": "h1",
                    "statement": "A person opened the door.",
                    "supporting_evidence_ids": ["e1"],
                    "contradicting_evidence_ids": [],
                    "assumptions": [],
                    "discriminating_questions": ["Is the handle visible?"],
                },
                {
                    "id": "h2",
                    "statement": "The door moved due to a mechanical issue.",
                    "supporting_evidence_ids": [],
                    "contradicting_evidence_ids": ["e1"],
                    "assumptions": [],
                    "discriminating_questions": ["Is a fault documented?"],
                },
            ],
            "unresolved_questions": [],
        },
        {
            "judgements": [
                {
                    "hypothesis_id": "h1",
                    "evidence_id": "e1",
                    "rating": "consistent",
                    "diagnosticity": 2,
                    "rationale": "The described movement is compatible.",
                },
                {
                    "hypothesis_id": "h2",
                    "evidence_id": "e1",
                    "rating": "neutral",
                    "diagnosticity": 1,
                    "rationale": "The observation does not resolve the cause.",
                },
            ],
            "review_notes": ["Verify against original footage."],
        },
    ]


def sample_evidence():
    return InvestigationEvidence(
        record_id="e1",
        source_ref="video://private/asset-1",
        independence_group="camera-1",
        observation="Door moves inward at 00:01:10.",
        quality_level=3,
        source_start_ms=70000,
        source_end_ms=72000,
        limitations=("Partial view of the handle.",),
    )


def open_store(path, *, instance_id=INSTANCE_ID, key=b"k" * 32):
    return EncryptedCaseStore(
        path,
        instance_id=instance_id,
        key_provider=FakeKeyProvider(key),
    )


def test_case_evidence_is_encrypted_and_survives_restart(tmp_path):
    path = tmp_path / "cases.sqlite"
    evidence = sample_evidence()

    with open_store(path) as store:
        case_id = store.create_case()
        store.add_evidence(case_id, evidence)
        assert store.list_evidence(case_id) == (evidence,)
        assert store.evidence_count(case_id) == 1

    raw = path.read_bytes()
    assert evidence.observation.encode() not in raw
    assert evidence.source_ref.encode() not in raw

    with open_store(path) as reopened:
        assert reopened.list_evidence(case_id) == (evidence,)


def test_case_evidence_cannot_be_overwritten(tmp_path):
    with open_store(tmp_path / "cases.sqlite") as store:
        case_id = store.create_case()
        evidence = sample_evidence()
        store.add_evidence(case_id, evidence)

        with pytest.raises(ValueError, match="already exists"):
            store.add_evidence(case_id, evidence)

        assert store.evidence_count(case_id) == 1


def test_investigation_result_must_match_case_evidence_manifest(tmp_path):
    with open_store(tmp_path / "cases.sqlite") as store:
        case_id = store.create_case()
        evidence = sample_evidence()
        store.add_evidence(case_id, evidence)

        result = CognitiveRuntime(
            QueueClient(runtime_responses())
        ).investigate(goal="Explain the door movement.", evidence=(evidence,))
        store.store_result(case_id, result)

        recovered = store.get_result(case_id, result.investigation_id)
        assert recovered["investigation_id"] == result.investigation_id
        assert recovered["evidence_manifest_sha256"] == result.evidence_manifest_sha256
        assert recovered["human_review_required"] is True
        assert store.report_count(case_id) == 1


def test_result_with_different_evidence_is_rejected(tmp_path):
    with open_store(tmp_path / "cases.sqlite") as store:
        case_id = store.create_case()
        evidence = sample_evidence()
        store.add_evidence(case_id, evidence)
        result = CognitiveRuntime(
            QueueClient(runtime_responses())
        ).investigate(goal="Explain the door movement.", evidence=(evidence,))

        different = InvestigationEvidence(
            "e2",
            "video://private/other",
            "camera-2",
            "A different event.",
        )
        with pytest.raises(ValueError, match="does not match"):
            store.add_evidence(case_id, different)
            # The report remains bound to the original evidence set.
            store.store_result(case_id, result)


def test_case_reports_are_encrypted(tmp_path):
    path = tmp_path / "cases.sqlite"
    evidence = sample_evidence()
    with open_store(path) as store:
        case_id = store.create_case()
        store.add_evidence(case_id, evidence)
        result = CognitiveRuntime(
            QueueClient(runtime_responses())
        ).investigate(goal="Explain private door movement.", evidence=(evidence,))
        store.store_result(case_id, result)

    raw = path.read_bytes()
    assert b"Explain private door movement." not in raw
    assert b"A person opened the door." not in raw
    assert b"Review against original footage." not in raw


def test_wrong_key_cannot_open_case_evidence(tmp_path):
    path = tmp_path / "cases.sqlite"
    evidence = sample_evidence()
    with open_store(path) as store:
        case_id = store.create_case()
        store.add_evidence(case_id, evidence)

    with open_store(path, key=b"x" * 32) as wrong_key_store:
        with pytest.raises(CaseIntegrityError):
            wrong_key_store.list_evidence(case_id)


def test_ciphertext_tampering_is_detected(tmp_path):
    path = tmp_path / "cases.sqlite"
    evidence = sample_evidence()
    with open_store(path) as store:
        case_id = store.create_case()
        store.add_evidence(case_id, evidence)

    with sqlite3.connect(path) as connection:
        ciphertext = bytearray(
            connection.execute(
                "SELECT ciphertext FROM case_evidence WHERE case_id = ?",
                (case_id,),
            ).fetchone()[0]
        )
        ciphertext[-1] ^= 0x01
        connection.execute(
            "UPDATE case_evidence SET ciphertext = ? WHERE case_id = ?",
            (bytes(ciphertext), case_id),
        )

    with open_store(path) as store:
        with pytest.raises(CaseIntegrityError, match="authentication"):
            store.list_evidence(case_id)


def test_case_namespace_isolation_between_instances(tmp_path):
    path = tmp_path / "cases.sqlite"
    evidence = sample_evidence()
    with open_store(path) as store:
        case_id = store.create_case()
        store.add_evidence(case_id, evidence)

    with open_store(path, instance_id=str(uuid4())) as other:
        assert not other.case_exists(case_id)


def test_missing_case_is_rejected(tmp_path):
    with open_store(tmp_path / "cases.sqlite") as store:
        with pytest.raises(KeyError):
            store.list_evidence(str(uuid4()))



def test_media_asset_metadata_is_encrypted_and_persisted(tmp_path):
    from types import SimpleNamespace

    path = tmp_path / "cases.sqlite"
    entry = SimpleNamespace(
        asset_id=str(uuid4()),
        size_bytes=123456,
        sha256="ab" * 32,
        key_version=1,
        chunk_size=65536,
        chunk_count=2,
    )
    with open_store(path) as store:
        case_id = store.create_case()
        store.add_media_asset(case_id, entry)
        assets = store.list_media_assets(case_id)
        assert len(assets) == 1
        assert assets[0]["asset_id"] == entry.asset_id
        assert assets[0]["sha256"] == entry.sha256

    raw = path.read_bytes()
    assert entry.asset_id.encode() not in raw
    assert entry.sha256.encode() not in raw

    with open_store(path) as reopened:
        assert reopened.media_asset_exists(case_id, entry.asset_id)
        assert reopened.list_media_assets(case_id)[0]["asset_id"] == entry.asset_id


def test_media_asset_metadata_rejects_duplicate_and_unknown_case(tmp_path):
    from types import SimpleNamespace

    entry = SimpleNamespace(
        asset_id=str(uuid4()),
        size_bytes=999,
        sha256="cd" * 32,
        key_version=1,
        chunk_size=65536,
        chunk_count=1,
    )
    with open_store(tmp_path / "cases.sqlite") as store:
        with pytest.raises(KeyError):
            store.add_media_asset(str(uuid4()), entry)

        case_id = store.create_case()
        store.add_media_asset(case_id, entry)
        with pytest.raises(ValueError, match="already exists"):
            store.add_media_asset(case_id, entry)


def test_media_metadata_ciphertext_tampering_is_detected(tmp_path):
    from types import SimpleNamespace

    path = tmp_path / "cases.sqlite"
    entry = SimpleNamespace(
        asset_id=str(uuid4()),
        size_bytes=999,
        sha256="ef" * 32,
        key_version=1,
        chunk_size=65536,
        chunk_count=1,
    )
    with open_store(path) as store:
        case_id = store.create_case()
        store.add_media_asset(case_id, entry)

    with sqlite3.connect(path) as connection:
        ciphertext = bytearray(
            connection.execute(
                "SELECT ciphertext FROM case_media_assets WHERE case_id = ?",
                (case_id,),
            ).fetchone()[0]
        )
        ciphertext[-1] ^= 0x01
        connection.execute(
            "UPDATE case_media_assets SET ciphertext = ? WHERE case_id = ?",
            (bytes(ciphertext), case_id),
        )

    with open_store(path) as store:
        with pytest.raises(CaseIntegrityError, match="authentication"):
            store.list_media_assets(case_id)

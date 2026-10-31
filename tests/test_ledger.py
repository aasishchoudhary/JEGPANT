import json

import pytest

from jegpant.ledger import EvidenceLedger, LedgerIntegrityError


def test_append_and_verify_hash_chain(tmp_path):
    ledger = EvidenceLedger(tmp_path / "case" / "evidence.jsonl")
    first = ledger.append(
        case_id="case-1",
        source_ref="asset://video-1",
        modality="video",
        observation="A person enters the room.",
        source_start_ms=1200,
        source_end_ms=2400,
        limitations=("Low light in part of the clip.",),
    )
    second = ledger.append(
        case_id="case-1",
        source_ref="asset://video-1",
        modality="video",
        observation="The door closes.",
        source_start_ms=2500,
        source_end_ms=3100,
    )

    records = ledger.read_all()
    assert len(records) == 2
    assert records[0]["record_hash"] == first["record_hash"]
    assert second["previous_hash"] == first["record_hash"]


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "evidence.jsonl"
    ledger = EvidenceLedger(path)
    ledger.append(
        case_id="case-1",
        source_ref="asset://clip",
        modality="video",
        observation="A vehicle stops.",
    )

    record = json.loads(path.read_text(encoding="utf-8"))
    record["observation"] = "A different observation."
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(LedgerIntegrityError):
        ledger.read_all()


def test_invalid_timestamps_are_rejected(tmp_path):
    ledger = EvidenceLedger(tmp_path / "evidence.jsonl")
    with pytest.raises(ValueError):
        ledger.append(
            case_id="case-1",
            source_ref="asset://clip",
            modality="video",
            observation="An event.",
            source_start_ms=500,
            source_end_ms=400,
        )

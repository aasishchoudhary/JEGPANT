import sqlite3
from uuid import uuid4

import pytest

from jegpant.encrypted_store import (
    EncryptedMemoryStore,
    StorageIntegrityError,
)
from jegpant.memory import MemoryKind, MemoryRecord, MemorySensitivity


INSTANCE_ID = str(uuid4())


class TestKeyProvider:
    def __init__(self):
        self.keys = {1: b"1" * 32, 2: b"2" * 32}

    def get_key(self, version):
        return self.keys[version]


def sample_record(instance_id=INSTANCE_ID):
    return MemoryRecord(
        memory_id="memory-001",
        instance_id=instance_id,
        proposal_id="proposal-001",
        kind=MemoryKind.EPISODIC,
        summary="A sensitive private memory summary.",
        provenance_refs=("evidence-1", "claim-2"),
        sensitivity=MemorySensitivity.HIGHLY_SENSITIVE,
        context_tags=("investigation", "video"),
        created_at="2026-10-31T12:00:00+00:00",
        owner_approval_id="owner-approval-1",
    )


def test_round_trip_encrypted_memory(tmp_path):
    path = tmp_path / "memory.sqlite"
    keys = TestKeyProvider()
    record = sample_record()

    with EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=keys
    ) as store:
        store.put(record)
        assert store.get(record.memory_id) == record
        assert store.count() == 1

    raw = path.read_bytes()
    assert b"A sensitive private memory summary." not in raw
    assert b"owner-approval-1" not in raw


def test_database_ciphertext_tampering_is_detected(tmp_path):
    path = tmp_path / "memory.sqlite"
    store = EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=TestKeyProvider()
    )
    record = sample_record()
    store.put(record)

    with sqlite3.connect(path) as connection:
        ciphertext = bytearray(
            connection.execute(
                "SELECT ciphertext FROM encrypted_memory WHERE memory_id = ?",
                (record.memory_id,),
            ).fetchone()[0]
        )
        ciphertext[0] ^= 0x01
        connection.execute(
            "UPDATE encrypted_memory SET ciphertext = ? WHERE memory_id = ?",
            (bytes(ciphertext), record.memory_id),
        )

    with pytest.raises(StorageIntegrityError, match="authentication failed"):
        store.get(record.memory_id)
    store.close()


def test_database_is_bound_to_cognitive_instance(tmp_path):
    path = tmp_path / "memory.sqlite"
    store = EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=TestKeyProvider()
    )
    store.put(sample_record())
    store.close()

    other_store = EncryptedMemoryStore(
        path, instance_id=str(uuid4()), key_provider=TestKeyProvider()
    )
    with pytest.raises(StorageIntegrityError):
        other_store.get("memory-001")
    other_store.close()


def test_key_rotation_reencrypts_existing_records(tmp_path):
    path = tmp_path / "memory.sqlite"
    keys = TestKeyProvider()
    record = sample_record()

    with EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=keys
    ) as store:
        store.put(record)
        assert store.rotate_key(2) == 1
        assert store.current_key_version == 2
        assert store.get(record.memory_id) == record

        version = store._connection.execute(
            "SELECT key_version FROM encrypted_memory WHERE memory_id = ?",
            (record.memory_id,),
        ).fetchone()[0]
        assert version == 2


def test_wrong_key_cannot_decrypt_memory(tmp_path):
    path = tmp_path / "memory.sqlite"
    writer = EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=TestKeyProvider()
    )
    writer.put(sample_record())
    writer.close()

    wrong_keys = TestKeyProvider()
    wrong_keys.keys[1] = b"x" * 32
    reader = EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=wrong_keys
    )
    with pytest.raises(StorageIntegrityError):
        reader.get("memory-001")
    reader.close()


def test_delete_removes_record_from_catalogue(tmp_path):
    path = tmp_path / "memory.sqlite"
    with EncryptedMemoryStore(
        path, instance_id=INSTANCE_ID, key_provider=TestKeyProvider()
    ) as store:
        store.put(sample_record())
        assert store.delete("memory-001") is True
        assert store.count() == 0
        assert store.delete("memory-001") is False


def test_memory_store_rejects_wrong_instance_on_write(tmp_path):
    with EncryptedMemoryStore(
        tmp_path / "memory.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=TestKeyProvider(),
    ) as store:
        with pytest.raises(PermissionError):
            store.put(sample_record(str(uuid4())))

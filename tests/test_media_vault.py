import hashlib
from uuid import uuid4

import pytest

from jegpant.media_vault import (
    EncryptedMediaVault,
    MediaVaultError,
    MediaVaultIntegrityError,
)


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def __init__(self):
        self.keys = {1: b"a" * 32, 2: b"b" * 32}

    def get_key(self, version):
        return self.keys[version]


def make_vault(tmp_path, *, instance_id=INSTANCE_ID, chunk_size=64 * 1024):
    return EncryptedMediaVault(
        tmp_path / "vault",
        instance_id=instance_id,
        key_provider=FakeKeyProvider(),
        chunk_size=chunk_size,
    )


def test_multi_chunk_round_trip_and_source_digest(tmp_path):
    source = tmp_path / "original.mp4"
    data = bytes(range(256)) * 1024
    source.write_bytes(data)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)

    assert entry.size_bytes == len(data)
    assert entry.sha256 == hashlib.sha256(data).hexdigest()
    assert entry.chunk_count == 4

    restored = tmp_path / "restored.mp4"
    vault.decrypt_file(entry.asset_id, restored)
    assert restored.read_bytes() == data


def test_encrypted_vault_does_not_contain_plaintext_source(tmp_path):
    secret = b"THIS IS PRIVATE VIDEO DATA DO NOT STORE IN PLAINTEXT"
    source = tmp_path / "private.mp4"
    source.write_bytes(secret)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)

    encrypted_path = vault._asset_path(entry.asset_id)
    encrypted = encrypted_path.read_bytes()
    assert secret not in encrypted
    assert len(encrypted) > len(secret)


def test_tampered_chunk_is_rejected_and_no_plaintext_output_is_published(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"q" * 100_000)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)
    encrypted_path = vault._asset_path(entry.asset_id)

    blob = bytearray(encrypted_path.read_bytes())
    header_length = int.from_bytes(
        blob[len(vault.MAGIC):len(vault.MAGIC) + 4], "big"
    )
    first_chunk_offset = len(vault.MAGIC) + 4 + header_length
    blob[first_chunk_offset + 20] ^= 0x40
    encrypted_path.write_bytes(blob)

    target = tmp_path / "should-not-exist.bin"
    with pytest.raises(MediaVaultIntegrityError, match="authentication"):
        vault.decrypt_file(entry.asset_id, target)

    assert not target.exists()
    assert not list(tmp_path.glob(".should-not-exist.bin.*.decrypting"))


def test_truncated_media_file_is_rejected(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"r" * 90_000)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)
    encrypted_path = vault._asset_path(entry.asset_id)
    encrypted_path.write_bytes(encrypted_path.read_bytes()[:-10])

    with pytest.raises(MediaVaultIntegrityError, match="size is inconsistent"):
        vault.decrypt_file(entry.asset_id, tmp_path / "truncated.out")


def test_wrong_instance_cannot_decrypt_media(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"video" * 20_000)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)

    other = make_vault(tmp_path, instance_id=str(uuid4()))
    with pytest.raises(MediaVaultIntegrityError, match="another instance"):
        other.decrypt_file(entry.asset_id, tmp_path / "output.bin")


def test_wrong_key_fails_authentication(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"private" * 20_000)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)

    class WrongKeyProvider:
        def get_key(self, version):
            return b"x" * 32

    other = EncryptedMediaVault(
        tmp_path / "vault",
        instance_id=INSTANCE_ID,
        key_provider=WrongKeyProvider(),
        chunk_size=64 * 1024,
    )
    with pytest.raises(MediaVaultIntegrityError):
        other.decrypt_file(entry.asset_id, tmp_path / "output.bin")


def test_existing_destination_is_never_overwritten(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"video" * 20_000)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)
    destination = tmp_path / "existing.out"
    destination.write_bytes(b"keep me")

    with pytest.raises(FileExistsError):
        vault.decrypt_file(entry.asset_id, destination)

    assert destination.read_bytes() == b"keep me"


def test_duplicate_asset_id_is_rejected(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"video" * 20_000)
    vault = make_vault(tmp_path)
    asset_id = str(uuid4())
    vault.encrypt_file(source, asset_id=asset_id)

    with pytest.raises(FileExistsError):
        vault.encrypt_file(source, asset_id=asset_id)


def test_empty_and_oversized_source_are_rejected(tmp_path):
    vault = make_vault(tmp_path)
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(MediaVaultError, match="empty"):
        vault.encrypt_file(empty)

    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * 100)
    limited = EncryptedMediaVault(
        tmp_path / "limited",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
        chunk_size=64 * 1024,
        max_asset_bytes=99,
    )
    with pytest.raises(MediaVaultError, match="size limit"):
        limited.encrypt_file(large)


def test_delete_removes_ciphertext_asset(tmp_path):
    source = tmp_path / "original.bin"
    source.write_bytes(b"video" * 1000)
    vault = make_vault(tmp_path)
    entry = vault.encrypt_file(source)
    path = vault._asset_path(entry.asset_id)
    assert path.exists()

    assert vault.delete(entry.asset_id) is True
    assert path.exists() is False
    assert vault.delete(entry.asset_id) is False


def test_invalid_asset_id_is_rejected(tmp_path):
    vault = make_vault(tmp_path)
    with pytest.raises(ValueError, match="UUID"):
        vault.decrypt_file("../../outside", tmp_path / "out.bin")



def test_async_stream_upload_encrypts_without_plaintext_staging(tmp_path):
    import asyncio

    data = bytes(range(256)) * 900
    digest = hashlib.sha256(data).hexdigest()
    vault = make_vault(tmp_path)
    asset_id = str(uuid4())

    async def chunks():
        for offset in range(0, len(data), 7777):
            yield data[offset:offset + 7777]

    entry = asyncio.run(
        vault.encrypt_stream(
            chunks(),
            asset_id=asset_id,
            expected_size_bytes=len(data),
            expected_sha256=digest,
        )
    )
    assert entry.sha256 == digest
    assert entry.size_bytes == len(data)
    assert entry.chunk_count == 4

    encrypted_path = vault._asset_path(asset_id)
    assert data not in encrypted_path.read_bytes()

    restored = tmp_path / "stream-restored.bin"
    vault.decrypt_file(asset_id, restored)
    assert restored.read_bytes() == data


def test_async_stream_upload_rejects_wrong_digest_and_removes_partial_asset(tmp_path):
    import asyncio

    data = b"streamed-private-data" * 10000
    vault = make_vault(tmp_path)
    asset_id = str(uuid4())

    async def chunks():
        yield data[:50000]
        yield data[50000:]

    with pytest.raises(MediaVaultIntegrityError, match="did not match"):
        asyncio.run(
            vault.encrypt_stream(
                chunks(),
                asset_id=asset_id,
                expected_size_bytes=len(data),
                expected_sha256="0" * 64,
            )
        )
    assert not vault._asset_path(asset_id).exists()


def test_async_stream_upload_rejects_short_and_long_uploads(tmp_path):
    import asyncio

    vault = make_vault(tmp_path)
    short_id = str(uuid4())
    long_id = str(uuid4())

    async def short_chunks():
        yield b"short"

    async def long_chunks():
        yield b"this is longer than expected"

    with pytest.raises(MediaVaultError, match="ended before"):
        asyncio.run(
            vault.encrypt_stream(
                short_chunks(),
                asset_id=short_id,
                expected_size_bytes=100,
                expected_sha256=hashlib.sha256(b"x" * 100).hexdigest(),
            )
        )
    assert not vault._asset_path(short_id).exists()

    long_data = b"this is longer than expected"
    with pytest.raises(MediaVaultError, match="exceeds"):
        asyncio.run(
            vault.encrypt_stream(
                long_chunks(),
                asset_id=long_id,
                expected_size_bytes=5,
                expected_sha256=hashlib.sha256(b"12345").hexdigest(),
            )
        )
    assert not vault._asset_path(long_id).exists()

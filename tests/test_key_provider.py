import os

import pytest

from jegpant.key_provider import LocalFileKeyProvider, LocalKeyProviderError


INSTANCE_ID = "a1000000-0000-4000-8000-000000000001"


def test_local_key_provider_creates_private_root_and_derives_purpose_keys(tmp_path):
    root = tmp_path / "private"
    path = root / "root.key"

    memory = LocalFileKeyProvider(
        path,
        instance_id=INSTANCE_ID,
        purpose="memory",
        create_if_missing=True,
    )
    reopened = LocalFileKeyProvider(
        path,
        instance_id=INSTANCE_ID,
        purpose="memory",
        create_if_missing=False,
    )
    cases = LocalFileKeyProvider(
        path,
        instance_id=INSTANCE_ID,
        purpose="cases",
        create_if_missing=False,
    )

    assert memory.get_key(1) == reopened.get_key(1)
    assert memory.get_key(1) != cases.get_key(1)
    assert memory.get_key(1) != memory.get_key(2)
    assert len(memory.get_key(1)) == 32
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_local_key_provider_refuses_missing_key_without_create_permission(tmp_path):
    with pytest.raises(LocalKeyProviderError, match="missing"):
        LocalFileKeyProvider(
            tmp_path / "root.key",
            instance_id=INSTANCE_ID,
            purpose="memory",
        )


def test_local_key_provider_refuses_group_or_world_readable_key(tmp_path):
    path = tmp_path / "root.key"
    path.write_bytes(b"k" * 32)
    path.chmod(0o644)

    if os.name == "posix":
        with pytest.raises(LocalKeyProviderError, match="owner-only"):
            LocalFileKeyProvider(
                path,
                instance_id=INSTANCE_ID,
                purpose="memory",
            )
    else:
        pytest.skip("POSIX mode-bit validation is not supported")


def test_local_key_provider_rejects_wrong_length_and_symlink(tmp_path):
    path = tmp_path / "root.key"
    path.write_bytes(b"short")
    path.chmod(0o600)

    with pytest.raises(LocalKeyProviderError, match="exactly 32"):
        LocalFileKeyProvider(
            path,
            instance_id=INSTANCE_ID,
            purpose="memory",
        )

    other = tmp_path / "real.key"
    other.write_bytes(b"x" * 32)
    other.chmod(0o600)
    link = tmp_path / "link.key"
    try:
        link.symlink_to(other)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(OSError):
        LocalFileKeyProvider(
            link,
            instance_id=INSTANCE_ID,
            purpose="memory",
        )


def test_local_key_provider_requires_positive_integer_versions(tmp_path):
    provider = LocalFileKeyProvider(
        tmp_path / "root.key",
        instance_id=INSTANCE_ID,
        purpose="memory",
        create_if_missing=True,
    )
    with pytest.raises(ValueError):
        provider.get_key(0)
    with pytest.raises(ValueError):
        provider.get_key(True)

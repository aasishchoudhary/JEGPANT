import base64
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from jegpant.key_provider import LocalKeyProviderError
from jegpant.service_factory import build_services


def owner_public_key_b64():
    key = ec.generate_private_key(ec.SECP256R1())
    public_key = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_key).decode("ascii")


def test_service_factory_builds_single_instance_services_and_reopens(tmp_path):
    instance_id = str(uuid4())
    storage = tmp_path / "private-data"
    env = {
        "JEGPANT_INSTANCE_ID": instance_id,
        "JEGPANT_OWNER_PUBLIC_KEY_B64": owner_public_key_b64(),
        "JEGPANT_OWNER_KEY_ALGORITHM": "ecdsa_p256",
        "JEGPANT_STORAGE_ROOT": str(storage),
        "JEGPANT_ALLOW_LOCAL_FILE_KEYS": "true",
        "JEGPANT_INITIALIZE_LOCAL_STORAGE": "true",
    }

    first = build_services(env)
    assert first.instance_id == instance_id
    assert first.authorization.owner_key_algorithm == "ecdsa_p256"
    assert first.authorization.state_store is first.approval_verifier.state_store
    assert first.memory_service.instance_id == instance_id
    assert first.cases.instance_id == instance_id
    assert first.jobs.instance_id == instance_id
    assert first.media_vault.instance_id == instance_id

    key_path = storage / "keys" / "master.key"
    assert key_path.exists()
    assert (storage / ".jegpant-local-key-root-initialized").exists()

    first.memory_store.close()

    restarted_env = dict(env)
    restarted_env["JEGPANT_INITIALIZE_LOCAL_STORAGE"] = "false"
    second = build_services(restarted_env)
    assert second.instance_id == instance_id
    assert (
        second.memory_store.database_path
        == str(storage / "memory.sqlite")
    )
    second.memory_store.close()


def test_service_factory_refuses_to_recreate_missing_initialized_root_key(tmp_path):
    storage = tmp_path / "private-data"
    env = {
        "JEGPANT_INSTANCE_ID": str(uuid4()),
        "JEGPANT_OWNER_PUBLIC_KEY_B64": owner_public_key_b64(),
        "JEGPANT_OWNER_KEY_ALGORITHM": "ecdsa_p256",
        "JEGPANT_STORAGE_ROOT": str(storage),
        "JEGPANT_ALLOW_LOCAL_FILE_KEYS": "true",
        "JEGPANT_INITIALIZE_LOCAL_STORAGE": "true",
    }
    services = build_services(env)
    services.memory_store.close()
    (storage / "keys" / "master.key").unlink()

    with pytest.raises(LocalKeyProviderError, match="refusing to generate"):
        build_services(env)


def test_service_factory_requires_explicit_local_key_security_opt_in(tmp_path):
    env = {
        "JEGPANT_INSTANCE_ID": str(uuid4()),
        "JEGPANT_OWNER_PUBLIC_KEY_B64": owner_public_key_b64(),
        "JEGPANT_STORAGE_ROOT": str(tmp_path / "private-data"),
    }
    with pytest.raises(RuntimeError, match="local file key custody is disabled"):
        build_services(env)


def test_service_factory_rejects_missing_owner_public_key(tmp_path):
    env = {
        "JEGPANT_INSTANCE_ID": str(uuid4()),
        "JEGPANT_STORAGE_ROOT": str(tmp_path / "private-data"),
        "JEGPANT_ALLOW_LOCAL_FILE_KEYS": "true",
    }
    with pytest.raises(RuntimeError, match="OWNER_PUBLIC_KEY"):
        build_services(env)

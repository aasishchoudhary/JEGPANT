"""Production-shaped service wiring for a single-owner JEGPANT instance."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from .api import PrivateAPIConfig, create_app
from .case_store import EncryptedCaseStore
from .encrypted_store import EncryptedMemoryStore
from .job_queue import AnalysisJobQueue
from .key_provider import LocalFileKeyProvider, LocalKeyProviderError
from .media_vault import EncryptedMediaVault
from .memory_service import MemoryPromotionService
from .owner_auth import Ed25519ApprovalVerifier, OwnerAuthorizationService
from .owner_state_store import SQLiteOwnerStateStore


@dataclass(frozen=True, slots=True)
class RuntimeServices:
    instance_id: str
    owner_key_algorithm: str
    storage_root: Path
    authorization: OwnerAuthorizationService
    approval_verifier: Ed25519ApprovalVerifier
    memory_store: EncryptedMemoryStore
    memory_service: MemoryPromotionService
    cases: EncryptedCaseStore
    jobs: AnalysisJobQueue
    media_vault: EncryptedMediaVault


def _required(environment: dict[str, str], name: str) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


def _prepare_local_key_root(
    storage_root: Path,
    *,
    key_path: Path,
    allow_local_keys: bool,
    initialize_local_storage: bool,
) -> None:
    """Require an explicit first-run initialisation and refuse silent key reset."""
    if not allow_local_keys:
        raise RuntimeError(
            "local file key custody is disabled; use an external KMS/HSM provider "
            "or explicitly enable local self-hosted mode"
        )

    marker = storage_root / ".jegpant-local-key-root-initialized"
    if marker.exists():
        if not key_path.is_file():
            raise LocalKeyProviderError(
                "the initialized local root key is missing; refusing to generate "
                "a replacement that would make existing data unreadable"
            )
        return

    if not initialize_local_storage:
        raise RuntimeError(
            "local storage is not initialized; set "
            "JEGPANT_INITIALIZE_LOCAL_STORAGE=true for the first startup only"
        )

    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    LocalFileKeyProvider(
        key_path,
        instance_id="local-bootstrap",
        purpose="bootstrap-check",
        create_if_missing=True,
    )
    descriptor = os.open(
        marker,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(b"local-key-root-v1\n")
        stream.flush()
        os.fsync(stream.fileno())


def build_services(
    environment: dict[str, str] | None = None,
) -> RuntimeServices:
    """Construct all shared services from explicit runtime environment settings."""
    env = dict(os.environ if environment is None else environment)
    instance_id = _required(env, "JEGPANT_INSTANCE_ID")
    try:
        UUID(instance_id)
    except ValueError as exc:
        raise RuntimeError("JEGPANT_INSTANCE_ID must be a UUID") from exc

    owner_key_algorithm = env.get("JEGPANT_OWNER_KEY_ALGORITHM", "ecdsa_p256").strip()
    if owner_key_algorithm not in {"ecdsa_p256", "ed25519"}:
        raise RuntimeError("JEGPANT_OWNER_KEY_ALGORITHM is unsupported")
    try:
        owner_public_key = base64.b64decode(
            _required(env, "JEGPANT_OWNER_PUBLIC_KEY_B64"),
            validate=True,
        )
    except ValueError as exc:
        raise RuntimeError("owner public key must be valid base64") from exc

    storage_root = Path(env.get("JEGPANT_STORAGE_ROOT", "./private-data")).resolve()
    storage_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(storage_root, 0o700)
    except OSError:
        pass

    key_path = Path(
        env.get("JEGPANT_LOCAL_MASTER_KEY_PATH", str(storage_root / "keys" / "master.key"))
    )
    if not key_path.is_absolute():
        key_path = (storage_root / key_path).resolve()

    _prepare_local_key_root(
        storage_root,
        key_path=key_path,
        allow_local_keys=env.get("JEGPANT_ALLOW_LOCAL_FILE_KEYS", "").lower() == "true",
        initialize_local_storage=(
            env.get("JEGPANT_INITIALIZE_LOCAL_STORAGE", "").lower() == "true"
        ),
    )

    def key_provider(purpose: str) -> LocalFileKeyProvider:
        return LocalFileKeyProvider(
            key_path,
            instance_id=instance_id,
            purpose=purpose,
            create_if_missing=False,
        )

    state_store = SQLiteOwnerStateStore(
        storage_root / "owner-state.sqlite",
        instance_id=instance_id,
    )
    authorization = OwnerAuthorizationService(
        instance_id=instance_id,
        owner_public_key=owner_public_key,
        owner_key_algorithm=owner_key_algorithm,
        state_store=state_store,
    )
    approval_verifier = Ed25519ApprovalVerifier(
        instance_id=instance_id,
        owner_public_key=owner_public_key,
        owner_key_algorithm=owner_key_algorithm,
        key_id=env.get("JEGPANT_OWNER_KEY_ID", "owner-key-v1"),
        state_store=state_store,
    )

    memory_store = EncryptedMemoryStore(
        storage_root / "memory.sqlite",
        instance_id=instance_id,
        key_provider=key_provider("memory"),
    )
    memory_service = MemoryPromotionService(
        instance_id=instance_id,
        verifier=approval_verifier,
        authorization_service=authorization,
        store=memory_store,
    )
    cases = EncryptedCaseStore(
        storage_root / "cases.sqlite",
        instance_id=instance_id,
        key_provider=key_provider("cases"),
    )
    jobs = AnalysisJobQueue(
        storage_root / "jobs.sqlite",
        instance_id=instance_id,
        key_provider=key_provider("jobs"),
    )
    media_vault = EncryptedMediaVault(
        storage_root / "media",
        instance_id=instance_id,
        key_provider=key_provider("media"),
        max_asset_bytes=int(
            env.get("JEGPANT_MAX_MEDIA_BYTES", str(8 * 1024 * 1024 * 1024))
        ),
    )
    return RuntimeServices(
        instance_id=instance_id,
        owner_key_algorithm=owner_key_algorithm,
        storage_root=storage_root,
        authorization=authorization,
        approval_verifier=approval_verifier,
        memory_store=memory_store,
        memory_service=memory_service,
        cases=cases,
        jobs=jobs,
        media_vault=media_vault,
    )


def build_app(environment: dict[str, str] | None = None):
    """Build the FastAPI application and retain service handles for diagnostics."""
    env = dict(os.environ if environment is None else environment)
    services = build_services(env)
    app = create_app(
        authorization=services.authorization,
        cases=services.cases,
        jobs=services.jobs,
        media_vault=services.media_vault,
        config=PrivateAPIConfig(
            max_json_body_bytes=int(env.get("JEGPANT_MAX_JSON_BYTES", str(1024 * 1024))),
            max_media_upload_bytes=int(
                env.get("JEGPANT_MAX_MEDIA_BYTES", str(8 * 1024 * 1024 * 1024))
            ),
        ),
    )
    app.state.jegpant_services = services
    return app

"""Single-owner device enrolment and signed-request verification primitives.

The owner private key never enters this service. The service stores only public
keys and verifies short-lived, device-signed requests. State is delegated to an
atomic OwnerStateStore; use SQLiteOwnerStateStore for restart-persistent replay,
enrolment, revocation and owner-approval state.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from threading import RLock
from typing import Callable, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature

from .memory import SignedOwnerApproval
from .signatures import ED25519, load_public_key, verify_signature


def _synchronized(method):
    """Serialize calls within one process; the state store arbitrates across processes."""

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapped


ALLOWED_DEVICE_SCOPES = frozenset(
    {
        "read_memory",
        "propose_memory",
        "read_evidence",
        "ingest_media",
        "run_analysis",
        "export_data",
        "manage_devices",
        "create_case",
        "write_evidence",
        "queue_analysis",
        "read_jobs",
        "read_reports",
    }
)


class OwnerAuthorizationError(PermissionError):
    """Raised when owner or enrolled-device authorization fails."""


@dataclass(frozen=True, slots=True)
class DeviceEnrollment:
    instance_id: str
    device_id: str
    device_public_key_b64: str
    scopes: tuple[str, ...]
    enrollment_id: str
    issued_at: str
    expires_at: str
    owner_signature_b64: str
    device_proof_b64: str
    device_key_algorithm: str = ED25519


@dataclass(frozen=True, slots=True)
class SignedDeviceRequest:
    instance_id: str
    device_id: str
    request_id: str
    method: str
    path: str
    issued_at: str
    expires_at: str
    body_sha256: str
    signature_b64: str


@dataclass(frozen=True, slots=True)
class SignedDeviceRevocation:
    instance_id: str
    device_id: str
    revocation_id: str
    issued_at: str
    expires_at: str
    owner_signature_b64: str


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    device_id: str
    public_key: bytes
    scopes: frozenset[str]
    enrolled_at: str
    revoked_at: str | None = None
    key_algorithm: str = ED25519


class OwnerStateStore(Protocol):
    """Atomic state boundary for single-owner device and approval authorization."""

    instance_id: str

    def register_device(self, enrollment_id: str, record: DeviceRecord) -> bool:
        """Atomically register a device and consume an enrollment ID."""
        ...

    def get_device(self, device_id: str) -> DeviceRecord | None:
        """Read a device registration."""
        ...

    def authorize_request(
        self,
        device_id: str,
        required_scope: str,
        request_id: str,
        expires_at: str,
    ) -> str:
        """Atomically check active device/scope and consume a request ID.

        Returns 'ok', 'inactive', 'scope', or 'replay'.
        """
        ...

    def revoke_device(
        self, device_id: str, revocation_id: str, revoked_at: str
    ) -> DeviceRecord | None:
        """Atomically consume a revocation ID and revoke an active device."""
        ...

    def consume_approval(self, approval_id: str, expires_at: str) -> bool:
        """Atomically consume a one-time owner approval ID."""
        ...


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _decode_signature(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise OwnerAuthorizationError("signature encoding is invalid") from None


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise OwnerAuthorizationError("timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise OwnerAuthorizationError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _valid_window(
    issued_at: str,
    expires_at: str,
    *,
    now: datetime,
    max_ttl_seconds: int,
    future_skew_seconds: int = 30,
) -> bool:
    try:
        issued = _parse_time(issued_at)
        expires = _parse_time(expires_at)
    except OwnerAuthorizationError:
        return False
    now = now.astimezone(UTC)
    ttl = (expires - issued).total_seconds()
    return (
        ttl > 0
        and ttl <= max_ttl_seconds
        and issued.timestamp() <= now.timestamp() + future_skew_seconds
        and expires > now
    )


def enrollment_signing_bytes(enrollment: DeviceEnrollment) -> bytes:
    """Canonical bytes signed by both the owner and the enrolling device."""
    return _canonical_json(
        {
            "purpose": "jegpant.device.enrollment.v1",
            "instance_id": enrollment.instance_id,
            "device_id": enrollment.device_id,
            "device_public_key_b64": enrollment.device_public_key_b64,
            "device_key_algorithm": enrollment.device_key_algorithm,
            "scopes": sorted(enrollment.scopes),
            "enrollment_id": enrollment.enrollment_id,
            "issued_at": enrollment.issued_at,
            "expires_at": enrollment.expires_at,
        }
    )


def request_signing_bytes(request: SignedDeviceRequest) -> bytes:
    """Canonical bytes signed by the enrolled device for each request."""
    return _canonical_json(
        {
            "purpose": "jegpant.device.request.v1",
            "instance_id": request.instance_id,
            "device_id": request.device_id,
            "request_id": request.request_id,
            "method": request.method,
            "path": request.path,
            "issued_at": request.issued_at,
            "expires_at": request.expires_at,
            "body_sha256": request.body_sha256,
        }
    )


def revocation_signing_bytes(revocation: SignedDeviceRevocation) -> bytes:
    """Canonical bytes signed by the owner when revoking an enrolled device."""
    return _canonical_json(
        {
            "purpose": "jegpant.device.revocation.v1",
            "instance_id": revocation.instance_id,
            "device_id": revocation.device_id,
            "revocation_id": revocation.revocation_id,
            "issued_at": revocation.issued_at,
            "expires_at": revocation.expires_at,
        }
    )


def owner_approval_signing_bytes(approval: SignedOwnerApproval) -> bytes:
    """Canonical bytes signed by the owner for one memory-promotion approval."""
    return _canonical_json(
        {
            "purpose": "jegpant.memory.approval.v1",
            "instance_id": approval.instance_id,
            "proposal_id": approval.proposal_id,
            "approval_id": approval.approval_id,
            "key_id": approval.key_id,
            "expires_at": approval.expires_at,
        }
    )


class OwnerAuthorizationService:
    """Single-owner verifier whose state survives restarts when backed by SQLite."""

    def __init__(
        self,
        *,
        instance_id: str,
        owner_public_key: bytes,
        owner_key_algorithm: str = ED25519,
        clock: Callable[[], datetime] | None = None,
        max_request_ttl_seconds: int = 60,
        max_enrollment_ttl_seconds: int = 300,
        state_store: OwnerStateStore | None = None,
    ) -> None:
        try:
            UUID(instance_id)
        except (ValueError, TypeError) as exc:
            raise ValueError("instance_id must be a UUID") from exc
        self._owner_public_key_bytes = owner_public_key
        load_public_key(owner_public_key, owner_key_algorithm)
        if max_request_ttl_seconds <= 0 or max_enrollment_ttl_seconds <= 0:
            raise ValueError("authorization TTL limits must be positive")

        if state_store is None:
            # Lazy import avoids a module cycle: the SQLite adapter uses DeviceRecord.
            from .owner_state_store import InMemoryOwnerStateStore

            state_store = InMemoryOwnerStateStore(instance_id)
        if state_store.instance_id != instance_id:
            raise ValueError("owner state store belongs to a different instance")

        self.instance_id = instance_id
        self.owner_key_algorithm = owner_key_algorithm
        self.owner_key_fingerprint = hashlib.sha256(owner_public_key).hexdigest()
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_request_ttl_seconds = max_request_ttl_seconds
        self.max_enrollment_ttl_seconds = max_enrollment_ttl_seconds
        self.state_store = state_store
        self._lock = RLock()

    def _verify_owner(self, payload: bytes, signature_b64: str) -> None:
        signature = _decode_signature(signature_b64)
        try:
            verify_signature(
                self._owner_public_key_bytes,
                signature,
                payload,
                self.owner_key_algorithm,
            )
        except (InvalidSignature, ValueError):
            raise OwnerAuthorizationError("owner signature verification failed") from None

    @_synchronized
    def enroll_device(self, enrollment: DeviceEnrollment) -> DeviceRecord:
        if enrollment.instance_id != self.instance_id:
            raise OwnerAuthorizationError("enrolment belongs to a different instance")
        try:
            UUID(enrollment.device_id)
            UUID(enrollment.enrollment_id)
        except ValueError:
            raise OwnerAuthorizationError("device or enrollment ID is invalid") from None
        if not enrollment.scopes or not set(enrollment.scopes) <= ALLOWED_DEVICE_SCOPES:
            raise OwnerAuthorizationError("device requested unsupported permissions")
        if len(enrollment.scopes) != len(set(enrollment.scopes)):
            raise OwnerAuthorizationError("duplicate device permissions")
        if not _valid_window(
            enrollment.issued_at,
            enrollment.expires_at,
            now=self._clock(),
            max_ttl_seconds=self.max_enrollment_ttl_seconds,
        ):
            raise OwnerAuthorizationError(
                "enrollment request is expired or outside its time window"
            )

        payload = enrollment_signing_bytes(enrollment)
        self._verify_owner(payload, enrollment.owner_signature_b64)

        public_key_bytes = _decode_signature(enrollment.device_public_key_b64)
        try:
            load_public_key(public_key_bytes, enrollment.device_key_algorithm)
            device_device_proof = _decode_signature(enrollment.device_proof_b64)
            verify_signature(
                public_key_bytes,
                device_device_proof,
                payload,
                enrollment.device_key_algorithm,
            )
        except (InvalidSignature, ValueError):
            raise OwnerAuthorizationError("device key or possession proof is invalid") from None

        record = DeviceRecord(
            device_id=enrollment.device_id,
            public_key=public_key_bytes,
            scopes=frozenset(enrollment.scopes),
            enrolled_at=self._clock().astimezone(UTC).isoformat(),
            key_algorithm=enrollment.device_key_algorithm,
        )
        if not self.state_store.register_device(enrollment.enrollment_id, record):
            raise OwnerAuthorizationError(
                "device or enrollment request has already been used"
            )
        return record

    @_synchronized
    def verify_request(
        self,
        request: SignedDeviceRequest,
        *,
        body: bytes,
        required_scope: str,
    ) -> DeviceRecord:
        """Verify a request when its complete body is already in memory."""
        return self.verify_request_digest(
            request,
            body_sha256=hashlib.sha256(body).hexdigest(),
            required_scope=required_scope,
        )

    @_synchronized
    def verify_request_digest(
        self,
        request: SignedDeviceRequest,
        *,
        body_sha256: str,
        required_scope: str,
    ) -> DeviceRecord:
        """Verify a signed content digest without buffering a large request body."""
        if request.instance_id != self.instance_id:
            raise OwnerAuthorizationError("request belongs to a different instance")
        if request.method != request.method.upper() or not request.method:
            raise OwnerAuthorizationError("HTTP method must be uppercase")
        if (
            not request.path.startswith("/")
            or request.path.startswith("//")
            or "#" in request.path
            or "\\r" in request.path
            or "\\n" in request.path
        ):
            raise OwnerAuthorizationError("request path is not canonical")
        try:
            UUID(request.request_id)
        except ValueError:
            raise OwnerAuthorizationError("request ID must be a UUID") from None
        if not _valid_window(
            request.issued_at,
            request.expires_at,
            now=self._clock(),
            max_ttl_seconds=self.max_request_ttl_seconds,
        ):
            raise OwnerAuthorizationError(
                "request is expired or outside its time window"
            )
        if (
            not isinstance(body_sha256, str)
            or len(body_sha256) != 64
            or any(char not in "0123456789abcdef" for char in body_sha256)
            or body_sha256 != request.body_sha256
        ):
            raise OwnerAuthorizationError("request body digest mismatch")

        device = self.state_store.get_device(request.device_id)
        if device is None or device.revoked_at is not None:
            raise OwnerAuthorizationError("device is not enrolled or has been revoked")

        try:
            verify_signature(
                device.public_key,
                _decode_signature(request.signature_b64),
                request_signing_bytes(request),
                device.key_algorithm,
            )
        except (InvalidSignature, ValueError):
            raise OwnerAuthorizationError("device request signature is invalid") from None

        result = self.state_store.authorize_request(
            request.device_id,
            required_scope,
            request.request_id,
            request.expires_at,
        )
        if result == "replay":
            raise OwnerAuthorizationError("request replay detected")
        if result == "scope":
            raise OwnerAuthorizationError("device lacks the required permission")
        if result != "ok":
            raise OwnerAuthorizationError("device is not enrolled or has been revoked")
        return device

    @_synchronized
    def revoke_device(self, revocation: SignedDeviceRevocation) -> DeviceRecord:
        if revocation.instance_id != self.instance_id:
            raise OwnerAuthorizationError("revocation belongs to a different instance")
        try:
            UUID(revocation.revocation_id)
        except ValueError:
            raise OwnerAuthorizationError("revocation ID is invalid") from None
        if not _valid_window(
            revocation.issued_at,
            revocation.expires_at,
            now=self._clock(),
            max_ttl_seconds=self.max_request_ttl_seconds,
        ):
            raise OwnerAuthorizationError(
                "revocation is expired or outside its time window"
            )
        self._verify_owner(
            revocation_signing_bytes(revocation),
            revocation.owner_signature_b64,
        )

        revoked = self.state_store.revoke_device(
            revocation.device_id,
            revocation.revocation_id,
            self._clock().astimezone(UTC).isoformat(),
        )
        if revoked is None:
            raise OwnerAuthorizationError(
                "device is unknown or already revoked, or revocation was replayed"
            )
        return revoked

    @_synchronized
    def get_device(self, device_id: str) -> DeviceRecord | None:
        return self.state_store.get_device(device_id)


class Ed25519ApprovalVerifier:
    """Owner-signature verifier with persistent one-time approval consumption."""

    def __init__(
        self,
        *,
        instance_id: str,
        owner_public_key: bytes,
        key_id: str,
        owner_key_algorithm: str = ED25519,
        clock: Callable[[], datetime] | None = None,
        max_approval_ttl_seconds: int = 300,
        state_store: OwnerStateStore | None = None,
    ) -> None:
        try:
            UUID(instance_id)
        except (ValueError, TypeError) as exc:
            raise ValueError("instance_id must be a UUID") from exc
        self._owner_public_key_bytes = owner_public_key
        load_public_key(owner_public_key, owner_key_algorithm)
        if not key_id.strip() or max_approval_ttl_seconds <= 0:
            raise ValueError("key ID and positive approval TTL are required")
        if state_store is None:
            from .owner_state_store import InMemoryOwnerStateStore

            state_store = InMemoryOwnerStateStore(instance_id)
        if state_store.instance_id != instance_id:
            raise ValueError("owner state store belongs to a different instance")

        self.instance_id = instance_id
        self.key_id = key_id
        self.owner_key_algorithm = owner_key_algorithm
        self.owner_key_fingerprint = hashlib.sha256(owner_public_key).hexdigest()
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_approval_ttl_seconds = max_approval_ttl_seconds
        self.state_store = state_store
        self._lock = RLock()

    @_synchronized
    def verify(self, approval: SignedOwnerApproval) -> bool:
        if (
            approval.instance_id != self.instance_id
            or approval.key_id != self.key_id
            or not approval.approval_id
        ):
            return False
        try:
            expires = _parse_time(approval.expires_at)
            now = self._clock().astimezone(UTC)
            if (
                expires <= now
                or (expires - now).total_seconds() > self.max_approval_ttl_seconds
            ):
                return False
            verify_signature(
                self._owner_public_key_bytes,
                approval.signature,
                owner_approval_signing_bytes(approval),
                self.owner_key_algorithm,
            )
        except (OwnerAuthorizationError, InvalidSignature, TypeError, ValueError):
            return False
        return self.state_store.consume_approval(
            approval.approval_id, approval.expires_at
        )

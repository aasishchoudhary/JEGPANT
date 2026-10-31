"""Single-owner device enrolment and signed-request verification primitives.

The owner private key never enters this service. The service stores only public
keys and verifies short-lived, device-signed requests. Device state and replay
tracking are process-local prototypes; production requires transactional durable
state, rate limiting, audit logging, hardware-backed key adapters, and review.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .memory import SignedOwnerApproval


ALLOWED_DEVICE_SCOPES = frozenset(
    {
        "read_memory",
        "propose_memory",
        "read_evidence",
        "ingest_media",
        "run_analysis",
        "export_data",
        "manage_devices",
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
    """In-memory single-owner verifier for signed device operations."""

    def __init__(
        self,
        *,
        instance_id: str,
        owner_public_key: bytes,
        clock: Callable[[], datetime] | None = None,
        max_request_ttl_seconds: int = 60,
        max_enrollment_ttl_seconds: int = 300,
    ) -> None:
        try:
            UUID(instance_id)
            self._owner_key = Ed25519PublicKey.from_public_bytes(owner_public_key)
        except (ValueError, TypeError) as exc:
            raise ValueError("instance ID or owner Ed25519 public key is invalid") from exc
        if max_request_ttl_seconds <= 0 or max_enrollment_ttl_seconds <= 0:
            raise ValueError("authorization TTL limits must be positive")

        self.instance_id = instance_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_request_ttl_seconds = max_request_ttl_seconds
        self.max_enrollment_ttl_seconds = max_enrollment_ttl_seconds
        self._devices: dict[str, DeviceRecord] = {}
        self._enrollment_ids: set[str] = set()
        self._request_ids: set[str] = set()
        self._revocation_ids: set[str] = set()

    def _verify_owner(self, payload: bytes, signature_b64: str) -> None:
        signature = _decode_signature(signature_b64)
        try:
            self._owner_key.verify(signature, payload)
        except InvalidSignature:
            raise OwnerAuthorizationError("owner signature verification failed") from None

    def enroll_device(self, enrollment: DeviceEnrollment) -> DeviceRecord:
        if enrollment.instance_id != self.instance_id:
            raise OwnerAuthorizationError("enrolment belongs to a different instance")
        try:
            UUID(enrollment.device_id)
            UUID(enrollment.enrollment_id)
        except ValueError:
            raise OwnerAuthorizationError("device or enrollment ID is invalid") from None
        if enrollment.device_id in self._devices:
            raise OwnerAuthorizationError("device is already registered")
        if enrollment.enrollment_id in self._enrollment_ids:
            raise OwnerAuthorizationError("enrollment request has already been used")
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
            raise OwnerAuthorizationError("enrollment request is expired or outside its time window")

        payload = enrollment_signing_bytes(enrollment)
        self._verify_owner(payload, enrollment.owner_signature_b64)

        public_key_bytes = _decode_signature(enrollment.device_public_key_b64)
        try:
            device_public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except ValueError:
            raise OwnerAuthorizationError("device public key is invalid") from None
        try:
            device_public_key.verify(
                _decode_signature(enrollment.device_proof_b64), payload
            )
        except InvalidSignature:
            raise OwnerAuthorizationError("device key possession proof failed") from None

        record = DeviceRecord(
            device_id=enrollment.device_id,
            public_key=public_key_bytes,
            scopes=frozenset(enrollment.scopes),
            enrolled_at=self._clock().astimezone(UTC).isoformat(),
        )
        self._devices[record.device_id] = record
        self._enrollment_ids.add(enrollment.enrollment_id)
        return record

    def verify_request(
        self,
        request: SignedDeviceRequest,
        *,
        body: bytes,
        required_scope: str,
    ) -> DeviceRecord:
        if request.instance_id != self.instance_id:
            raise OwnerAuthorizationError("request belongs to a different instance")
        if request.method != request.method.upper() or not request.method:
            raise OwnerAuthorizationError("HTTP method must be uppercase")
        if (
            not request.path.startswith("/")
            or request.path.startswith("//")
            or "#" in request.path
            or "\r" in request.path
            or "\n" in request.path
        ):
            raise OwnerAuthorizationError("request path is not canonical")
        try:
            UUID(request.request_id)
        except ValueError:
            raise OwnerAuthorizationError("request ID must be a UUID") from None
        if request.request_id in self._request_ids:
            raise OwnerAuthorizationError("request replay detected")
        if not _valid_window(
            request.issued_at,
            request.expires_at,
            now=self._clock(),
            max_ttl_seconds=self.max_request_ttl_seconds,
        ):
            raise OwnerAuthorizationError("request is expired or outside its time window")

        actual_digest = hashlib.sha256(body).hexdigest()
        if actual_digest != request.body_sha256:
            raise OwnerAuthorizationError("request body digest mismatch")

        device = self._devices.get(request.device_id)
        if device is None or device.revoked_at is not None:
            raise OwnerAuthorizationError("device is not enrolled or has been revoked")
        if required_scope not in device.scopes:
            raise OwnerAuthorizationError("device lacks the required permission")

        try:
            Ed25519PublicKey.from_public_bytes(device.public_key).verify(
                _decode_signature(request.signature_b64),
                request_signing_bytes(request),
            )
        except InvalidSignature:
            raise OwnerAuthorizationError("device request signature is invalid") from None

        # Record only fully authenticated, correctly scoped requests.
        self._request_ids.add(request.request_id)
        return device

    def revoke_device(self, revocation: SignedDeviceRevocation) -> DeviceRecord:
        if revocation.instance_id != self.instance_id:
            raise OwnerAuthorizationError("revocation belongs to a different instance")
        try:
            UUID(revocation.revocation_id)
        except ValueError:
            raise OwnerAuthorizationError("revocation ID is invalid") from None
        if revocation.revocation_id in self._revocation_ids:
            raise OwnerAuthorizationError("revocation request has already been used")
        if not _valid_window(
            revocation.issued_at,
            revocation.expires_at,
            now=self._clock(),
            max_ttl_seconds=self.max_request_ttl_seconds,
        ):
            raise OwnerAuthorizationError("revocation is expired or outside its time window")
        self._verify_owner(
            revocation_signing_bytes(revocation),
            revocation.owner_signature_b64,
        )

        device = self._devices.get(revocation.device_id)
        if device is None:
            raise OwnerAuthorizationError("device is not enrolled")
        revoked = DeviceRecord(
            device_id=device.device_id,
            public_key=device.public_key,
            scopes=device.scopes,
            enrolled_at=device.enrolled_at,
            revoked_at=self._clock().astimezone(UTC).isoformat(),
        )
        self._devices[device.device_id] = revoked
        self._revocation_ids.add(revocation.revocation_id)
        return revoked

    def get_device(self, device_id: str) -> DeviceRecord | None:
        return self._devices.get(device_id)


class Ed25519ApprovalVerifier:
    """Owner-signature verifier for MemoryCatalog promotion approvals."""

    def __init__(
        self,
        *,
        instance_id: str,
        owner_public_key: bytes,
        key_id: str,
        clock: Callable[[], datetime] | None = None,
        max_approval_ttl_seconds: int = 300,
    ) -> None:
        try:
            self._owner_key = Ed25519PublicKey.from_public_bytes(owner_public_key)
            UUID(instance_id)
        except (ValueError, TypeError) as exc:
            raise ValueError("instance ID or owner public key is invalid") from exc
        if not key_id.strip() or max_approval_ttl_seconds <= 0:
            raise ValueError("key ID and positive approval TTL are required")
        self.instance_id = instance_id
        self.key_id = key_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self.max_approval_ttl_seconds = max_approval_ttl_seconds
        self._used_approval_ids: set[str] = set()

    def verify(self, approval: SignedOwnerApproval) -> bool:
        if (
            approval.instance_id != self.instance_id
            or approval.key_id != self.key_id
            or not approval.approval_id
            or approval.approval_id in self._used_approval_ids
        ):
            return False
        try:
            expires = _parse_time(approval.expires_at)
            now = self._clock().astimezone(UTC)
            signature = approval.signature
            if expires <= now or (expires - now).total_seconds() > self.max_approval_ttl_seconds:
                return False
            self._owner_key.verify(signature, owner_approval_signing_bytes(approval))
        except (OwnerAuthorizationError, InvalidSignature, TypeError, ValueError):
            return False
        self._used_approval_ids.add(approval.approval_id)
        return True

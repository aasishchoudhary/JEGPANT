"""Reviewed signature verification adapters for owner and device identities."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ED25519 = "ed25519"
ECDSA_P256 = "ecdsa_p256"
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({ED25519, ECDSA_P256})


def load_public_key(public_key_bytes: bytes, algorithm: str):
    """Load a constrained public key from raw Ed25519 or DER X.509 P-256."""
    if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError("unsupported signature algorithm")
    if not isinstance(public_key_bytes, bytes) or not public_key_bytes:
        raise ValueError("public key bytes are required")
    if algorithm == ED25519:
        try:
            return Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except ValueError as exc:
            raise ValueError("invalid Ed25519 public key") from exc

    try:
        public_key = serialization.load_der_public_key(public_key_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid DER-encoded ECDSA public key") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("ECDSA P-256 public key is required")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("only NIST P-256 ECDSA keys are accepted")
    return public_key


def verify_signature(
    public_key_bytes: bytes,
    signature: bytes,
    message: bytes,
    algorithm: str,
) -> None:
    """Verify a message signature or raise InvalidSignature/ValueError."""
    public_key = load_public_key(public_key_bytes, algorithm)
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("signature bytes are required")
    if algorithm == ED25519:
        public_key.verify(signature, message)
    elif algorithm == ECDSA_P256:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("unsupported signature algorithm")

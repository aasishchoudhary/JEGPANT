"""Chunked authenticated-encryption vault for original video/audio assets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MediaVaultError(RuntimeError):
    """Raised when encrypted media cannot be safely stored or retrieved."""


class MediaVaultIntegrityError(MediaVaultError):
    """Raised when encrypted media authentication or digest verification fails."""


class MediaKeyProvider(Protocol):
    def get_key(self, version: int) -> bytes:
        """Return an externally protected 256-bit data key."""
        ...


@dataclass(frozen=True, slots=True)
class MediaVaultEntry:
    asset_id: str
    size_bytes: int
    sha256: str
    key_version: int
    chunk_size: int
    chunk_count: int


class EncryptedMediaVault:
    """Stream large media assets into authenticated encrypted files.

    The caller must supply a protected key provider. This class does not
    implement a hardware-backed key provider, media retention policy, malware
    scanning, or an OS-level sandbox for downstream decoders.
    """

    MAGIC = b"JEGPANT_MEDIA_V1\n"
    SCHEMA_VERSION = 1
    KEY_BYTES = 32
    NONCE_BYTES = 12
    TAG_BYTES = 16
    HEADER_MAX_BYTES = 4096
    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
    MAX_CHUNKS = (1 << 32) - 2

    def __init__(
        self,
        root: str | Path,
        *,
        instance_id: str,
        key_provider: MediaKeyProvider,
        current_key_version: int = 1,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_asset_bytes: int = 8 * 1024 * 1024 * 1024,
    ) -> None:
        try:
            UUID(instance_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("instance_id must be a UUID") from exc
        if current_key_version <= 0:
            raise ValueError("current_key_version must be positive")
        if chunk_size < 64 * 1024 or chunk_size > 16 * 1024 * 1024:
            raise ValueError("chunk_size must be between 64 KiB and 16 MiB")
        if max_asset_bytes <= 0:
            raise ValueError("max_asset_bytes must be positive")

        requested_root = Path(root)
        if requested_root.is_symlink():
            raise MediaVaultError("media vault root may not be a symbolic link")
        requested_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = requested_root.resolve(strict=True)
        if not self.root.is_dir():
            raise MediaVaultError("media vault root must be a directory")

        self.instance_id = instance_id
        self.key_provider = key_provider
        self.current_key_version = current_key_version
        self.chunk_size = chunk_size
        self.max_asset_bytes = max_asset_bytes
        self._key(current_key_version)

    def _key(self, version: int) -> bytes:
        key = self.key_provider.get_key(version)
        if not isinstance(key, bytes) or len(key) != self.KEY_BYTES:
            raise ValueError("media key provider must return exactly 32 bytes")
        return key

    def _asset_path(self, asset_id: str) -> Path:
        try:
            UUID(asset_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("asset_id must be a UUID") from exc
        directory = self.root / asset_id[:2]
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved_directory = directory.resolve(strict=True)
        if self.root not in resolved_directory.parents:
            raise MediaVaultError("media asset path escaped the vault root")
        if directory.is_symlink():
            raise MediaVaultError("media asset directory may not be a symbolic link")
        return resolved_directory / f"{asset_id}.jmedia"

    @staticmethod
    def _fingerprint(path: Path) -> tuple[int, int, int]:
        stat = path.stat()
        return stat.st_size, stat.st_mtime_ns, getattr(stat, "st_ino", 0)

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _aad(self, header_digest: bytes, chunk_index: int, kind: bytes) -> bytes:
        return (
            b"JEGPANT-MEDIA-CHUNK\x00"
            + self.instance_id.encode("ascii")
            + b"\x00"
            + header_digest
            + b"\x00"
            + kind
            + struct.pack(">I", chunk_index)
        )

    @staticmethod
    def _nonce(base_nonce: bytes, chunk_index: int) -> bytes:
        value = int.from_bytes(base_nonce, "big") + chunk_index
        if value >= 1 << 96:
            raise MediaVaultIntegrityError("media nonce range overflow")
        return value.to_bytes(12, "big")

    @staticmethod
    def _canonical_json(payload: dict[str, object]) -> bytes:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def encrypt_file(
        self,
        source_path: str | Path,
        *,
        asset_id: str | None = None,
    ) -> MediaVaultEntry:
        """Encrypt a regular local file and return its opaque asset identifier."""
        source = Path(source_path)
        if source.is_symlink() or not source.is_file():
            raise MediaVaultError("source must be an existing regular non-symlink file")
        asset_id = asset_id or str(uuid4())
        destination = self._asset_path(asset_id)
        if destination.exists():
            raise FileExistsError("asset ID already exists in the media vault")

        try:
            before = self._fingerprint(source)
        except OSError:
            raise MediaVaultError("source file could not be inspected") from None
        size_bytes = before[0]
        if size_bytes <= 0:
            raise MediaVaultError("source file is empty")
        if size_bytes > self.max_asset_bytes:
            raise MediaVaultError("source file exceeds the configured size limit")

        try:
            source_digest = self._hash_file(source)
        except OSError:
            raise MediaVaultError("source file could not be read") from None
        chunk_count = (size_bytes + self.chunk_size - 1) // self.chunk_size
        if chunk_count > self.MAX_CHUNKS:
            raise MediaVaultError("source file requires too many encryption chunks")

        nonce_base = os.urandom(self.NONCE_BYTES)
        header = {
            "schema_version": self.SCHEMA_VERSION,
            "instance_id": self.instance_id,
            "asset_id": asset_id,
            "key_version": self.current_key_version,
            "size_bytes": size_bytes,
            "sha256": source_digest,
            "chunk_size": self.chunk_size,
            "chunk_count": chunk_count,
            "nonce_base": base64.b64encode(nonce_base).decode("ascii"),
        }
        header_bytes = self._canonical_json(header)
        if len(header_bytes) > self.HEADER_MAX_BYTES:
            raise MediaVaultError("media header exceeded its size limit")
        header_digest = hashlib.sha256(header_bytes).digest()
        cipher = AESGCM(self._key(self.current_key_version))
        second_digest = hashlib.sha256()
        total_written = 0
        created = False

        try:
            with source.open("rb") as input_stream, destination.open("xb") as output_stream:
                created = True
                output_stream.write(self.MAGIC)
                output_stream.write(struct.pack(">I", len(header_bytes)))
                output_stream.write(header_bytes)

                for chunk_index in range(chunk_count):
                    expected = min(
                        self.chunk_size, size_bytes - total_written
                    )
                    plaintext = input_stream.read(expected)
                    if len(plaintext) != expected:
                        raise MediaVaultError("source file changed during encryption")
                    second_digest.update(plaintext)
                    encrypted = cipher.encrypt(
                        self._nonce(nonce_base, chunk_index),
                        plaintext,
                        self._aad(header_digest, chunk_index, b"data"),
                    )
                    output_stream.write(encrypted)
                    total_written += len(plaintext)

                if input_stream.read(1):
                    raise MediaVaultError("source file grew during encryption")

                final_manifest = {
                    "complete": True,
                    "asset_id": asset_id,
                    "size_bytes": total_written,
                    "sha256": second_digest.hexdigest(),
                    "chunk_count": chunk_count,
                }
                final_plaintext = self._canonical_json(final_manifest)
                output_stream.write(
                    cipher.encrypt(
                        self._nonce(nonce_base, chunk_count),
                        final_plaintext,
                        self._aad(header_digest, chunk_count, b"final"),
                    )
                )
                output_stream.flush()
                os.fsync(output_stream.fileno())

            after = self._fingerprint(source)
            if before != after:
                raise MediaVaultError("source file changed during encryption")
            if total_written != size_bytes or second_digest.hexdigest() != source_digest:
                raise MediaVaultError("source file content changed during encryption")
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass
        except Exception:
            if created:
                destination.unlink(missing_ok=True)
            raise

        return MediaVaultEntry(
            asset_id=asset_id,
            size_bytes=size_bytes,
            sha256=source_digest,
            key_version=self.current_key_version,
            chunk_size=self.chunk_size,
            chunk_count=chunk_count,
        )

    def _read_header(self, encrypted_path: Path) -> tuple[dict[str, object], bytes, bytes]:
        with encrypted_path.open("rb") as stream:
            if stream.read(len(self.MAGIC)) != self.MAGIC:
                raise MediaVaultIntegrityError("media file header is invalid")
            length_bytes = stream.read(4)
            if len(length_bytes) != 4:
                raise MediaVaultIntegrityError("media header length is truncated")
            header_length = struct.unpack(">I", length_bytes)[0]
            if header_length <= 0 or header_length > self.HEADER_MAX_BYTES:
                raise MediaVaultIntegrityError("media header length is invalid")
            header_bytes = stream.read(header_length)
            if len(header_bytes) != header_length:
                raise MediaVaultIntegrityError("media header is truncated")
        try:
            header = json.loads(header_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MediaVaultIntegrityError("media header is not valid JSON") from None
        if not isinstance(header, dict):
            raise MediaVaultIntegrityError("media header must be an object")
        digest = hashlib.sha256(header_bytes).digest()
        return header, digest, header_bytes

    def decrypt_file(self, asset_id: str, destination_path: str | Path) -> Path:
        """Authenticate all chunks and the final manifest before publishing output."""
        encrypted_path = self._asset_path(asset_id)
        if encrypted_path.is_symlink() or not encrypted_path.is_file():
            raise FileNotFoundError(asset_id)
        target = Path(destination_path)
        if target.exists() or target.is_symlink():
            raise FileExistsError("destination already exists")
        target.parent.mkdir(parents=True, exist_ok=True)

        header, header_digest, _ = self._read_header(encrypted_path)
        required = {
            "schema_version",
            "instance_id",
            "asset_id",
            "key_version",
            "size_bytes",
            "sha256",
            "chunk_size",
            "chunk_count",
            "nonce_base",
        }
        if set(header) != required:
            raise MediaVaultIntegrityError("media header fields are invalid")
        if (
            header.get("schema_version") != self.SCHEMA_VERSION
            or header.get("instance_id") != self.instance_id
            or header.get("asset_id") != asset_id
        ):
            raise MediaVaultIntegrityError("media belongs to another instance or schema")
        try:
            key_version = int(header["key_version"])
            size_bytes = int(header["size_bytes"])
            chunk_size = int(header["chunk_size"])
            chunk_count = int(header["chunk_count"])
            source_digest = str(header["sha256"])
            nonce_base = base64.b64decode(header["nonce_base"], validate=True)
        except (TypeError, ValueError):
            raise MediaVaultIntegrityError("media header values are invalid") from None
        if (
            key_version <= 0
            or size_bytes <= 0
            or size_bytes > self.max_asset_bytes
            or chunk_size < 64 * 1024
            or chunk_size > 16 * 1024 * 1024
            or chunk_count != (size_bytes + chunk_size - 1) // chunk_size
            or chunk_count > self.MAX_CHUNKS
            or len(nonce_base) != self.NONCE_BYTES
            or len(source_digest) != 64
        ):
            raise MediaVaultIntegrityError("media header constraints are invalid")
        try:
            int(source_digest, 16)
        except ValueError:
            raise MediaVaultIntegrityError("media digest is invalid") from None

        final_manifest = {
            "complete": True,
            "asset_id": asset_id,
            "size_bytes": size_bytes,
            "sha256": source_digest,
            "chunk_count": chunk_count,
        }
        final_plaintext = self._canonical_json(final_manifest)
        expected_encrypted_size = (
            len(self.MAGIC)
            + 4
            + len(self._canonical_json(header))
            + size_bytes
            + self.TAG_BYTES * (chunk_count + 1)
            + len(final_plaintext)
        )
        try:
            if encrypted_path.stat().st_size != expected_encrypted_size:
                raise MediaVaultIntegrityError("encrypted media file size is inconsistent")
        except OSError:
            raise MediaVaultError("encrypted media file could not be inspected") from None

        cipher = AESGCM(self._key(key_version))
        digest = hashlib.sha256()
        total_written = 0
        temp_name: str | None = None

        try:
            with encrypted_path.open("rb") as input_stream:
                input_stream.seek(len(self.MAGIC) + 4 + len(self._canonical_json(header)))
                file_descriptor, temp_name = tempfile.mkstemp(
                    prefix=f".{target.name}.",
                    suffix=".decrypting",
                    dir=target.parent,
                )
                try:
                    os.fchmod(file_descriptor, 0o600)
                except OSError:
                    pass
                with os.fdopen(file_descriptor, "wb") as output_stream:
                    for chunk_index in range(chunk_count):
                        expected = min(chunk_size, size_bytes - total_written)
                        encrypted = input_stream.read(expected + self.TAG_BYTES)
                        if len(encrypted) != expected + self.TAG_BYTES:
                            raise MediaVaultIntegrityError("encrypted media chunk is truncated")
                        try:
                            plaintext = cipher.decrypt(
                                self._nonce(nonce_base, chunk_index),
                                encrypted,
                                self._aad(header_digest, chunk_index, b"data"),
                            )
                        except InvalidTag:
                            raise MediaVaultIntegrityError(
                                "media chunk authentication failed"
                            ) from None
                        if len(plaintext) != expected:
                            raise MediaVaultIntegrityError("decrypted chunk length is invalid")
                        output_stream.write(plaintext)
                        digest.update(plaintext)
                        total_written += len(plaintext)

                    encrypted_final = input_stream.read(len(final_plaintext) + self.TAG_BYTES)
                    if len(encrypted_final) != len(final_plaintext) + self.TAG_BYTES:
                        raise MediaVaultIntegrityError("final media manifest is truncated")
                    try:
                        final = cipher.decrypt(
                            self._nonce(nonce_base, chunk_count),
                            encrypted_final,
                            self._aad(header_digest, chunk_count, b"final"),
                        )
                    except InvalidTag:
                        raise MediaVaultIntegrityError(
                            "final media manifest authentication failed"
                        ) from None
                    if final != final_plaintext or input_stream.read(1):
                        raise MediaVaultIntegrityError("final media manifest is invalid")

                    if total_written != size_bytes or digest.hexdigest() != source_digest:
                        raise MediaVaultIntegrityError("decrypted media digest mismatch")
                    output_stream.flush()
                    os.fsync(output_stream.fileno())

            # Hard-link publishes atomically and refuses to overwrite an existing target.
            os.link(temp_name, target)
            os.unlink(temp_name)
            temp_name = None
            return target
        except Exception:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
            raise

    def delete(self, asset_id: str) -> bool:
        """Remove an encrypted asset; deletion is not a forensic-erasure guarantee."""
        path = self._asset_path(asset_id)
        if not path.exists():
            return False
        if path.is_symlink():
            raise MediaVaultError("refusing to delete a symbolic link")
        path.unlink()
        return True

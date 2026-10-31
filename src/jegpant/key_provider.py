"""Local owner-controlled key files for development and single-host prototypes.

This is NOT an HSM, Android Keystore, StrongBox, or confidential-computing
implementation. The host process can read the root key. Production should
inject a KMS/HSM-backed provider without writing its key material to disk.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class LocalKeyProviderError(RuntimeError):
    """Raised when the local development key file is unsafe or unavailable."""


class LocalFileKeyProvider:
    """Derive purpose-separated 256-bit data keys from one local root key.

    The root key is created only when explicitly permitted. The file must be a
    regular file with owner-only POSIX permissions and exactly 32 random bytes.
    """

    ROOT_KEY_BYTES = 32

    def __init__(
        self,
        path: str | Path,
        *,
        instance_id: str,
        purpose: str,
        create_if_missing: bool = False,
    ) -> None:
        if not instance_id.strip() or not purpose.strip():
            raise ValueError("instance_id and purpose are required")
        self.path = Path(path)
        self.instance_id = instance_id
        self.purpose = purpose
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._root_key = self._load_or_create(create_if_missing=create_if_missing)

    def _load_or_create(self, *, create_if_missing: bool) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            if not create_if_missing:
                raise LocalKeyProviderError("local root key file is missing") from None
            return self._create_exclusive()

        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise LocalKeyProviderError("local root key path is not a regular file")
            if os.name == "posix" and file_stat.st_mode & 0o077:
                raise LocalKeyProviderError(
                    "local root key permissions must be owner-only (0600)"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                key = stream.read(self.ROOT_KEY_BYTES + 1)
            if len(key) != self.ROOT_KEY_BYTES:
                raise LocalKeyProviderError("local root key must contain exactly 32 bytes")
            return key
        except OSError as exc:
            raise LocalKeyProviderError("local root key could not be read") from exc
        finally:
            os.close(descriptor)

    def _create_exclusive(self) -> bytes:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        key = os.urandom(self.ROOT_KEY_BYTES)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            # Another process won the first-run race; load only the resulting file.
            return self._load_or_create(create_if_missing=False)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            return key
        except OSError as exc:
            self.path.unlink(missing_ok=True)
            raise LocalKeyProviderError("local root key could not be created") from exc

    def get_key(self, version: int) -> bytes:
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("key version must be a positive integer")
        salt = hashlib.sha256(
            f"JEGPANT-LOCAL-SALT:{self.instance_id}".encode("utf-8")
        ).digest()
        info = (
            f"JEGPANT-LOCAL-DATA-KEY:{self.purpose}:v{version}".encode("utf-8")
        )
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(self._root_key)

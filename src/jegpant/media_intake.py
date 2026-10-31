"""Safe local media intake and ffprobe metadata extraction."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .video import VideoMetadata


class MediaIntakeError(RuntimeError):
    """Raised when a source asset cannot be safely inspected."""


class SourceChangedError(MediaIntakeError):
    """Raised if the source file changes during intake."""


@dataclass(frozen=True, slots=True)
class MediaIntakeResult:
    metadata: VideoMetadata
    size_bytes: int


def _file_fingerprint(path: Path) -> tuple[int, int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, getattr(stat, "st_ino", 0)


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def probe_local_video(
    path: str | Path,
    *,
    asset_id: str,
    ffprobe_path: str = "ffprobe",
    timeout_seconds: float = 30.0,
    max_file_bytes: int = 2 * 1024 * 1024 * 1024,
) -> MediaIntakeResult:
    """Hash and inspect a local video without invoking a shell.

    This function does not decode frames or perform person recognition. The
    subprocess should run with restricted OS permissions in production.
    """
    source = Path(path)
    if source.is_symlink():
        raise MediaIntakeError("symbolic-link media paths are not accepted")
    if not source.is_file():
        raise MediaIntakeError("media path must refer to an existing regular file")
    if not asset_id.strip():
        raise ValueError("asset_id must not be empty")
    if not ffprobe_path.strip():
        raise ValueError("ffprobe_path must not be empty")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive")

    try:
        resolved = source.resolve(strict=True)
        before = _file_fingerprint(resolved)
    except OSError:
        raise MediaIntakeError("media file could not be inspected") from None

    size_bytes = before[0]
    if size_bytes <= 0:
        raise MediaIntakeError("media file is empty")
    if size_bytes > max_file_bytes:
        raise MediaIntakeError("media file exceeds the configured size limit")

    try:
        digest = _sha256_file(resolved)
    except OSError:
        raise MediaIntakeError("media file could not be read") from None

    command = [
        ffprobe_path,
        "-v",
        "error",
        "-show_entries",
        "format=duration:stream=index,codec_type,codec_name,width,height,avg_frame_rate,duration",
        "-of",
        "json",
        str(resolved),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise MediaIntakeError("ffprobe exceeded the configured time limit") from None
    except OSError:
        raise MediaIntakeError("ffprobe could not be started") from None

    if completed.returncode != 0:
        # stderr may contain local paths and media metadata; do not expose it.
        raise MediaIntakeError("ffprobe could not inspect the media file")

    try:
        payload: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise MediaIntakeError("ffprobe returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise MediaIntakeError("ffprobe returned an unexpected metadata shape")

    try:
        after = _file_fingerprint(resolved)
    except OSError:
        raise SourceChangedError("source file changed or disappeared during intake") from None
    if before != after:
        raise SourceChangedError("source file changed during intake")

    try:
        metadata = VideoMetadata.from_ffprobe(
            payload, asset_id=asset_id, source_sha256=digest
        )
    except (ValueError, TypeError):
        raise MediaIntakeError("ffprobe metadata failed validation") from None

    return MediaIntakeResult(metadata=metadata, size_bytes=size_bytes)

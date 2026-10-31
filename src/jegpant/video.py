"""Post-hoc video metadata and timeline primitives.

This module does not decode video or identify people. It normalises metadata
returned by an external media probe and validates event time references.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any
from uuid import uuid4


def _parse_rate(value: str | None) -> float | None:
    if not value or value in {"0/0", "N/A"}:
        return None
    try:
        rate = float(Fraction(value))
    except (ValueError, ZeroDivisionError):
        return None
    return rate if rate > 0 else None


@dataclass(frozen=True, slots=True)
class VideoMetadata:
    asset_id: str
    duration_ms: int
    width: int
    height: int
    video_codec: str | None
    average_frame_rate: float | None
    has_audio: bool
    source_sha256: str

    def __post_init__(self) -> None:
        if not self.asset_id.strip():
            raise ValueError("asset_id must not be empty")
        if self.duration_ms <= 0:
            raise ValueError("duration_ms must be positive")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("video dimensions must be positive")
        if len(self.source_sha256) != 64:
            raise ValueError("source_sha256 must be a 64-character SHA-256 hex digest")
        try:
            int(self.source_sha256, 16)
        except ValueError as exc:
            raise ValueError("source_sha256 must be hexadecimal") from exc

    @classmethod
    def from_ffprobe(
        cls, payload: dict[str, Any], *, asset_id: str, source_sha256: str
    ) -> VideoMetadata:
        """Create metadata from ffprobe JSON using format and stream fields."""
        streams = payload.get("streams")
        if not isinstance(streams, list):
            raise TypeError("ffprobe payload must contain a streams list")
        video_stream = next(
            (stream for stream in streams if stream.get("codec_type") == "video"),
            None,
        )
        if video_stream is None:
            raise ValueError("no video stream found")

        format_data = payload.get("format") or {}
        duration = format_data.get("duration") or video_stream.get("duration")
        if duration is None:
            raise ValueError("video duration is missing")
        try:
            duration_ms = round(float(duration) * 1000)
            width = int(video_stream["width"])
            height = int(video_stream["height"])
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError("invalid duration or video dimensions in ffprobe data") from exc

        return cls(
            asset_id=asset_id,
            duration_ms=duration_ms,
            width=width,
            height=height,
            video_codec=video_stream.get("codec_name"),
            average_frame_rate=_parse_rate(video_stream.get("avg_frame_rate")),
            has_audio=any(
                stream.get("codec_type") == "audio" for stream in streams
            ),
            source_sha256=source_sha256,
        )


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    asset_id: str
    event_type: str
    start_ms: int
    end_ms: int
    observation: str
    extractor: str
    extractor_version: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    track_ids: tuple[str, ...] = field(default_factory=tuple)
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("asset_id", "event_type", "observation", "extractor"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        if self.start_ms < 0 or self.end_ms < self.start_ms:
            raise ValueError("event timestamps must satisfy 0 <= start_ms <= end_ms")


class VideoTimeline:
    """In-memory, source-linked timeline for one video asset."""

    def __init__(self, metadata: VideoMetadata) -> None:
        self.metadata = metadata
        self._events: list[TimelineEvent] = []

    def add(self, event: TimelineEvent) -> None:
        if event.asset_id != self.metadata.asset_id:
            raise ValueError("event belongs to a different asset")
        if event.end_ms > self.metadata.duration_ms:
            raise ValueError("event extends beyond the source video duration")
        if any(existing.event_id == event.event_id for existing in self._events):
            raise ValueError("event_id must be unique within a timeline")
        self._events.append(event)
        self._events.sort(key=lambda item: (item.start_ms, item.end_ms, item.event_id))

    def events(self) -> tuple[TimelineEvent, ...]:
        return tuple(self._events)

    def overlapping(self, start_ms: int, end_ms: int) -> tuple[TimelineEvent, ...]:
        if start_ms < 0 or end_ms < start_ms:
            raise ValueError("query interval must satisfy 0 <= start_ms <= end_ms")
        return tuple(
            event
            for event in self._events
            if event.start_ms <= end_ms and event.end_ms >= start_ms
        )

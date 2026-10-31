from jegpant.video import TimelineEvent, VideoMetadata, VideoTimeline

import pytest


HASH = "a" * 64


def sample_metadata():
    return VideoMetadata.from_ffprobe(
        {
            "format": {"duration": "12.500"},
            "streams": [
                {
                    "codec_type": "video",
                    "codec_name": "h264",
                    "width": 1920,
                    "height": 1080,
                    "avg_frame_rate": "30000/1001",
                },
                {"codec_type": "audio", "codec_name": "aac"},
            ],
        },
        asset_id="video-1",
        source_sha256=HASH,
    )


def test_ffprobe_metadata_is_normalised():
    metadata = sample_metadata()
    assert metadata.duration_ms == 12500
    assert metadata.width == 1920
    assert metadata.has_audio is True
    assert metadata.average_frame_rate == pytest.approx(29.97003, rel=1e-5)


def test_timeline_sorts_events_and_retrieves_overlaps():
    timeline = VideoTimeline(sample_metadata())
    later = TimelineEvent(
        "video-1", "door_closed", 5000, 5500, "Door closes.", "manual", "1"
    )
    earlier = TimelineEvent(
        "video-1", "person_enters", 1000, 1800, "Person enters.", "manual", "1"
    )
    timeline.add(later)
    timeline.add(earlier)

    assert [event.event_type for event in timeline.events()] == [
        "person_enters",
        "door_closed",
    ]
    assert len(timeline.overlapping(1700, 2000)) == 1


def test_event_outside_source_duration_is_rejected():
    timeline = VideoTimeline(sample_metadata())
    event = TimelineEvent(
        "video-1", "unknown", 12000, 13000, "Outside clip.", "test", "1"
    )
    with pytest.raises(ValueError):
        timeline.add(event)

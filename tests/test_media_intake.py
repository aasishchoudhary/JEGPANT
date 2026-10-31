import json
from types import SimpleNamespace

import pytest

from jegpant.media_intake import (
    MediaIntakeError,
    SourceChangedError,
    probe_local_video,
)


def ffprobe_payload():
    return {
        "format": {"duration": "8.25"},
        "streams": [
            {
                "index": 0,
                "codec_type": "video",
                "codec_name": "h264",
                "width": 1280,
                "height": 720,
                "avg_frame_rate": "25/1",
            },
            {"index": 1, "codec_type": "audio", "codec_name": "aac"},
        ],
    }


def test_probe_hashes_file_and_extracts_metadata(tmp_path, monkeypatch):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"test video bytes")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(ffprobe_payload()),
            stderr="",
        )

    monkeypatch.setattr("jegpant.media_intake.subprocess.run", fake_run)
    result = probe_local_video(path, asset_id="asset-1")

    assert result.metadata.duration_ms == 8250
    assert result.metadata.width == 1280
    assert result.metadata.has_audio is True
    assert len(result.metadata.source_sha256) == 64
    assert result.size_bytes == len(b"test video bytes")
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 30.0
    assert captured["command"][-1] == str(path.resolve())
    assert captured["command"][captured["command"].index("-protocol_whitelist") + 1] == "file"
    assert "-max_alloc" in captured["command"]


def test_probe_rejects_file_over_size_limit(tmp_path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"123456")
    with pytest.raises(MediaIntakeError, match="size limit"):
        probe_local_video(path, asset_id="asset-2", max_file_bytes=5)


def test_probe_rejects_empty_files(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with pytest.raises(MediaIntakeError, match="empty"):
        probe_local_video(path, asset_id="asset-3")


def test_probe_rejects_symbolic_link(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"video")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(MediaIntakeError, match="symbolic-link"):
        probe_local_video(link, asset_id="asset-4")


def test_probe_rejects_ffprobe_failure(tmp_path, monkeypatch):
    path = tmp_path / "bad.bin"
    path.write_bytes(b"not actually video")
    monkeypatch.setattr(
        "jegpant.media_intake.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="private path detail"
        ),
    )
    with pytest.raises(MediaIntakeError, match="could not inspect"):
        probe_local_video(path, asset_id="asset-5")


def test_probe_rejects_timeout(tmp_path, monkeypatch):
    import subprocess

    path = tmp_path / "slow.bin"
    path.write_bytes(b"video")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ffprobe", timeout=kwargs["timeout"])

    monkeypatch.setattr("jegpant.media_intake.subprocess.run", fake_run)
    with pytest.raises(MediaIntakeError, match="time limit"):
        probe_local_video(path, asset_id="asset-6")


def test_probe_detects_source_change_during_processing(tmp_path, monkeypatch):
    path = tmp_path / "changing.bin"
    path.write_bytes(b"before")

    def fake_run(*args, **kwargs):
        path.write_bytes(b"after with different length")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(ffprobe_payload()),
            stderr="",
        )

    monkeypatch.setattr("jegpant.media_intake.subprocess.run", fake_run)
    with pytest.raises(SourceChangedError, match="changed during intake"):
        probe_local_video(path, asset_id="asset-7")


def test_probe_rejects_invalid_ffprobe_json(tmp_path, monkeypatch):
    path = tmp_path / "invalid.bin"
    path.write_bytes(b"video")
    monkeypatch.setattr(
        "jegpant.media_intake.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="{bad json", stderr=""
        ),
    )
    with pytest.raises(MediaIntakeError, match="invalid JSON"):
        probe_local_video(path, asset_id="asset-8")


def test_probe_does_not_expose_ffprobe_stderr(tmp_path, monkeypatch):
    path = tmp_path / "broken.bin"
    path.write_bytes(b"video")
    monkeypatch.setattr(
        "jegpant.media_intake.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="/private/users/name/secret.mov"
        ),
    )
    with pytest.raises(MediaIntakeError) as error:
        probe_local_video(path, asset_id="asset-9")

    assert "private/users" not in str(error.value)


def test_probe_rejects_oversized_metadata_output(tmp_path, monkeypatch):
    path = tmp_path / "noisy.bin"
    path.write_bytes(b"video")
    monkeypatch.setattr(
        "jegpant.media_intake.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="x" * 100, stderr=""
        ),
    )
    with pytest.raises(MediaIntakeError, match="output exceeded"):
        probe_local_video(path, asset_id="asset-10", max_probe_output_bytes=10)

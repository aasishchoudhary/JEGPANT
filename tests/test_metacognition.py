import pytest

from jegpant.metacognition import Forecast, calibration_report, resolve_forecast


def forecast(probability=0.8):
    return Forecast(
        "f1",
        "The system will locate the event.",
        probability,
        "Event appears in the provided recording.",
        "2026-11-30",
    )


def test_brier_score_for_resolved_positive_forecast():
    resolved = resolve_forecast(
        forecast(0.8), outcome=True, verification_ref="review://verified-event"
    )
    assert resolved.brier_score == pytest.approx(0.04)


def test_brier_score_for_resolved_negative_forecast():
    resolved = resolve_forecast(
        forecast(0.8), outcome=False, verification_ref="review://not-found"
    )
    assert resolved.brier_score == pytest.approx(0.64)


def test_calibration_report_warns_about_small_samples():
    resolved = resolve_forecast(
        forecast(), outcome=True, verification_ref="review://verified"
    )
    report = calibration_report((resolved,))
    assert report.sample_size == 1
    assert "Small sample" in report.warning


def test_empty_calibration_report_does_not_invent_score():
    report = calibration_report(())
    assert report.sample_size == 0
    assert report.mean_brier_score is None

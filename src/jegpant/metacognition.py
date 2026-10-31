"""Metacognitive forecast tracking and outcome-based calibration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite


@dataclass(frozen=True, slots=True)
class Forecast:
    forecast_id: str
    proposition: str
    probability: float
    resolution_criteria: str
    resolves_after: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.forecast_id.strip() or not self.proposition.strip():
            raise ValueError("forecast_id and proposition must not be empty")
        if not isfinite(self.probability) or not 0.0 <= self.probability <= 1.0:
            raise ValueError("probability must be finite and between 0 and 1")
        if not self.resolution_criteria.strip() or not self.resolves_after.strip():
            raise ValueError("resolution criteria and deadline are required")


@dataclass(frozen=True, slots=True)
class ResolvedForecast:
    forecast: Forecast
    outcome: bool
    verification_ref: str
    resolved_at: str
    brier_score: float


def resolve_forecast(
    forecast: Forecast, *, outcome: bool, verification_ref: str
) -> ResolvedForecast:
    """Score a resolved binary forecast using the Brier score."""
    if not verification_ref.strip():
        raise ValueError("a verification reference is required")
    observed = 1.0 if outcome else 0.0
    score = (forecast.probability - observed) ** 2
    return ResolvedForecast(
        forecast=forecast,
        outcome=outcome,
        verification_ref=verification_ref,
        resolved_at=datetime.now(timezone.utc).isoformat(),
        brier_score=score,
    )


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    sample_size: int
    mean_brier_score: float | None
    warning: str


def calibration_report(
    forecasts: tuple[ResolvedForecast, ...],
) -> CalibrationReport:
    """Return proper-score summary with an explicit small-sample warning."""
    if not forecasts:
        return CalibrationReport(
            sample_size=0,
            mean_brier_score=None,
            warning="No resolved forecasts; calibration cannot yet be measured.",
        )
    mean_score = sum(item.brier_score for item in forecasts) / len(forecasts)
    warning = (
        "Small sample: do not infer stable calibration."
        if len(forecasts) < 30
        else "Interpret by domain and forecast horizon; aggregate scores can hide subgroup errors."
    )
    return CalibrationReport(
        sample_size=len(forecasts),
        mean_brier_score=mean_score,
        warning=warning,
    )

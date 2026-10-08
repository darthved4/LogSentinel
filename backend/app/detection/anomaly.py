from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.detection.models import Finding
from app.models import EventCreate


@dataclass(frozen=True)
class FeatureWindow:
    ip: str
    start: datetime
    end: datetime
    event_indices: list[int]
    values: list[float]


def build_feature_windows(
    events: list[EventCreate], window_seconds: int = 10
) -> list[FeatureWindow]:
    buckets: dict[tuple[str, int], list[tuple[int, EventCreate]]] = defaultdict(list)
    for index, event in enumerate(events):
        if not event.ip:
            continue
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        bucket = int(timestamp.timestamp()) // window_seconds
        buckets[(event.ip, bucket)].append((index, event))

    windows = []
    for (ip, bucket), grouped_events in sorted(buckets.items(), key=lambda item: item[0]):
        event_values = [event for _, event in grouped_events]
        request_count = len(event_values)
        error_count = sum(1 for event in event_values if (event.status or 0) >= 400)
        auth_failures = sum(
            1
            for event in event_values
            if event.status in {401, 403}
            and any(marker in (event.path or "").lower() for marker in ("login", "auth"))
        )
        distinct_paths = len({event.path for event in event_values if event.path})
        latencies = [
            event.latency_ms for event in event_values if event.latency_ms is not None
        ]
        average_latency = sum(latencies) / len(latencies) if latencies else 0.0
        start = min(event.timestamp for event in event_values)
        end = max(event.timestamp for event in event_values)
        windows.append(
            FeatureWindow(
                ip=ip,
                start=start,
                end=end,
                event_indices=[index for index, _ in grouped_events],
                values=[
                    float(request_count),
                    error_count / request_count,
                    auth_failures / request_count,
                    float(distinct_paths),
                    float(average_latency),
                ],
            )
        )
    return windows


class AnomalyDetector:
    def __init__(
        self,
        contamination: float = 0.05,
        window_seconds: int = 10,
        minimum_baseline_windows: int = 8,
    ) -> None:
        self.window_seconds = window_seconds
        self.minimum_baseline_windows = minimum_baseline_windows
        self.pipeline = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        contamination=contamination,
                        random_state=42,
                        n_estimators=150,
                    ),
                ),
            ]
        )
        self.is_fitted = False
        self.feature_upper_bounds: np.ndarray | None = None

    def fit(self, baseline_events: list[EventCreate]) -> int:
        windows = build_feature_windows(baseline_events, self.window_seconds)
        if len(windows) < self.minimum_baseline_windows:
            raise ValueError(
                f"At least {self.minimum_baseline_windows} baseline windows are required; "
                f"received {len(windows)}."
            )
        features = np.asarray([window.values for window in windows])
        self.pipeline.fit(features)
        # Isolation Forest needs variance to learn useful tree splits. A very quiet site can
        # produce near-identical baseline windows, so retain a robust learned upper envelope
        # for those cases. These floors prevent a zero-variance feature from becoming unusable.
        upper_floor = np.asarray([5.0, 0.25, 0.25, 3.0, 100.0])
        self.feature_upper_bounds = np.percentile(features, 95, axis=0) + np.maximum(
            np.std(features, axis=0) * 3,
            upper_floor,
        )
        self.is_fitted = True
        return len(windows)

    def detect(self, events: list[EventCreate]) -> list[Finding]:
        if not self.is_fitted:
            return []

        windows = build_feature_windows(events, self.window_seconds)
        if not windows:
            return []

        features = np.asarray([window.values for window in windows])
        predictions = self.pipeline.predict(features)
        scores = self.pipeline.decision_function(features)
        findings = []

        for window, prediction, score in zip(windows, predictions, scores, strict=True):
            values = np.asarray(window.values)
            baseline_deviation = bool(
                self.feature_upper_bounds is not None
                and np.any(values > self.feature_upper_bounds)
            )
            if prediction != -1 and not baseline_deviation:
                continue
            deviation_ratio = (
                float(np.max(values / self.feature_upper_bounds))
                if self.feature_upper_bounds is not None
                else 1.0
            )
            confidence = min(
                0.99,
                max(0.6 + abs(float(score)) * 3, min(0.95, 0.5 + deviation_ratio / 4)),
            )
            findings.append(
                Finding(
                    detector="ml",
                    rule_id="LS-ML-001",
                    type="behavioral_anomaly",
                    severity="high",
                    confidence=round(confidence, 3),
                    source_ip=window.ip,
                    first_seen=window.start,
                    last_seen=window.end,
                    event_count=len(window.event_indices),
                    evidence_indices=window.event_indices,
                    mitre_techniques=[],
                    summary=f"Traffic from {window.ip} differs significantly from the "
                    "learned baseline.",
                    recommended_actions=[
                        "Review the anomalous traffic window",
                        "Correlate this signal with deterministic rule findings",
                    ],
                    metadata={
                        "anomaly_score": round(float(score), 4),
                        "trigger": "isolation_forest"
                        if prediction == -1
                        else "baseline_deviation",
                        "request_count": int(window.values[0]),
                        "error_rate": round(window.values[1], 3),
                        "auth_failure_rate": round(window.values[2], 3),
                        "distinct_paths": int(window.values[3]),
                        "average_latency_ms": round(window.values[4], 2),
                    },
                )
            )
        return findings

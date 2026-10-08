from datetime import datetime, timedelta, timezone

from app.detection import DetectionEngine
from app.detection.anomaly import AnomalyDetector
from app.detection.rules import RuleConfig, RuleEngine
from app.models import EventCreate


START = datetime(2026, 10, 8, tzinfo=timezone.utc)


def make_event(
    second: float,
    *,
    ip: str = "192.0.2.10",
    path: str = "/",
    status: int = 200,
    latency_ms: float = 25,
    message: str = "HTTP request",
) -> EventCreate:
    return EventCreate(
        timestamp=START + timedelta(seconds=second),
        ip=ip,
        method="GET",
        path=path,
        status=status,
        latency_ms=latency_ms,
        user_agent="pytest",
        message=message,
        raw=f"GET {path} {status} {latency_ms}ms",
    )


def finding_types(events: list[EventCreate]) -> set[str]:
    return {finding.type for finding in RuleEngine().detect(events)}


def test_brute_force_rule() -> None:
    events = [
        make_event(second, path="/login", status=401, message="Login failed")
        for second in range(5)
    ]
    assert "brute_force" in finding_types(events)


def test_sql_injection_rule_decodes_url() -> None:
    events = [make_event(0, path="/search?q=%27+OR+1%3D1--")]
    assert "sql_injection" in finding_types(events)


def test_http_flood_rule() -> None:
    config = RuleConfig(flood_requests=20, flood_window_seconds=10)
    events = [make_event(index / 10, path="/api") for index in range(20)]
    findings = RuleEngine(config).detect(events)
    assert any(finding.type == "http_flood" for finding in findings)


def test_reconnaissance_rule() -> None:
    events = [make_event(index, path=f"/missing-{index}", status=404) for index in range(8)]
    assert "reconnaissance" in finding_types(events)


def test_normal_traffic_has_no_rule_findings() -> None:
    events = [make_event(index * 2, path="/products") for index in range(10)]
    assert RuleEngine().detect(events) == []


def test_isolation_forest_flags_traffic_spike() -> None:
    baseline = []
    for window in range(12):
        for offset in range(3):
            baseline.append(
                make_event(window * 10 + offset, ip="198.51.100.5", path="/products")
            )

    attack = [
        make_event(index / 10, path=f"/probe-{index % 15}", status=404, latency_ms=800)
        for index in range(100)
    ]
    detector = AnomalyDetector(contamination=0.1)
    engine = DetectionEngine(anomaly_detector=detector)
    assert engine.train_anomaly_detector(baseline) == 12

    result = engine.analyze(attack)
    assert any(finding.detector == "ml" for finding in result.findings)


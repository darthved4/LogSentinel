from datetime import datetime, timedelta, timezone

from app.detection import DetectionEngine
from app.models import EventCreate


def event(
    second: int,
    *,
    ip: str = "192.0.2.10",
    path: str = "/",
    status: int = 200,
    latency_ms: float = 30,
    message: str = "HTTP request",
) -> EventCreate:
    timestamp = datetime(2026, 10, 8, tzinfo=timezone.utc) + timedelta(seconds=second)
    return EventCreate(
        timestamp=timestamp,
        ip=ip,
        method="GET",
        path=path,
        status=status,
        latency_ms=latency_ms,
        user_agent="engine-test",
        message=message,
        raw=f"GET {path} {status} {latency_ms}ms",
    )


def main() -> None:
    baseline = []
    for window in range(12):
        for offset in range(3):
            baseline.append(event(window * 10 + offset, ip="198.51.100.5"))

    suspicious = [
        event(second, path="/login", status=401, message="Login failed")
        for second in range(6)
    ]
    suspicious.append(event(7, path="/search?q=%27+OR+1%3D1--"))
    suspicious.extend(
        event(second / 10, path="/api/products", latency_ms=900)
        for second in range(300)
    )

    engine = DetectionEngine()
    trained_windows = engine.train_anomaly_detector(baseline)
    result = engine.analyze(suspicious)

    print(f"ML baseline windows: {trained_windows}")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()


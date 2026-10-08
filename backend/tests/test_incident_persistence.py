from datetime import datetime, timedelta, timezone

import pytest

from app.detection import DetectionEngine
from app.incidents import build_incident_documents
from app.models import EventCreate


def make_event(second: int) -> EventCreate:
    return EventCreate(
        asset_id="demo-store",
        timestamp=datetime(2026, 10, 8, tzinfo=timezone.utc) + timedelta(seconds=second),
        source="demo-site",
        ip="203.0.113.66",
        method="POST",
        path="/login",
        status=401,
        latency_ms=30,
        user_agent="attack-simulator",
        message="Login failed",
        raw="POST /login 401",
    )


def test_build_incident_documents_preserves_event_ids() -> None:
    events = [make_event(second) for second in range(5)]
    result = DetectionEngine().analyze(events)

    documents = build_incident_documents(
        events=events,
        result=result,
        ingestion_batch_id="upload-001",
        event_ids=[f"event-{index}" for index in range(5)],
    )

    assert len(documents) == 1
    assert documents[0]["finding"]["type"] == "brute_force"
    assert documents[0]["evidence_event_ids"] == [
        "event-0",
        "event-1",
        "event-2",
        "event-3",
        "event-4",
    ]


def test_build_incident_documents_rejects_unaligned_event_ids() -> None:
    events = [make_event(second) for second in range(5)]
    result = DetectionEngine().analyze(events)

    with pytest.raises(ValueError, match="one entry for every input event"):
        build_incident_documents(
            events=events,
            result=result,
            ingestion_batch_id="upload-001",
            event_ids=["event-0"],
        )

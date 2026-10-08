"""The one-call handoff from ingestion to detection and incident persistence."""

from uuid import uuid4

from pydantic import BaseModel
from pymongo.asynchronous.database import AsyncDatabase

from app.detection import DetectionEngine
from app.detection.models import PersistedIncident
from app.incidents import persist_incidents
from app.models import EventCreate


class BatchProcessingResult(BaseModel):
    ingestion_batch_id: str
    event_ids: list[str]
    incidents: list[PersistedIncident]


async def process_event_batch(
    database: AsyncDatabase,
    events: list[EventCreate],
    *,
    ingestion_batch_id: str | None = None,
    engine: DetectionEngine | None = None,
) -> BatchProcessingResult:
    """Store one normalized upload, analyze it, and persist deduplicated incidents."""
    if not events:
        raise ValueError("Cannot process an empty event batch")

    batch_id = ingestion_batch_id or f"upload-{uuid4()}"
    documents = [
        event.model_dump() | {"ingestion_batch_id": batch_id} for event in events
    ]
    insert_result = await database.events.insert_many(documents)
    event_ids = [str(event_id) for event_id in insert_result.inserted_ids]

    detection_result = (engine or DetectionEngine()).analyze(events)
    incidents = await persist_incidents(
        database,
        events=events,
        result=detection_result,
        ingestion_batch_id=batch_id,
        event_ids=event_ids,
    )
    return BatchProcessingResult(
        ingestion_batch_id=batch_id,
        event_ids=event_ids,
        incidents=incidents,
    )

"""Persistence helpers shared by ingestion and incident API routes."""

from datetime import datetime, timezone
from hashlib import sha256

from pymongo import DESCENDING
from pymongo.asynchronous.database import AsyncDatabase

from app.detection.models import DetectionResult, PersistedIncident
from app.models import EventCreate


def build_incident_documents(
    *,
    events: list[EventCreate],
    result: DetectionResult,
    ingestion_batch_id: str,
    event_ids: list[str] | None = None,
) -> list[dict]:
    """Build deterministic incident documents from detection findings.

    `event_ids`, when supplied, must align with `events` by list index. Ingestion supplies
    these MongoDB IDs after persisting its parsed batch.
    """
    if not ingestion_batch_id.strip():
        raise ValueError("ingestion_batch_id cannot be empty")
    if event_ids is not None and len(event_ids) != len(events):
        raise ValueError("event_ids must have one entry for every input event")

    now = datetime.now(timezone.utc)
    documents = []
    for finding in result.findings:
        evidence_event_ids = (
            [event_ids[index] for index in finding.evidence_indices]
            if event_ids is not None
            else []
        )
        evidence_events = [events[index] for index in finding.evidence_indices]
        asset_id = evidence_events[0].asset_id if evidence_events else "demo-store"
        fingerprint_source = "|".join(
            [
                ingestion_batch_id,
                finding.rule_id,
                finding.source_ip or "unknown",
                finding.first_seen.isoformat(),
                finding.last_seen.isoformat(),
            ]
        )
        documents.append(
            {
                "ingestion_batch_id": ingestion_batch_id,
                "asset_id": asset_id,
                "fingerprint": sha256(fingerprint_source.encode()).hexdigest(),
                "finding": finding.model_dump(),
                "evidence_event_ids": evidence_event_ids,
                "status": "open",
                "created_at": now,
                "updated_at": now,
            }
        )
    return documents


async def persist_incidents(
    database: AsyncDatabase,
    *,
    events: list[EventCreate],
    result: DetectionResult,
    ingestion_batch_id: str,
    event_ids: list[str] | None = None,
) -> list[PersistedIncident]:
    """Upsert findings so a retried upload cannot create duplicate incidents."""
    documents = build_incident_documents(
        events=events,
        result=result,
        ingestion_batch_id=ingestion_batch_id,
        event_ids=event_ids,
    )
    persisted = []
    for document in documents:
        await database.incidents.update_one(
            {"fingerprint": document["fingerprint"]},
            {"$setOnInsert": document},
            upsert=True,
        )
        stored = await database.incidents.find_one(
            {"fingerprint": document["fingerprint"]}
        )
        if stored is None:
            raise RuntimeError("Incident upsert completed but the incident was not found")
        persisted.append(_serialize_incident(stored))
    return persisted


async def list_incidents(
    database: AsyncDatabase, limit: int = 50
) -> list[PersistedIncident]:
    cursor = database.incidents.find().sort("updated_at", DESCENDING).limit(limit)
    return [_serialize_incident(document) async for document in cursor]


def _serialize_incident(document: dict) -> PersistedIncident:
    document = dict(document)
    document["id"] = str(document.pop("_id"))
    return PersistedIncident(**document)

from contextlib import asynccontextmanager

from bson import ObjectId
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.database import close_database, connect_database, get_database
from app.detection import DetectionEngine, DetectionResult
from app.detection.models import PersistedIncident
from app.incidents import list_incidents, persist_incidents
from app.models import EventCreate, EventResponse


detection_engine = DetectionEngine()


class AnalyzeAndPersistRequest(BaseModel):
    ingestion_batch_id: str
    events: list[EventCreate]
    event_ids: list[str] | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    await connect_database()
    yield
    await close_database()


app = FastAPI(
    title="LogSentinel API",
    description="Log ingestion and threat-detection backend.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "LogSentinel API", "docs": "/docs"}


@app.get("/health")
async def health() -> dict[str, str]:
    database = get_database()
    await database.client.admin.command("ping")
    return {"status": "ok", "database": "connected"}


@app.post("/api/events", response_model=EventResponse, status_code=201)
async def create_event(event: EventCreate) -> EventResponse:
    database = get_database()
    document = event.model_dump()
    result = await database.events.insert_one(document)
    return EventResponse(id=str(result.inserted_id), **document)


@app.post("/api/detect", response_model=DetectionResult)
async def detect_events(events: list[EventCreate]) -> DetectionResult:
    return detection_engine.analyze(events)


@app.post("/api/incidents/analyze", response_model=list[PersistedIncident])
async def analyze_and_persist_incidents(
    request: AnalyzeAndPersistRequest,
) -> list[PersistedIncident]:
    result = detection_engine.analyze(request.events)
    return await persist_incidents(
        get_database(),
        events=request.events,
        result=result,
        ingestion_batch_id=request.ingestion_batch_id,
        event_ids=request.event_ids,
    )


@app.get("/api/incidents", response_model=list[PersistedIncident])
async def get_incidents(limit: int = 50) -> list[PersistedIncident]:
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")
    return await list_incidents(get_database(), limit=limit)


@app.get("/api/events/{event_id}", response_model=EventResponse)
async def get_event(event_id: str) -> EventResponse:
    if not ObjectId.is_valid(event_id):
        raise HTTPException(status_code=400, detail="Invalid event ID")

    database = get_database()
    document = await database.events.find_one({"_id": ObjectId(event_id)})
    if document is None:
        raise HTTPException(status_code=404, detail="Event not found")

    document["id"] = str(document.pop("_id"))
    return EventResponse(**document)

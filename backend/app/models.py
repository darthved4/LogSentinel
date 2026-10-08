from datetime import datetime, timezone

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    asset_id: str = "demo-store"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "demo-site"
    ip: str | None = None
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    latency_ms: float | None = None
    user_agent: str | None = None
    message: str
    raw: str


class EventResponse(EventCreate):
    id: str

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class Finding(BaseModel):
    detector: Literal["rule", "ml"]
    rule_id: str
    type: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    source_ip: str | None = None
    first_seen: datetime
    last_seen: datetime
    event_count: int = Field(ge=1)
    evidence_indices: list[int]
    mitre_techniques: list[str]
    summary: str
    recommended_actions: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    events_analyzed: int
    findings: list[Finding]


class PersistedIncident(BaseModel):
    id: str
    ingestion_batch_id: str
    asset_id: str
    fingerprint: str
    finding: Finding
    evidence_event_ids: list[str]
    status: Literal["open", "contained"]
    created_at: datetime
    updated_at: datetime

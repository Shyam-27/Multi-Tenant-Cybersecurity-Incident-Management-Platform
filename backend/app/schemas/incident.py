from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.incident import IncidentCategory, IncidentSeverity, IncidentStatus
from app.schemas.evidence import EvidenceResponse


class CreateIncidentRequest(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="", max_length=10000)
    category: IncidentCategory = Field(default=IncidentCategory.OTHER)
    severity: IncidentSeverity = Field(default=IncidentSeverity.MEDIUM)
    assigned_to_id: UUID | None = None


class UpdateIncidentRequest(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=10000)
    category: IncidentCategory | None = None
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    assigned_to_id: UUID | None = None


class CreateNoteRequest(BaseModel):
    content: str = Field(min_length=1, max_length=10000)


class IncidentNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    incident_id: UUID
    author_id: UUID
    author_name: str | None = None
    content: str
    created_at: datetime


class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    title: str
    description: str
    category: str
    severity: str
    status: str
    assigned_to_id: UUID | None = None
    assigned_to_name: str | None = None
    created_by_id: UUID
    created_by_name: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    notes: list[IncidentNoteResponse] = []
    evidence: list[EvidenceResponse] = []


class IncidentListResponse(BaseModel):
    items: list[IncidentDetailResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class IncidentMetricsResponse(BaseModel):
    total: int
    open: int
    investigating: int
    contained: int
    resolved: int
    closed: int
    critical_and_high: int

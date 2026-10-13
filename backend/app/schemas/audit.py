from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.audit import ActorType, AuditOutcome


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID | None
    actor_user_id: UUID | None
    actor_user_name: str | None = None
    actor_user_email: str | None = None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    occurred_at: datetime
    request_id: str | None
    source_ip: str | None
    user_agent: str | None
    details: dict[str, Any]
    previous_hash: str | None
    event_hash: str | None


class AuditEventListResponse(BaseModel):
    items: list[AuditEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AuditVerificationResult(BaseModel):
    verified_count: int
    is_valid: bool
    broken_event_id: UUID | None = None
    details: str

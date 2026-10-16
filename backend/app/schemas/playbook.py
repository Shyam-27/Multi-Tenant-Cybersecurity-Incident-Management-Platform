from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class CreatePlaybookRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    trigger_event: str = Field(default="MANUAL", description="MANUAL, INCIDENT_CRITICAL, MALICIOUS_IOC_DETECTED")
    actions: list[dict[str, Any]] = Field(description="List of action definitions")
    is_enabled: bool = Field(default=True)
    is_dry_run: bool = Field(default=True)
    requires_approval: bool = Field(default=True)


class UpdatePlaybookRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    actions: list[dict[str, Any]] | None = None
    is_enabled: bool | None = None
    is_dry_run: bool | None = None
    requires_approval: bool | None = None


class TriggerExecutionRequest(BaseModel):
    incident_id: UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    override_dry_run: bool | None = None


class ApprovalDecisionRequest(BaseModel):
    notes: str | None = Field(default=None, max_length=1000)


class PlaybookResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    description: str
    trigger_event: str
    actions: list[dict[str, Any]]
    is_enabled: bool
    is_dry_run: bool
    requires_approval: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApprovalResponse(BaseModel):
    id: UUID
    status: str
    required_role: str
    decided_by_id: UUID | None
    decision_notes: str | None
    decided_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class ExecutionResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    playbook_id: UUID
    incident_id: UUID | None
    triggered_by_id: UUID
    trigger_source: str
    status: str
    is_dry_run: bool
    parameters: dict[str, Any]
    step_results: list[dict[str, Any]]
    error_summary: str | None
    created_at: datetime
    completed_at: datetime | None
    approval: ApprovalResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class ExecutionListResponse(BaseModel):
    items: list[ExecutionResponse]
    total: int
    page: int
    page_size: int
    pages: int

from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class BackgroundJobResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    job_type: str
    status: str
    resource_id: str | None
    parameters: dict[str, Any]
    result_summary: dict[str, Any]
    error_message: str | None
    attempt_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class JobListResponse(BaseModel):
    items: list[BackgroundJobResponse]
    total: int
    page: int
    page_size: int
    pages: int


class AsyncIOCEnrichResponse(BaseModel):
    message: str
    job_id: UUID
    ioc_id: UUID
    status: str

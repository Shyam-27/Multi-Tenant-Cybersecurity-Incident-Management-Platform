from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class CreateDestinationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    destination_type: str = Field(description="SPLUNK_HEC, ELASTIC_SIEM, MS_TEAMS, or SLACK")
    endpoint_url: str = Field(min_length=5, max_length=1024)
    secret_token: str | None = Field(default=None, max_length=512)
    is_enabled: bool = Field(default=True)
    event_types: list[str] = Field(default_factory=list, description="Subscribed event types")


class UpdateDestinationRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    endpoint_url: str | None = Field(default=None, max_length=1024)
    secret_token: str | None = Field(default=None, max_length=512)
    is_enabled: bool | None = None
    event_types: list[str] | None = None


class DestinationResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    destination_type: str
    endpoint_url: str
    is_enabled: bool
    event_types: list[str]
    has_secret: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeliveryResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    destination_id: UUID
    event_type: str
    payload: dict[str, Any]
    status: str
    attempt_count: int
    max_attempts: int
    next_retry_at: datetime | None
    last_attempt_at: datetime | None
    response_status_code: int | None
    error_summary: str | None
    last_error_category: str | None = None
    is_terminal_failure: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeliveryListResponse(BaseModel):
    items: list[DeliveryResponse]
    total: int
    page: int
    page_size: int
    pages: int


class TestWebhookResponse(BaseModel):
    success: bool
    status_code: int | None
    error: str | None
    message: str


class RetryDeliveryResponse(BaseModel):
    message: str
    delivery: DeliveryResponse


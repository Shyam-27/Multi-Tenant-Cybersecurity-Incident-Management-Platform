from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

from app.models.ioc import IndicatorType, ThreatSeverity, ThreatVerdict


class CreateIOCRequest(BaseModel):
    indicator_type: str = Field(description="IPV4, IPV6, DOMAIN, URL, SHA256, SHA1, or MD5")
    value: str = Field(min_length=1, max_length=512)
    incident_id: UUID | None = Field(default=None)
    notes: str | None = Field(default=None, max_length=2000)
    source: str = Field(default="MANUAL", max_length=60)
    external_reference: str | None = Field(default=None, max_length=255)


class UpdateIOCRequest(BaseModel):
    is_false_positive: bool | None = None
    notes: str | None = None
    threat_verdict: str | None = None
    severity: str | None = None


class EnrichIOCRequest(BaseModel):
    providers: list[str] | None = Field(default=None, description="List of providers: VirusTotal, AbuseIPDB, AlienVaultOTX")
    force_refresh: bool = Field(default=False)


class IOCResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    indicator_type: str
    value: str
    threat_verdict: str
    confidence_score: int
    severity: str
    source: str
    external_reference: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    enriched_at: datetime | None
    expires_at: datetime | None
    incident_id: UUID | None
    is_false_positive: bool
    notes: str | None
    raw_enrichment_data: dict[str, Any]
    created_by_id: UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int
    pages: int

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.database import Base


class IndicatorType(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5"


class ThreatVerdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class IndicatorOfCompromise(Base):
    """Tenant-scoped Indicator of Compromise (IOC) record."""

    __tablename__ = "indicators_of_compromise"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    threat_verdict: Mapped[str] = mapped_column(String(20), nullable=False, default=ThreatVerdict.UNKNOWN.value, index=True)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # 0 to 100
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=ThreatSeverity.UNKNOWN.value)
    source: Mapped[str] = mapped_column(String(60), nullable=False, default="MANUAL")
    external_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    incident_id: Mapped[UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_enrichment_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    created_by_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    tenant: Mapped["Tenant"] = relationship()
    incident: Mapped["Incident | None"] = relationship()
    created_by: Mapped["User | None"] = relationship()

    __table_args__ = (
        UniqueConstraint("tenant_id", "indicator_type", "value", name="uq_tenant_indicator_type_value"),
        Index("ix_iocs_tenant_type", "tenant_id", "indicator_type"),
        Index("ix_iocs_tenant_verdict", "tenant_id", "threat_verdict"),
        Index("ix_iocs_tenant_created", "tenant_id", "created_at"),
    )

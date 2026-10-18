from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.database import Base


class DestinationType(str, Enum):
    SPLUNK_HEC = "SPLUNK_HEC"
    ELASTIC_SIEM = "ELASTIC_SIEM"
    MS_TEAMS = "MS_TEAMS"
    SLACK = "SLACK"


class DeliveryStatus(str, Enum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    RETRYING = "RETRYING"


class NotificationDestination(Base):
    """Configured SIEM or webhook endpoint for alert dispatch."""

    __tablename__ = "notification_destinations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    destination_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    endpoint_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    secret_token: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    event_types: Mapped[list[str]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    created_by_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    tenant: Mapped["Tenant"] = relationship()
    created_by: Mapped["User | None"] = relationship()
    deliveries: Mapped[list["WebhookDelivery"]] = relationship(back_populates="destination", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_destinations_tenant_type", "tenant_id", "destination_type"),
        Index("ix_destinations_tenant_enabled", "tenant_id", "is_enabled"),
    )


class WebhookDelivery(Base):
    """Durable audit and retry record of an outbound webhook dispatch."""

    __tablename__ = "webhook_deliveries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    destination_id: Mapped[UUID] = mapped_column(ForeignKey("notification_destinations.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=DeliveryStatus.PENDING.value, index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_error_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_terminal_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    destination: Mapped["NotificationDestination"] = relationship(back_populates="deliveries")
    tenant: Mapped["Tenant"] = relationship()

    __table_args__ = (
        Index("ix_deliveries_tenant_status", "tenant_id", "status"),
        Index("ix_deliveries_tenant_created", "tenant_id", "created_at"),
    )

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentCategory(str, Enum):
    ACCOUNT_COMPROMISE = "ACCOUNT_COMPROMISE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    RANSOMWARE = "RANSOMWARE"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    OTHER = "OTHER"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(80), nullable=False, default=IncidentCategory.OTHER.value)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=IncidentSeverity.MEDIUM.value)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=IncidentStatus.OPEN.value)
    assigned_to_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    tenant: Mapped["Tenant"] = relationship()
    assigned_to: Mapped["User | None"] = relationship(foreign_keys=[assigned_to_id])
    created_by: Mapped["User"] = relationship(foreign_keys=[created_by_id])
    notes: Mapped[list["IncidentNote"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentNote.created_at.asc()",
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        "Evidence",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="Evidence.created_at.asc()",
    )

    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_tenant_severity", "tenant_id", "severity"),
        Index("ix_incidents_tenant_assigned", "tenant_id", "assigned_to_id"),
        Index("ix_incidents_tenant_created", "tenant_id", "created_at"),
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    incident: Mapped["Incident"] = relationship(back_populates="notes")
    author: Mapped["User"] = relationship()

    __table_args__ = (
        Index("ix_incident_notes_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_incident_notes_created_at", "created_at"),
    )

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.database import Base


class PlaybookTrigger(str, Enum):
    MANUAL = "MANUAL"
    INCIDENT_CRITICAL = "INCIDENT_CRITICAL"
    MALICIOUS_IOC_DETECTED = "MALICIOUS_IOC_DETECTED"


class PlaybookActionType(str, Enum):
    REVOKE_USER_SESSIONS = "REVOKE_USER_SESSIONS"
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    BLOCK_IP = "BLOCK_IP"


class ExecutionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ResponsePlaybook(Base):
    """Playbook defining automated or approved incident response procedures."""

    __tablename__ = "response_playbooks"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    trigger_event: Mapped[str] = mapped_column(String(50), nullable=False, default=PlaybookTrigger.MANUAL.value, index=True)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)  # Safe default: dry-run enabled
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)  # Safe default: human approval required
    created_by_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    tenant: Mapped["Tenant"] = relationship()
    created_by: Mapped["User | None"] = relationship()
    executions: Mapped[list["PlaybookExecution"]] = relationship(back_populates="playbook", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_playbooks_tenant_trigger", "tenant_id", "trigger_event"),
        Index("ix_playbooks_tenant_enabled", "tenant_id", "is_enabled"),
    )


class PlaybookExecution(Base):
    """Audit and tracking record for a playbook invocation."""

    __tablename__ = "playbook_executions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    playbook_id: Mapped[UUID] = mapped_column(ForeignKey("response_playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id: Mapped[UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    triggered_by_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    trigger_source: Mapped[str] = mapped_column(String(50), nullable=False, default="MANUAL")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default=ExecutionStatus.PENDING_APPROVAL.value, index=True)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    step_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    error_summary: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Phase 7A: Privileged-Action Step-Up Verification
    step_up_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    step_up_verified_by_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    step_up_method: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Relationships
    playbook: Mapped["ResponsePlaybook"] = relationship(back_populates="executions")
    tenant: Mapped["Tenant"] = relationship()
    incident: Mapped["Incident | None"] = relationship()
    triggered_by: Mapped["User"] = relationship(foreign_keys=[triggered_by_id])
    step_up_verified_by: Mapped["User | None"] = relationship(foreign_keys=[step_up_verified_by_id])
    approval: Mapped["PlaybookApproval | None"] = relationship(back_populates="execution", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_executions_tenant_status", "tenant_id", "status"),
        Index("ix_executions_tenant_created", "tenant_id", "created_at"),
    )


class PlaybookApproval(Base):
    """Authorization gating record required before disruptive playbook execution."""

    __tablename__ = "playbook_approvals"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    execution_id: Mapped[UUID] = mapped_column(ForeignKey("playbook_executions.id", ondelete="CASCADE"), nullable=False, unique=True)
    required_role: Mapped[str] = mapped_column(String(30), nullable=False, default="TENANT_ADMIN")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=ApprovalStatus.PENDING.value, index=True)
    decided_by_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Phase 7A: Privileged-Action Step-Up Verification
    step_up_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    step_up_method: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Relationships
    execution: Mapped["PlaybookExecution"] = relationship(back_populates="approval")
    tenant: Mapped["Tenant"] = relationship()
    decided_by: Mapped["User | None"] = relationship()

    __table_args__ = (
        Index("ix_approvals_tenant_status", "tenant_id", "status"),
    )

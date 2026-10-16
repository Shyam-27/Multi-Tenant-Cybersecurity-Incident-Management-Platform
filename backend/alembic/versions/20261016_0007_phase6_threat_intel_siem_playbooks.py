"""Phase 6: threat intelligence feeds, siem alerting, and response playbooks

Revision ID: 20261016_0007
Revises: 20261013_0006
Create Date: 2026-10-16 13:30:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261016_0007"
down_revision = "20261013_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. indicators_of_compromise
    op.create_table(
        "indicators_of_compromise",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("indicator_type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("threat_verdict", sa.String(20), server_default="UNKNOWN", nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="0", nullable=False),
        sa.Column("severity", sa.String(20), server_default="UNKNOWN", nullable=False),
        sa.Column("source", sa.String(60), server_default="MANUAL", nullable=False),
        sa.Column("external_reference", sa.String(255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("is_false_positive", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "raw_enrichment_data",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("tenant_id", "indicator_type", "value", name="uq_tenant_indicator_type_value"),
    )
    op.create_index("ix_iocs_tenant_id", "indicators_of_compromise", ["tenant_id"])
    op.create_index("ix_iocs_indicator_type", "indicators_of_compromise", ["indicator_type"])
    op.create_index("ix_iocs_value", "indicators_of_compromise", ["value"])
    op.create_index("ix_iocs_threat_verdict", "indicators_of_compromise", ["threat_verdict"])
    op.create_index("ix_iocs_incident_id", "indicators_of_compromise", ["incident_id"])
    op.create_index("ix_iocs_tenant_type", "indicators_of_compromise", ["tenant_id", "indicator_type"])
    op.create_index("ix_iocs_tenant_verdict", "indicators_of_compromise", ["tenant_id", "threat_verdict"])
    op.create_index("ix_iocs_tenant_created", "indicators_of_compromise", ["tenant_id", "created_at"])

    # 2. notification_destinations
    op.create_table(
        "notification_destinations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("destination_type", sa.String(30), nullable=False),
        sa.Column("endpoint_url", sa.String(1024), nullable=False),
        sa.Column("secret_token", sa.String(512), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "event_types",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_destinations_tenant_id", "notification_destinations", ["tenant_id"])
    op.create_index("ix_destinations_destination_type", "notification_destinations", ["destination_type"])
    op.create_index("ix_destinations_tenant_type", "notification_destinations", ["tenant_id", "destination_type"])
    op.create_index("ix_destinations_tenant_enabled", "notification_destinations", ["tenant_id", "is_enabled"])

    # 3. webhook_deliveries
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("destination_id", sa.Uuid(), sa.ForeignKey("notification_destinations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), server_default="PENDING", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="3", nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("response_status_code", sa.Integer(), nullable=True),
        sa.Column("error_summary", sa.String(1024), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_deliveries_tenant_id", "webhook_deliveries", ["tenant_id"])
    op.create_index("ix_deliveries_destination_id", "webhook_deliveries", ["destination_id"])
    op.create_index("ix_deliveries_event_type", "webhook_deliveries", ["event_type"])
    op.create_index("ix_deliveries_status", "webhook_deliveries", ["status"])
    op.create_index("ix_deliveries_idempotency_key", "webhook_deliveries", ["idempotency_key"])
    op.create_index("ix_deliveries_next_retry_at", "webhook_deliveries", ["next_retry_at"])
    op.create_index("ix_deliveries_tenant_status", "webhook_deliveries", ["tenant_id", "status"])
    op.create_index("ix_deliveries_tenant_created", "webhook_deliveries", ["tenant_id", "created_at"])

    # 4. response_playbooks
    op.create_table(
        "response_playbooks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("trigger_event", sa.String(50), server_default="MANUAL", nullable=False),
        sa.Column(
            "actions",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("is_enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("is_dry_run", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("requires_approval", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_playbooks_tenant_id", "response_playbooks", ["tenant_id"])
    op.create_index("ix_playbooks_trigger_event", "response_playbooks", ["trigger_event"])
    op.create_index("ix_playbooks_tenant_trigger", "response_playbooks", ["tenant_id", "trigger_event"])
    op.create_index("ix_playbooks_tenant_enabled", "response_playbooks", ["tenant_id", "is_enabled"])

    # 5. playbook_executions
    op.create_table(
        "playbook_executions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("playbook_id", sa.Uuid(), sa.ForeignKey("response_playbooks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("triggered_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("trigger_source", sa.String(50), server_default="MANUAL", nullable=False),
        sa.Column("status", sa.String(30), server_default="PENDING_APPROVAL", nullable=False),
        sa.Column("is_dry_run", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "parameters",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "step_results",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("error_summary", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_executions_tenant_id", "playbook_executions", ["tenant_id"])
    op.create_index("ix_executions_playbook_id", "playbook_executions", ["playbook_id"])
    op.create_index("ix_executions_incident_id", "playbook_executions", ["incident_id"])
    op.create_index("ix_executions_triggered_by_id", "playbook_executions", ["triggered_by_id"])
    op.create_index("ix_executions_status", "playbook_executions", ["status"])
    op.create_index("ix_executions_tenant_status", "playbook_executions", ["tenant_id", "status"])
    op.create_index("ix_executions_tenant_created", "playbook_executions", ["tenant_id", "created_at"])

    # 6. playbook_approvals
    op.create_table(
        "playbook_approvals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("execution_id", sa.Uuid(), sa.ForeignKey("playbook_executions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("required_role", sa.String(30), server_default="TENANT_ADMIN", nullable=False),
        sa.Column("status", sa.String(20), server_default="PENDING", nullable=False),
        sa.Column("decided_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decision_notes", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("execution_id", name="uq_playbook_approval_execution_id"),
    )
    op.create_index("ix_approvals_tenant_id", "playbook_approvals", ["tenant_id"])
    op.create_index("ix_approvals_execution_id", "playbook_approvals", ["execution_id"])
    op.create_index("ix_approvals_status", "playbook_approvals", ["status"])
    op.create_index("ix_approvals_tenant_status", "playbook_approvals", ["tenant_id", "status"])


def downgrade() -> None:
    op.drop_table("playbook_approvals")
    op.drop_table("playbook_executions")
    op.drop_table("response_playbooks")
    op.drop_table("webhook_deliveries")
    op.drop_table("notification_destinations")
    op.drop_table("indicators_of_compromise")

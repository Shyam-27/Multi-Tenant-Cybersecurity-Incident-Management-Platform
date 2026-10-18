"""Phase 7C: Automated Incident Response & Dynamic Playbook Triggers

Revision ID: 20261018_0010
Revises: 20261018_0009
Create Date: 2026-10-18 03:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20261018_0010"
down_revision = "20261018_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")

    # 1. Add trigger configuration & versioning to response_playbooks
    op.add_column(
        "response_playbooks",
        sa.Column("trigger_conditions", json_type, server_default="{}", nullable=False),
    )
    op.add_column(
        "response_playbooks",
        sa.Column("rule_version", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "response_playbooks",
        sa.Column("cooldown_seconds", sa.Integer(), server_default="300", nullable=False),
    )

    # 2. Add trigger event identity & reasoning to playbook_executions
    op.add_column(
        "playbook_executions",
        sa.Column("trigger_event_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "playbook_executions",
        sa.Column("trigger_reason", sa.String(length=512), nullable=True),
    )
    op.create_index("ix_executions_trigger_event_id", "playbook_executions", ["trigger_event_id"])
    op.create_unique_constraint(
        "uq_execution_tenant_trigger_event",
        "playbook_executions",
        ["tenant_id", "trigger_event_id"],
    )
    op.create_index(
        "ix_executions_tenant_playbook_incident",
        "playbook_executions",
        ["tenant_id", "playbook_id", "incident_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_executions_tenant_playbook_incident", table_name="playbook_executions")
    op.drop_constraint("uq_execution_tenant_trigger_event", "playbook_executions", type_="unique")
    op.drop_index("ix_executions_trigger_event_id", table_name="playbook_executions")
    op.drop_column("playbook_executions", "trigger_reason")
    op.drop_column("playbook_executions", "trigger_event_id")

    op.drop_column("response_playbooks", "cooldown_seconds")
    op.drop_column("response_playbooks", "rule_version")
    op.drop_column("response_playbooks", "trigger_conditions")

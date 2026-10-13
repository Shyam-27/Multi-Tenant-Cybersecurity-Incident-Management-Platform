"""create incidents and notes

Revision ID: 20261013_0004
Revises: 20261013_0003
Create Date: 2026-10-13 01:10:00
"""

from alembic import op
import sqlalchemy as sa

revision = "20261013_0004"
down_revision = "20261013_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("category", sa.String(80), server_default="OTHER", nullable=False),
        sa.Column("severity", sa.String(20), server_default="MEDIUM", nullable=False),
        sa.Column("status", sa.String(20), server_default="OPEN", nullable=False),
        sa.Column("assigned_to_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_tenant_id", "incidents", ["tenant_id"])
    op.create_index("ix_incidents_assigned_to_id", "incidents", ["assigned_to_id"])
    op.create_index("ix_incidents_created_by_id", "incidents", ["created_by_id"])
    op.create_index("ix_incidents_tenant_status", "incidents", ["tenant_id", "status"])
    op.create_index("ix_incidents_tenant_severity", "incidents", ["tenant_id", "severity"])
    op.create_index("ix_incidents_tenant_assigned", "incidents", ["tenant_id", "assigned_to_id"])
    op.create_index("ix_incidents_tenant_created", "incidents", ["tenant_id", "created_at"])

    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("author_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_incident_notes_tenant_id", "incident_notes", ["tenant_id"])
    op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])
    op.create_index("ix_incident_notes_author_id", "incident_notes", ["author_id"])
    op.create_index("ix_incident_notes_tenant_incident", "incident_notes", ["tenant_id", "incident_id"])
    op.create_index("ix_incident_notes_created_at", "incident_notes", ["created_at"])


def downgrade() -> None:
    op.drop_table("incident_notes")
    op.drop_table("incidents")

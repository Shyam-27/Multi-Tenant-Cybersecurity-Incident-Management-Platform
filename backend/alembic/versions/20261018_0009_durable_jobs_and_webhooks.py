"""Phase 7B: Durable Background Processing and Scheduled Jobs

Revision ID: 20261018_0009
Revises: 20261017_0008
Create Date: 2026-10-18 01:20:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20261018_0009"
down_revision = "20261017_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add durability & concurrency fields to webhook_deliveries
    op.add_column("webhook_deliveries", sa.Column("last_error_category", sa.String(length=50), nullable=True))
    op.add_column("webhook_deliveries", sa.Column("is_terminal_failure", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("webhook_deliveries", sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("webhook_deliveries", sa.Column("locked_by", sa.String(length=100), nullable=True))
    op.create_index("ix_deliveries_tenant_terminal", "webhook_deliveries", ["tenant_id", "is_terminal_failure"])
    op.create_index("ix_deliveries_retry_sweep", "webhook_deliveries", ["status", "next_retry_at"])

    # 2. Create background_jobs table
    json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")
    op.create_table(
        "background_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), server_default="QUEUED", nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("parameters", json_type, server_default="{}", nullable=False),
        sa.Column("result_summary", json_type, server_default="{}", nullable=False),
        sa.Column("error_message", sa.String(length=1024), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_jobs_tenant_id", "background_jobs", ["tenant_id"])
    op.create_index("ix_jobs_tenant_status", "background_jobs", ["tenant_id", "status"])
    op.create_index("ix_jobs_tenant_created", "background_jobs", ["tenant_id", "created_at"])
    op.create_index("ix_jobs_tenant_type", "background_jobs", ["tenant_id", "job_type"])
    op.create_index("ix_jobs_resource_id", "background_jobs", ["resource_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_resource_id", table_name="background_jobs")
    op.drop_index("ix_jobs_tenant_type", table_name="background_jobs")
    op.drop_index("ix_jobs_tenant_created", table_name="background_jobs")
    op.drop_index("ix_jobs_tenant_status", table_name="background_jobs")
    op.drop_index("ix_jobs_tenant_id", table_name="background_jobs")
    op.drop_table("background_jobs")

    op.drop_index("ix_deliveries_retry_sweep", table_name="webhook_deliveries")
    op.drop_index("ix_deliveries_tenant_terminal", table_name="webhook_deliveries")
    op.drop_column("webhook_deliveries", "locked_by")
    op.drop_column("webhook_deliveries", "locked_at")
    op.drop_column("webhook_deliveries", "is_terminal_failure")
    op.drop_column("webhook_deliveries", "last_error_category")

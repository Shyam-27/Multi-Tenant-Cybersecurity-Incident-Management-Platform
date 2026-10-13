"""create evidence table
 
Revision ID: 20261013_0005
Revises: 20261013_0004
Create Date: 2026-10-13 04:50:00
"""

from alembic import op
import sqlalchemy as sa

revision = "20261013_0005"
down_revision = "20261013_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("uploaded_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_hash", sa.String(64), nullable=False),
        sa.Column("mime_type", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1000), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_evidence_tenant_id", "evidence", ["tenant_id"])
    op.create_index("ix_evidence_incident_id", "evidence", ["incident_id"])
    op.create_index("ix_evidence_uploaded_by_id", "evidence", ["uploaded_by_id"])
    op.create_index("ix_evidence_sha256_hash", "evidence", ["sha256_hash"])
    op.create_index("ix_evidence_tenant_incident", "evidence", ["tenant_id", "incident_id"])
    op.create_index("ix_evidence_created_at", "evidence", ["created_at"])


def downgrade() -> None:
    op.drop_table("evidence")

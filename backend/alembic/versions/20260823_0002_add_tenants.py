"""add tenants and tenant membership"""
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "20260823_0002"
down_revision = "20260823_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])
    op.add_column("users", sa.Column("tenant_id", sa.Uuid(), nullable=True))
    tenant_id = uuid4()
    op.bulk_insert(
        sa.table("tenants", sa.column("id", sa.Uuid()), sa.column("name", sa.String()), sa.column("slug", sa.String()), sa.column("status", sa.String())),
        [{"id": tenant_id, "name": "Legacy Workspace", "slug": "legacy-workspace", "status": "ACTIVE"}],
    )
    op.execute(sa.text("UPDATE users SET tenant_id = :tenant_id").bindparams(tenant_id=tenant_id))
    op.alter_column("users", "tenant_id", nullable=False)
    op.create_foreign_key("fk_users_tenant_id_tenants", "users", "tenants", ["tenant_id"], ["id"], ondelete="RESTRICT")
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_users_tenant_id", table_name="users")
    op.drop_constraint("fk_users_tenant_id_tenants", "users", type_="foreignkey")
    op.drop_column("users", "tenant_id")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_table("tenants")

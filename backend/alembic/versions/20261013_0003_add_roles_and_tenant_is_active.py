"""add roles and tenant is_active

Revision ID: 20261013_0003
Revises: 20260823_0002
Create Date: 2026-10-13 00:30:00
"""

from alembic import op
import sqlalchemy as sa

revision = "20261013_0003"
down_revision = "20260823_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_active to tenants
    op.add_column("tenants", sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False))
    
    # Add role to users
    op.add_column("users", sa.Column("role", sa.String(length=30), server_default=sa.text("'SECURITY_ANALYST'"), nullable=False))
    
    # Make tenant_id nullable for platform super_admin
    op.alter_column("users", "tenant_id", nullable=True)
    
    # Elevate initial existing users to TENANT_ADMIN
    op.execute(sa.text("UPDATE users SET role = 'TENANT_ADMIN'"))
    
    # Create composite index for tenant_id and role
    op.create_index("ix_users_tenant_id_role", "users", ["tenant_id", "role"])


def downgrade() -> None:
    op.drop_index("ix_users_tenant_id_role", table_name="users")
    op.alter_column("users", "tenant_id", nullable=False)
    op.drop_column("users", "role")
    op.drop_column("tenants", "is_active")

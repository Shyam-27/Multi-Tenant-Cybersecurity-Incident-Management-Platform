"""Phase 7A: MFA, TOTP, and Privileged-Action Security

Revision ID: 20261017_0008
Revises: 20261016_0007
Create Date: 2026-10-17 12:40:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20261017_0008"
down_revision = "20261016_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add MFA fields to users table
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.String(length=512), nullable=True))
    op.add_column("users", sa.Column("mfa_enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("last_totp_timestep", sa.BigInteger(), nullable=True))
    op.add_column("users", sa.Column("mfa_failed_attempts", sa.Integer(), server_default="0", nullable=False))
    op.add_column("users", sa.Column("mfa_locked_until", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_mfa_enabled", "users", ["mfa_enabled"])

    # 2. Create user_recovery_codes table
    op.create_table(
        "user_recovery_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("is_used", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_user_recovery_codes_user_id", "user_recovery_codes", ["user_id"])
    op.create_index("ix_user_recovery_codes_user_used", "user_recovery_codes", ["user_id", "is_used"])

    # 3. Add step-up tracking columns to playbook_executions
    op.add_column("playbook_executions", sa.Column("step_up_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("playbook_executions", sa.Column("step_up_verified_by_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True))
    op.add_column("playbook_executions", sa.Column("step_up_method", sa.String(length=30), nullable=True))

    # 4. Add step-up tracking columns to playbook_approvals
    op.add_column("playbook_approvals", sa.Column("step_up_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("playbook_approvals", sa.Column("step_up_method", sa.String(length=30), nullable=True))


def downgrade() -> None:
    # 4. Remove step-up columns from playbook_approvals
    op.drop_column("playbook_approvals", "step_up_method")
    op.drop_column("playbook_approvals", "step_up_verified_at")

    # 3. Remove step-up columns from playbook_executions
    op.drop_column("playbook_executions", "step_up_method")
    op.drop_column("playbook_executions", "step_up_verified_by_id")
    op.drop_column("playbook_executions", "step_up_verified_at")

    # 2. Drop user_recovery_codes table
    op.drop_index("ix_user_recovery_codes_user_used", table_name="user_recovery_codes")
    op.drop_index("ix_user_recovery_codes_user_id", table_name="user_recovery_codes")
    op.drop_table("user_recovery_codes")

    # 1. Remove MFA fields from users table
    op.drop_index("ix_users_mfa_enabled", table_name="users")
    op.drop_column("users", "mfa_locked_until")
    op.drop_column("users", "mfa_failed_attempts")
    op.drop_column("users", "last_totp_timestep")
    op.drop_column("users", "mfa_enrolled_at")
    op.drop_column("users", "totp_secret_encrypted")
    op.drop_column("users", "mfa_enabled")

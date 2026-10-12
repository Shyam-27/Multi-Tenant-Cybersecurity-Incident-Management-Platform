"""SQLAlchemy models registered for migrations."""

from app.models.tenant import Tenant
from app.models.user import User, UserRole

__all__ = ["Tenant", "User", "UserRole"]

from collections.abc import Callable
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.tenant import Tenant
from app.models.user import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
inactive_account_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Account is inactive",
    headers={"WWW-Authenticate": "Bearer"},
)
inactive_tenant_exception = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Organization is deactivated",
)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        user_id: UUID = decode_access_token(token)
    except (jwt.PyJWTError, ValueError):
        raise credentials_exception
    user = db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise inactive_account_exception
    # Check tenant status if user belongs to a tenant
    if user.tenant is not None and not user.tenant.is_active:
        raise inactive_tenant_exception
    return user


def get_current_tenant(current_user: User = Depends(get_current_user)) -> Tenant:
    if current_user.tenant is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User does not belong to any tenant",
        )
    if not current_user.tenant.is_active:
        raise inactive_tenant_exception
    return current_user.tenant


def require_roles(*allowed_roles: UserRole) -> Callable[[User], User]:
    allowed_values = {role.value for role in allowed_roles}

    def role_verifier(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for current user role",
            )
        return current_user

    return role_verifier

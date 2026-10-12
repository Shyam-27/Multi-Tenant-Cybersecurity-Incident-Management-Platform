from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import hash_password
from app.dependencies.auth import get_current_user, require_roles
from app.models.user import User, UserRole
from app.schemas.user import CreateUserRequest, UpdateUserRequest, UserDetailResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserDetailResponse])
def list_users(
    tenant_id: UUID | None = None,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> list[User]:
    query = select(User)
    if current_user.role == UserRole.SUPER_ADMIN.value:
        if tenant_id is not None:
            query = query.where(User.tenant_id == tenant_id)
    else:
        # Strictly tenant-scoped for TENANT_ADMIN
        query = query.where(User.tenant_id == current_user.tenant_id)

    query = query.order_by(User.created_at.desc())
    return list(db.scalars(query).all())


@router.post("", response_model=UserDetailResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    data: CreateUserRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> User:
    email = data.email.lower().strip()
    if db.scalar(select(User.id).where(func.lower(User.email) == email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")

    # Privilege escalation prevention
    if current_user.role == UserRole.TENANT_ADMIN.value and data.role == UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant administrators cannot grant SUPER_ADMIN privileges",
        )

    # Server-derived tenant context: tenant_admin can only create users in their own tenant
    target_tenant_id = current_user.tenant_id if current_user.role != UserRole.SUPER_ADMIN.value else current_user.tenant_id

    new_user = User(
        tenant_id=target_tenant_id,
        name=data.name.strip(),
        email=email,
        password_hash=hash_password(data.password),
        role=data.role.value,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.get("/{user_id}", response_model=UserDetailResponse)
def get_user_by_id(
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    user = db.scalar(select(User).where(User.id == user_id))
    # Return 404 for missing or cross-tenant records to prevent IDOR and enumeration
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and user.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return user


@router.patch("/{user_id}", response_model=UserDetailResponse)
def update_user(
    user_id: UUID,
    data: UpdateUserRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> User:
    user = db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Cross-tenant modification protection
    if current_user.role != UserRole.SUPER_ADMIN.value and user.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent users from modifying their own role
    if user.id == current_user.id and data.role is not None and data.role.value != current_user.role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Users cannot modify their own role",
        )

    # Privilege escalation prevention
    if current_user.role == UserRole.TENANT_ADMIN.value and data.role == UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant administrators cannot grant SUPER_ADMIN privileges",
        )

    if data.name is not None:
        user.name = data.name.strip()
    if data.role is not None:
        user.role = data.role.value
    if data.is_active is not None:
        user.is_active = data.is_active

    db.commit()
    db.refresh(user)
    return user

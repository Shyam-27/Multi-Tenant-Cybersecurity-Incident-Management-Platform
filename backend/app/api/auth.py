from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (
    create_access_token,
    hash_password,
    needs_rehash,
    revoke_token,
    verify_password,
)
from app.dependencies.auth import get_current_user, oauth2_scheme
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RegistrationRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["authentication"])
invalid_credentials = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid email or password",
    headers={"WWW-Authenticate": "Bearer"},
)
# Fixed dummy hash for constant-time comparison when email is not found
_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$somesalt12345678$e5dF1w3vJgX+P2hLkE3Qf0w4u2K1rA8yN8"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(data: RegistrationRequest, db: Session = Depends(get_db)) -> User:
    email = data.email.lower().strip()
    if db.scalar(select(User.id).where(func.lower(User.email) == email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
    if db.scalar(select(Tenant.id).where(Tenant.slug == data.organization_slug)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An organization with this slug already exists")

    tenant = Tenant(name=data.organization_name.strip(), slug=data.organization_slug, is_active=True)
    user = User(
        tenant=tenant,
        name=data.name.strip(),
        email=email,
        password_hash=hash_password(data.password),
        role=UserRole.TENANT_ADMIN.value,
        is_active=True,
    )
    db.add(tenant)
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists") from exc
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = data.email.lower().strip()
    user = db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        verify_password("dummy-password", _DUMMY_HASH)
        raise invalid_credentials
    if not user.is_active or (user.tenant is not None and not user.tenant.is_active):
        raise invalid_credentials
    if not verify_password(data.password, user.password_hash):
        raise invalid_credentials

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(data.password)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id))


@router.post("/token", response_model=TokenResponse, include_in_schema=False)
def oauth2_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> TokenResponse:
    """OAuth2 password flow for Swagger UI; enter the email in the username field."""
    email = form_data.username.lower().strip()
    user = db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        verify_password("dummy-password", _DUMMY_HASH)
        raise invalid_credentials
    if not user.is_active or (user.tenant is not None and not user.tenant.is_active):
        raise invalid_credentials
    if not verify_password(form_data.password, user.password_hash):
        raise invalid_credentials

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(token: str = Depends(oauth2_scheme), current_user: User = Depends(get_current_user)) -> Response:
    revoke_token(token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    data: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not verify_password(data.current_password, current_user.password_hash):
        raise invalid_credentials
    current_user.password_hash = hash_password(data.new_password)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

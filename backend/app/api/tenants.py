from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.tenant import TenantResponse

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("/me", response_model=TenantResponse)
def current_tenant(current_user: User = Depends(get_current_user)) -> TenantResponse:
    if current_user.tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not associated with this account",
        )
    return current_user.tenant

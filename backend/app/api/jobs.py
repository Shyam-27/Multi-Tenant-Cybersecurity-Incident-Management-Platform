from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.models.job import BackgroundJob
from app.models.user import User, UserRole
from app.schemas.job import BackgroundJobResponse, JobListResponse

router = APIRouter(prefix="/jobs", tags=["background-jobs"])


@router.get("", response_model=JobListResponse)
def list_jobs(
    job_type: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JobListResponse:
    """Lists background processing and scheduled jobs with multi-tenant isolation."""
    query = select(BackgroundJob)

    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(BackgroundJob.tenant_id == current_user.tenant_id)

    if job_type:
        query = query.where(BackgroundJob.job_type == job_type.upper().strip())
    if status_filter:
        query = query.where(BackgroundJob.status == status_filter.upper().strip())

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    pages = max(1, ceil(total / page_size))
    offset = (page - 1) * page_size

    items = db.scalars(
        query.order_by(BackgroundJob.created_at.desc()).offset(offset).limit(page_size)
    ).all()

    return JobListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{id}", response_model=BackgroundJobResponse)
def get_job(
    id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BackgroundJob:
    """Retrieves status and results for a specific background job with anti-IDOR enforcement."""
    job = db.scalar(select(BackgroundJob).where(BackgroundJob.id == id))
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Background job not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and job.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Background job not found")

    return job

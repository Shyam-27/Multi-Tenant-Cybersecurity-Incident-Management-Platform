from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_roles
from app.models.audit import ActorType, AuditOutcome
from app.models.incident import Incident
from app.models.ioc import IndicatorOfCompromise
from app.models.job import BackgroundJob, JobStatus, JobType
from app.models.user import User, UserRole
from app.schemas.ioc import CreateIOCRequest, EnrichIOCRequest, IOCListResponse, IOCResponse, UpdateIOCRequest
from app.schemas.job import AsyncIOCEnrichResponse
from app.services.audit_service import record_audit_event
from app.services.threat_intel.normalizer import normalize_indicator
from app.services.threat_intel.service import get_threat_intel_service

router = APIRouter(prefix="/iocs", tags=["threat-intel"])


@router.post("", response_model=IOCResponse, status_code=status.HTTP_201_CREATED)
def create_ioc(
    payload: CreateIOCRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> IndicatorOfCompromise:
    # 1. Normalize & Validate
    try:
        norm_type, norm_value = normalize_indicator(payload.indicator_type, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # 2. Check for duplicate within tenant
    existing = db.scalar(
        select(IndicatorOfCompromise).where(
            IndicatorOfCompromise.tenant_id == current_user.tenant_id,
            IndicatorOfCompromise.indicator_type == norm_type,
            IndicatorOfCompromise.value == norm_value,
        )
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Indicator '{norm_value}' of type '{norm_type}' already exists for this tenant",
        )

    # 3. If incident_id provided, verify belongs to same tenant
    if payload.incident_id:
        inc = db.scalar(
            select(Incident).where(
                Incident.id == payload.incident_id,
                Incident.tenant_id == current_user.tenant_id,
            )
        )
        if not inc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found in your organization")

    ioc = IndicatorOfCompromise(
        tenant_id=current_user.tenant_id,
        indicator_type=norm_type,
        value=norm_value,
        incident_id=payload.incident_id,
        notes=payload.notes,
        source=payload.source,
        external_reference=payload.external_reference,
        created_by_id=current_user.id,
    )
    db.add(ioc)
    db.flush()

    record_audit_event(
        db=db,
        action="IOC_CREATED",
        resource_type="ioc",
        resource_id=str(ioc.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"type": norm_type, "value": norm_value, "source": payload.source},
    )
    db.commit()
    db.refresh(ioc)
    return ioc


@router.get("", response_model=IOCListResponse)
def list_iocs(
    indicator_type: str | None = Query(default=None),
    threat_verdict: str | None = Query(default=None),
    search: str | None = Query(default=None),
    incident_id: UUID | None = Query(default=None),
    is_false_positive: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IOCListResponse:
    query = select(IndicatorOfCompromise)

    # Multi-tenant isolation: filter by caller tenant
    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(IndicatorOfCompromise.tenant_id == current_user.tenant_id)

    if indicator_type:
        query = query.where(IndicatorOfCompromise.indicator_type == indicator_type.upper().strip())
    if threat_verdict:
        query = query.where(IndicatorOfCompromise.threat_verdict == threat_verdict.upper().strip())
    if incident_id:
        query = query.where(IndicatorOfCompromise.incident_id == incident_id)
    if is_false_positive is not None:
        query = query.where(IndicatorOfCompromise.is_false_positive == is_false_positive)
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.where(
            or_(
                func.lower(IndicatorOfCompromise.value).like(s),
                func.lower(IndicatorOfCompromise.notes).like(s),
            )
        )

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    pages = max(1, ceil(total / page_size))
    offset = (page - 1) * page_size

    items = db.scalars(
        query.order_by(IndicatorOfCompromise.created_at.desc()).offset(offset).limit(page_size)
    ).all()

    return IOCListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{id}", response_model=IOCResponse)
def get_ioc(
    id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IndicatorOfCompromise:
    ioc = db.scalar(select(IndicatorOfCompromise).where(IndicatorOfCompromise.id == id))
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and ioc.tenant_id != current_user.tenant_id:
        # Anti-IDOR: strict 404
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    return ioc


@router.patch("/{id}", response_model=IOCResponse)
def update_ioc(
    id: UUID,
    payload: UpdateIOCRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> IndicatorOfCompromise:
    ioc = db.scalar(select(IndicatorOfCompromise).where(IndicatorOfCompromise.id == id))
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    if payload.is_false_positive is not None:
        ioc.is_false_positive = payload.is_false_positive
    if payload.notes is not None:
        ioc.notes = payload.notes
    if payload.threat_verdict is not None:
        ioc.threat_verdict = payload.threat_verdict
    if payload.severity is not None:
        ioc.severity = payload.severity

    record_audit_event(
        db=db,
        action="IOC_UPDATED",
        resource_type="ioc",
        resource_id=str(ioc.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=ioc.tenant_id,
        details={
            "is_false_positive": ioc.is_false_positive,
            "threat_verdict": ioc.threat_verdict,
        },
    )
    db.commit()
    db.refresh(ioc)
    return ioc


@router.post("/{id}/enrich", response_model=IOCResponse)
def enrich_ioc(
    id: UUID,
    payload: EnrichIOCRequest | None = None,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> IndicatorOfCompromise:
    ioc = db.scalar(select(IndicatorOfCompromise).where(IndicatorOfCompromise.id == id))
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    threat_service = get_threat_intel_service()
    providers = payload.providers if payload else None
    force_refresh = payload.force_refresh if payload else False

    enriched = threat_service.enrich_indicator(
        db=db,
        indicator=ioc,
        selected_providers=providers,
        force_refresh=force_refresh,
        actor_user=current_user,
    )
    return enriched


@router.post("/{id}/enrich-async", response_model=AsyncIOCEnrichResponse, status_code=status.HTTP_202_ACCEPTED)
def enrich_ioc_async(
    id: UUID,
    payload: EnrichIOCRequest | None = None,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> AsyncIOCEnrichResponse:
    ioc = db.scalar(select(IndicatorOfCompromise).where(IndicatorOfCompromise.id == id))
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    force_refresh = payload.force_refresh if payload else True

    job = BackgroundJob(
        tenant_id=ioc.tenant_id,
        job_type=JobType.THREAT_INTEL_REFRESH.value,
        status=JobStatus.QUEUED.value,
        resource_id=str(ioc.id),
        parameters={"indicator_type": ioc.indicator_type, "value": ioc.value, "force_refresh": force_refresh},
    )
    db.add(job)

    record_audit_event(
        db=db,
        action="IOC_ENRICH_ASYNC_REQUESTED",
        resource_type="ioc",
        resource_id=str(ioc.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=ioc.tenant_id,
        details={"indicator_type": ioc.indicator_type, "value": ioc.value},
    )
    db.commit()
    db.refresh(job)

    from app.core.celery_app import safe_apply_async
    from app.tasks.threat_intel_tasks import refresh_threat_intel_task

    safe_apply_async(
        refresh_threat_intel_task,
        args=[str(ioc.id), str(ioc.tenant_id), force_refresh, str(current_user.id), str(job.id)],
    )

    return AsyncIOCEnrichResponse(
        message="Threat intelligence enrichment job successfully queued",
        job_id=job.id,
        ioc_id=ioc.id,
        status=job.status,
    )


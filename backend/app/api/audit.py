from datetime import datetime
from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_roles
from app.models.audit import AuditEvent, AuditOutcome
from app.models.user import User, UserRole
from app.schemas.audit import (
    AuditEventListResponse,
    AuditEventResponse,
    AuditVerificationResult,
)
from app.services.audit_service import verify_tenant_audit_chain

router = APIRouter(prefix="/audit-events", tags=["audit-events"])


def _format_audit_event_response(event: AuditEvent) -> AuditEventResponse:
    return AuditEventResponse(
        id=event.id,
        tenant_id=event.tenant_id,
        actor_user_id=event.actor_user_id,
        actor_user_name=event.actor_user.name if event.actor_user else None,
        actor_user_email=event.actor_user.email if event.actor_user else None,
        actor_type=event.actor_type,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        outcome=event.outcome,
        occurred_at=event.occurred_at,
        request_id=event.request_id,
        source_ip=event.source_ip,
        user_agent=event.user_agent,
        details=event.details,
        previous_hash=event.previous_hash,
        event_hash=event.event_hash,
    )


@router.get("", response_model=AuditEventListResponse)
def list_audit_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    action: str | None = None,
    outcome: AuditOutcome | None = None,
    actor_user_id: UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    tenant_id: UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AuditEventListResponse:
    parsed_start: datetime | None = None
    parsed_end: datetime | None = None

    if start_time:
        try:
            cleaned_start = start_time.replace("Z", "+00:00").replace(" ", "+")
            parsed_start = datetime.fromisoformat(cleaned_start)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid start_time ISO format")

    if end_time:
        try:
            cleaned_end = end_time.replace("Z", "+00:00").replace(" ", "+")
            parsed_end = datetime.fromisoformat(cleaned_end)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid end_time ISO format")

    # Validate date range
    if parsed_start and parsed_end and parsed_start > parsed_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time cannot be after end_time",
        )

    query = select(AuditEvent).options(selectinload(AuditEvent.actor_user))

    # Tenant Scoping: strictly enforced
    if current_user.role == UserRole.SUPER_ADMIN.value:
        if tenant_id is not None:
            query = query.where(AuditEvent.tenant_id == tenant_id)
    else:
        query = query.where(AuditEvent.tenant_id == current_user.tenant_id)

    # Filtering
    if action:
        query = query.where(AuditEvent.action == action.strip())
    if outcome:
        query = query.where(AuditEvent.outcome == outcome.value)
    if actor_user_id:
        query = query.where(AuditEvent.actor_user_id == actor_user_id)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type.strip())
    if resource_id:
        query = query.where(AuditEvent.resource_id == resource_id.strip())
    if parsed_start:
        query = query.where(AuditEvent.occurred_at >= parsed_start)
    if parsed_end:
        query = query.where(AuditEvent.occurred_at <= parsed_end)

    # Total count query
    count_query = select(func.count()).select_from(query.subquery())
    total_count = db.scalar(count_query) or 0

    # Stable Ordering: newest first
    query = query.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())

    # Pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    events = db.scalars(query).all()
    total_pages = ceil(total_count / page_size) if total_count > 0 else 1

    return AuditEventListResponse(
        items=[_format_audit_event_response(e) for e in events],
        total=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/verify-chain", response_model=AuditVerificationResult)
def verify_audit_trail_chain(
    tenant_id: UUID | None = None,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> AuditVerificationResult:
    """
    Cryptographic verification endpoint that walks the SHA-256 hash chain
    and verifies that every record is linked and untampered.
    """
    target_tenant = current_user.tenant_id
    if current_user.role == UserRole.SUPER_ADMIN.value and tenant_id is not None:
        target_tenant = tenant_id

    is_valid, count, broken_id, message = verify_tenant_audit_chain(db, target_tenant)
    return AuditVerificationResult(
        verified_count=count,
        is_valid=is_valid,
        broken_event_id=broken_id,
        details=message,
    )


@router.get("/{event_id}", response_model=AuditEventResponse)
def get_audit_event_by_id(
    event_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AuditEventResponse:
    event = db.scalar(
        select(AuditEvent)
        .options(selectinload(AuditEvent.actor_user))
        .where(AuditEvent.id == event_id)
    )

    # Anti-IDOR check: return 404 for missing or cross-tenant records
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and event.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")

    return _format_audit_event_response(event)

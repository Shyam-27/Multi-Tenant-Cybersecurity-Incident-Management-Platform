from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_roles
from app.models.audit import ActorType, AuditOutcome
from app.models.job import BackgroundJob, JobStatus, JobType
from app.models.user import User, UserRole
from app.models.webhook import DeliveryStatus, DestinationType, NotificationDestination, WebhookDelivery
from app.schemas.webhook import (
    CreateDestinationRequest,
    DeliveryListResponse,
    DeliveryResponse,
    DestinationResponse,
    RetryDeliveryResponse,
    TestWebhookResponse,
    UpdateDestinationRequest,
)
from app.services.audit_service import record_audit_event
from app.services.webhook_service import send_test_webhook, validate_destination_url

router = APIRouter(prefix="/destinations", tags=["siem-webhooks"])


def _to_destination_response(d: NotificationDestination) -> DestinationResponse:
    return DestinationResponse(
        id=d.id,
        tenant_id=d.tenant_id,
        name=d.name,
        destination_type=d.destination_type,
        endpoint_url=d.endpoint_url,
        is_enabled=d.is_enabled,
        event_types=d.event_types,
        has_secret=bool(d.secret_token),
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


@router.post("", response_model=DestinationResponse, status_code=status.HTTP_201_CREATED)
def create_destination(
    payload: CreateDestinationRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> DestinationResponse:
    settings = get_settings()

    # SSRF Protection
    try:
        valid_url = validate_destination_url(payload.endpoint_url, allow_local=settings.allow_local_webhooks)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # Validate destination type
    dtype = payload.destination_type.upper().strip()
    if dtype not in [t.value for t in DestinationType]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid destination type: '{payload.destination_type}'",
        )

    destination = NotificationDestination(
        tenant_id=current_user.tenant_id,
        name=payload.name.strip(),
        destination_type=dtype,
        endpoint_url=valid_url,
        secret_token=payload.secret_token.strip() if payload.secret_token else None,
        is_enabled=payload.is_enabled,
        event_types=payload.event_types,
        created_by_id=current_user.id,
    )
    db.add(destination)
    db.flush()

    record_audit_event(
        db=db,
        action="DESTINATION_CREATED",
        resource_type="webhook_destination",
        resource_id=str(destination.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"name": destination.name, "destination_type": destination.destination_type},
    )
    db.commit()
    db.refresh(destination)
    return _to_destination_response(destination)


@router.get("", response_model=list[DestinationResponse])
def list_destinations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DestinationResponse]:
    query = select(NotificationDestination)
    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(NotificationDestination.tenant_id == current_user.tenant_id)

    items = db.scalars(query.order_by(NotificationDestination.created_at.desc())).all()
    return [_to_destination_response(d) for d in items]


@router.get("/deliveries/list", response_model=DeliveryListResponse)
def list_all_deliveries(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeliveryListResponse:
    query = select(WebhookDelivery)
    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(WebhookDelivery.tenant_id == current_user.tenant_id)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    pages = max(1, ceil(total / page_size))
    offset = (page - 1) * page_size

    items = db.scalars(
        query.order_by(WebhookDelivery.created_at.desc()).offset(offset).limit(page_size)
    ).all()

    return DeliveryListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{id}", response_model=DestinationResponse)
def get_destination(
    id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DestinationResponse:
    dest = db.scalar(select(NotificationDestination).where(NotificationDestination.id == id))
    if not dest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and dest.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    return _to_destination_response(dest)


@router.patch("/{id}", response_model=DestinationResponse)
def update_destination(
    id: UUID,
    payload: UpdateDestinationRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> DestinationResponse:
    dest = db.scalar(select(NotificationDestination).where(NotificationDestination.id == id))
    if not dest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and dest.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    settings = get_settings()
    if payload.endpoint_url is not None:
        try:
            dest.endpoint_url = validate_destination_url(
                payload.endpoint_url, allow_local=settings.allow_local_webhooks
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if payload.name is not None:
        dest.name = payload.name.strip()
    if payload.secret_token is not None:
        dest.secret_token = payload.secret_token.strip() if payload.secret_token else None
    if payload.is_enabled is not None:
        dest.is_enabled = payload.is_enabled
    if payload.event_types is not None:
        dest.event_types = payload.event_types

    record_audit_event(
        db=db,
        action="DESTINATION_UPDATED",
        resource_type="webhook_destination",
        resource_id=str(dest.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=dest.tenant_id,
        details={"name": dest.name, "is_enabled": dest.is_enabled},
    )
    db.commit()
    db.refresh(dest)
    return _to_destination_response(dest)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_destination(
    id: UUID,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> None:
    dest = db.scalar(select(NotificationDestination).where(NotificationDestination.id == id))
    if not dest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and dest.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    dest_name = dest.name
    db.delete(dest)

    record_audit_event(
        db=db,
        action="DESTINATION_DELETED",
        resource_type="webhook_destination",
        resource_id=str(id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"name": dest_name},
    )
    db.commit()


@router.post("/{id}/test", response_model=TestWebhookResponse)
def test_destination(
    id: UUID,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> TestWebhookResponse:
    dest = db.scalar(select(NotificationDestination).where(NotificationDestination.id == id))
    if not dest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and dest.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    success, code, err = send_test_webhook(db=db, destination=dest, actor_user=current_user)

    msg = "Test event dispatched successfully" if success else f"Test delivery failed: {err}"
    return TestWebhookResponse(
        success=success,
        status_code=code,
        error=err,
        message=msg,
    )


@router.get("/{id}/deliveries", response_model=DeliveryListResponse)
def list_destination_deliveries(
    id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeliveryListResponse:
    dest = db.scalar(select(NotificationDestination).where(NotificationDestination.id == id))
    if not dest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and dest.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination not found")

    query = select(WebhookDelivery).where(WebhookDelivery.destination_id == id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    pages = max(1, ceil(total / page_size))
    offset = (page - 1) * page_size

    items = db.scalars(
        query.order_by(WebhookDelivery.created_at.desc()).offset(offset).limit(page_size)
    ).all()

    return DeliveryListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post("/deliveries/{delivery_id}/retry", response_model=RetryDeliveryResponse)
def retry_webhook_delivery(
    delivery_id: UUID,
    current_user: User = Depends(require_roles(UserRole.SECURITY_ANALYST, UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> RetryDeliveryResponse:
    """Manually queues a retry for a failed or retrying webhook delivery with tenant isolation."""
    delivery = db.scalar(select(WebhookDelivery).where(WebhookDelivery.id == delivery_id))
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook delivery not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and delivery.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook delivery not found")

    # Reset terminal flags and reset to pending
    delivery.status = DeliveryStatus.PENDING.value
    delivery.is_terminal_failure = False
    delivery.locked_at = None
    delivery.locked_by = None
    delivery.next_retry_at = None
    # Reset attempt count if it had hit max attempts so fresh attempts can proceed
    if delivery.attempt_count >= delivery.max_attempts:
        delivery.attempt_count = 0

    job = BackgroundJob(
        tenant_id=delivery.tenant_id,
        job_type=JobType.DELIVERY_RETRY.value,
        status=JobStatus.QUEUED.value,
        resource_id=str(delivery.id),
        parameters={"delivery_id": str(delivery.id), "event_type": delivery.event_type},
    )
    db.add(job)

    record_audit_event(
        db=db,
        action="WEBHOOK_DELIVERY_RETRY_REQUESTED",
        resource_type="webhook_delivery",
        resource_id=str(delivery.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=delivery.tenant_id,
        details={"destination_id": str(delivery.destination_id), "event_type": delivery.event_type},
    )

    db.commit()
    db.refresh(delivery)

    from app.core.celery_app import safe_apply_async
    from app.tasks.webhook_tasks import dispatch_webhook_delivery_task

    safe_apply_async(dispatch_webhook_delivery_task, args=[str(delivery.id), True])

    return RetryDeliveryResponse(
        message="Webhook delivery retry successfully scheduled",
        delivery=delivery,
    )


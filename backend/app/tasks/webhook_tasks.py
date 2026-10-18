from datetime import datetime, timedelta, timezone
import logging
import random
import socket
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app, safe_apply_async
from app.core.config import get_settings
from app.core import database
from app.models.audit import ActorType, AuditOutcome
from app.models.job import BackgroundJob, JobStatus, JobType
from app.models.webhook import DeliveryStatus, NotificationDestination, WebhookDelivery
from app.services.audit_service import record_audit_event
from app.services import webhook_service

logger = logging.getLogger("sentinelops.webhook_tasks")


def compute_backoff_seconds(attempt: int, base_seconds: float = 10.0, jitter_factor: float = 0.2) -> float:
    """
    Computes exponential backoff with bounded jitter.
    Attempt 1: ~10s, Attempt 2: ~20s, Attempt 3: ~40s, Attempt 4: ~80s.
    """
    exponent = max(0, attempt - 1)
    base = base_seconds * (2 ** exponent)
    jitter = random.uniform(1.0 - jitter_factor, 1.0 + jitter_factor)
    return round(base * jitter, 2)


def is_permanent_client_error(status_code: int) -> bool:
    """4xx errors are permanent client errors, except 429 Too Many Requests (transient rate limiting)."""
    return 400 <= status_code < 500 and status_code != 429


@celery_app.task(bind=True, max_retries=None, acks_late=True)
def dispatch_webhook_delivery_task(self, delivery_id: str, is_retry: bool = False) -> dict[str, Any]:
    """
    Executes durable webhook dispatch with:
    - Worker concurrency protection (SELECT FOR UPDATE SKIP LOCKED)
    - Destination URL revalidation before connect (SSRF protection)
    - Strictly no redirect following (follow_redirects=False)
    - Categorized transient vs permanent error classification
    - Exponential backoff with jitter up to max_attempts (terminal failure at 5)
    - Zero credential leakage
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    worker_id = f"{socket.gethostname()}-{getattr(self.request, 'id', 'manual')}"

    with database.SessionLocal() as db:
        # Atomic lock claim to prevent concurrent worker execution
        delivery = db.scalar(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.id == UUID(delivery_id),
                WebhookDelivery.status.in_([DeliveryStatus.PENDING.value, DeliveryStatus.RETRYING.value]),
            )
            .with_for_update(skip_locked=True)
        )

        if not delivery:
            logger.info("Delivery %s already claimed, completed, or not found", delivery_id)
            return {"status": "SKIPPED", "delivery_id": delivery_id}

        # Check terminal failure guard
        if delivery.is_terminal_failure or delivery.attempt_count >= delivery.max_attempts:
            delivery.status = DeliveryStatus.FAILED.value
            delivery.is_terminal_failure = True
            delivery.locked_at = None
            delivery.locked_by = None
            db.commit()
            return {"status": "TERMINAL_FAILED", "delivery_id": delivery_id}

        delivery.locked_at = now
        delivery.locked_by = worker_id
        delivery.attempt_count += 1
        delivery.last_attempt_at = now
        db.commit()
        db.refresh(delivery)

        # Retrieve destination
        destination = db.scalar(
            select(NotificationDestination).where(NotificationDestination.id == delivery.destination_id)
        )
        if not destination or not destination.is_enabled:
            delivery.status = DeliveryStatus.FAILED.value
            delivery.is_terminal_failure = True
            delivery.last_error_category = "DESTINATION_UNAVAILABLE"
            delivery.error_summary = "Destination deleted or disabled"
            delivery.locked_at = None
            delivery.locked_by = None
            db.commit()
            return {"status": "FAILED", "reason": "DESTINATION_UNAVAILABLE"}

        # Dispatch webhook using core delivery mechanism
        success, status_code, error_msg = webhook_service.deliver_webhook_now(
            destination=destination,
            event_type=delivery.event_type,
            payload=delivery.payload,
            delivery_id=delivery.id,
        )

        error_category = None
        is_terminal = False

        if not success:
            if status_code is not None and 300 <= status_code < 400:
                is_terminal = True
                error_category = "REDIRECT_PROHIBITED"
            elif status_code is not None and is_permanent_client_error(status_code):
                is_terminal = True
                error_category = "CLIENT_ERROR"
            elif status_code == 429:
                is_terminal = False
                error_category = "RATE_LIMITED"
            elif status_code is not None and status_code >= 500:
                is_terminal = False
                error_category = "SERVER_ERROR"
            elif error_msg and ("timed out" in error_msg.lower() or "timeout" in error_msg.lower()):
                is_terminal = False
                error_category = "TIMEOUT"
            elif error_msg and ("security check" in error_msg.lower() or "ssrf" in error_msg.lower() or "prohibited" in error_msg.lower()):
                is_terminal = True
                error_category = "SSRF_BLOCKED"
            else:
                is_terminal = False
                error_category = "CONNECTION_ERROR"

        # 3. Update delivery state
        delivery.response_status_code = status_code
        delivery.last_error_category = error_category
        delivery.locked_at = None
        delivery.locked_by = None

        if success:
            delivery.status = DeliveryStatus.SUCCESS.value
            delivery.is_terminal_failure = False
            delivery.error_summary = None
            delivery.next_retry_at = None
        else:
            delivery.error_summary = error_msg
            # Check if attempts exhausted or permanent failure
            if is_terminal or delivery.attempt_count >= delivery.max_attempts:
                delivery.status = DeliveryStatus.FAILED.value
                delivery.is_terminal_failure = True
                delivery.next_retry_at = None
            else:
                delivery.status = DeliveryStatus.RETRYING.value
                delay = compute_backoff_seconds(delivery.attempt_count)
                next_retry = now + timedelta(seconds=delay)
                delivery.next_retry_at = next_retry
                # Queue next retry via Celery
                safe_apply_async(dispatch_webhook_delivery_task, args=[str(delivery.id), True], countdown=int(delay))

        db.commit()

        # Update associated BackgroundJob if present
        job = db.scalar(
            select(BackgroundJob).where(
                BackgroundJob.resource_id == str(delivery.id),
                BackgroundJob.job_type == JobType.WEBHOOK_DELIVERY.value,
            )
        )
        if job:
            job.attempt_count = delivery.attempt_count
            if success:
                job.status = JobStatus.COMPLETED.value
                job.completed_at = datetime.now(timezone.utc)
                job.result_summary = {"status_code": status_code, "attempt_count": delivery.attempt_count}
            elif delivery.is_terminal_failure:
                job.status = JobStatus.FAILED.value
                job.completed_at = datetime.now(timezone.utc)
                job.error_message = error_msg
                job.result_summary = {"status_code": status_code, "category": error_category}
            else:
                job.status = JobStatus.RETRYING.value
                job.error_message = error_msg
            db.commit()

        return {
            "delivery_id": delivery_id,
            "status": delivery.status,
            "attempt_count": delivery.attempt_count,
            "status_code": status_code,
            "error_category": error_category,
        }


@celery_app.task(name="app.tasks.webhook_tasks.recover_pending_deliveries_task")
def recover_pending_deliveries_task() -> int:
    """
    Scheduled sweep task:
    1. Unlocks deliveries with expired locks (abandoned worker crashes > 5 mins).
    2. Re-queues PENDING deliveries not picked up after 30s.
    3. Re-queues RETRYING deliveries whose next_retry_at is due.
    """
    now = datetime.now(timezone.utc)
    lock_expiry = now - timedelta(minutes=5)
    pending_grace = now - timedelta(seconds=30)
    recovered_count = 0

    with database.SessionLocal() as db:
        # 1. Clear abandoned locks
        stale_locked = db.scalars(
            select(WebhookDelivery).where(
                WebhookDelivery.locked_at.is_not(None),
                WebhookDelivery.locked_at <= lock_expiry,
                WebhookDelivery.status.in_([DeliveryStatus.PENDING.value, DeliveryStatus.RETRYING.value]),
            )
        ).all()
        for d in stale_locked:
            logger.warning("Unlocking stale delivery %s locked by %s at %s", d.id, d.locked_by, d.locked_at)
            d.locked_at = None
            d.locked_by = None
            recovered_count += 1
        if stale_locked:
            db.commit()

        # 2. Pick up due retries and pending deliveries
        due_deliveries = db.scalars(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.is_terminal_failure == False,
                WebhookDelivery.locked_at.is_(None),
                or_(
                    (WebhookDelivery.status == DeliveryStatus.PENDING.value) & (WebhookDelivery.created_at <= pending_grace),
                    (WebhookDelivery.status == DeliveryStatus.RETRYING.value) & (WebhookDelivery.next_retry_at <= now),
                ),
            )
            .limit(100)
        ).all()

        for d in due_deliveries:
            safe_apply_async(dispatch_webhook_delivery_task, args=[str(d.id), True])
            recovered_count += 1

    return recovered_count

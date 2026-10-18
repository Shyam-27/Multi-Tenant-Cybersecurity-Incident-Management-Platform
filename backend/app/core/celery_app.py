import logging
from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

logger = logging.getLogger("sentinelops.celery")

settings = get_settings()

celery_app = Celery(
    "sentinelops",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.tasks.webhook_tasks",
        "app.tasks.threat_intel_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_time_limit=300,
    task_soft_time_limit=240,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "recover-pending-deliveries": {
            "task": "app.tasks.webhook_tasks.recover_pending_deliveries_task",
            "schedule": 60.0,
        },
        "scheduled-threat-intel-refresh": {
            "task": "app.tasks.threat_intel_tasks.scheduled_threat_intel_refresh_task",
            "schedule": 900.0,  # 15 minutes
        },
    },
)


def safe_apply_async(task, args=None, kwargs=None, countdown=None):
    """
    Safely enqueues a Celery task. If Redis/broker is unreachable or fails,
    logs a warning and returns None without raising an unhandled exception
    to the caller, ensuring database-persisted intent can be recovered later.
    """
    try:
        return task.apply_async(args=args, kwargs=kwargs, countdown=countdown)
    except Exception as exc:
        task_name = getattr(task, "name", str(task))
        logger.warning(
            "Broker unavailable when queueing '%s'. Task state remains persisted in PostgreSQL: %s",
            task_name,
            exc,
        )
        return None

import logging
from typing import Any
from uuid import UUID

from app.core import database
from app.core.celery_app import celery_app
from app.services.playbook_trigger_service import (
    evaluate_incident_triggers,
    evaluate_ioc_triggers,
)

logger = logging.getLogger("sentinelops.playbook_tasks")


@celery_app.task(
    bind=True,
    name="app.tasks.playbook_tasks.evaluate_incident_triggers_task",
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
)
def evaluate_incident_triggers_task(
    self: Any,
    incident_id: str,
    event_type: str,
    previous_state: dict[str, Any] | None = None,
    actor_user_id: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Asynchronously evaluates response playbooks for an incident event."""
    logger.info("Evaluating incident triggers for %s (event: %s)", incident_id, event_type)
    inc_uuid = UUID(incident_id)
    actor_uuid = UUID(actor_user_id) if actor_user_id else None

    with database.SessionLocal() as db:
        executions = evaluate_incident_triggers(
            db=db,
            incident_id=inc_uuid,
            event_type=event_type,
            previous_state=previous_state,
            actor_user_id=actor_uuid,
            event_id=event_id,
        )
        return {
            "incident_id": incident_id,
            "event_type": event_type,
            "executions_created": len(executions),
            "execution_ids": [str(e.id) for e in executions],
        }


@celery_app.task(
    bind=True,
    name="app.tasks.playbook_tasks.evaluate_ioc_triggers_task",
    max_retries=3,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
)
def evaluate_ioc_triggers_task(
    self: Any,
    ioc_id: str,
    event_type: str,
    previous_verdict: str | None = None,
    actor_user_id: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Asynchronously evaluates response playbooks for an IOC threat verdict update."""
    logger.info("Evaluating IOC triggers for %s (event: %s)", ioc_id, event_type)
    ioc_uuid = UUID(ioc_id)
    actor_uuid = UUID(actor_user_id) if actor_user_id else None

    with database.SessionLocal() as db:
        executions = evaluate_ioc_triggers(
            db=db,
            ioc_id=ioc_uuid,
            event_type=event_type,
            previous_verdict=previous_verdict,
            actor_user_id=actor_uuid,
            event_id=event_id,
        )
        return {
            "ioc_id": ioc_id,
            "event_type": event_type,
            "executions_created": len(executions),
            "execution_ids": [str(e.id) for e in executions],
        }

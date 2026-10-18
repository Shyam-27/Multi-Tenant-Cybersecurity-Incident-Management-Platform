from datetime import datetime, timezone
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select

from app.core import database
from app.core.celery_app import celery_app, safe_apply_async
from app.models.ioc import IndicatorOfCompromise, ThreatVerdict
from app.models.job import BackgroundJob, JobStatus, JobType
from app.models.user import User
from app.services.threat_intel.service import get_threat_intel_service

logger = logging.getLogger("sentinelops.threat_intel_tasks")


@celery_app.task(bind=True, acks_late=True)
def refresh_threat_intel_task(
    self,
    ioc_id: str,
    tenant_id: str,
    force_refresh: bool = True,
    actor_user_id: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """
    Asynchronously refreshes threat intelligence for an IOC.
    Strict anti-tampering rule: provider timeouts and errors never result in a BENIGN verdict.
    """
    now = datetime.now(timezone.utc)
    threat_service = get_threat_intel_service()

    with database.SessionLocal() as db:
        # Load associated BackgroundJob if supplied
        job = None
        if job_id:
            job = db.scalar(select(BackgroundJob).where(BackgroundJob.id == UUID(job_id)))
            if job:
                job.status = JobStatus.RUNNING.value
                job.started_at = now
                job.attempt_count += 1
                db.commit()

        # Load IOC ensuring tenant isolation
        ioc = db.scalar(
            select(IndicatorOfCompromise).where(
                IndicatorOfCompromise.id == UUID(ioc_id),
                IndicatorOfCompromise.tenant_id == UUID(tenant_id),
            )
        )
        if not ioc:
            msg = f"IOC {ioc_id} not found for tenant {tenant_id}"
            if job:
                job.status = JobStatus.FAILED.value
                job.error_message = msg
                job.completed_at = now
                db.commit()
            return {"status": "FAILED", "error": msg}

        actor_user = None
        if actor_user_id:
            actor_user = db.scalar(select(User).where(User.id == UUID(actor_user_id)))

        try:
            enriched = threat_service.enrich_indicator(
                db=db,
                indicator=ioc,
                force_refresh=force_refresh,
                actor_user=actor_user,
            )

            # Strict verification of anti-tampering verdict
            raw_providers = enriched.raw_enrichment_data.get("providers", {})
            has_errors = any(bool(res.get("error")) for res in raw_providers.values())
            if has_errors and enriched.threat_verdict == ThreatVerdict.BENIGN.value:
                # Security violation safeguard: override to UNKNOWN
                logger.critical(
                    "Anti-tampering violation intercepted: provider error coincided with BENIGN verdict. Forcing UNKNOWN."
                )
                enriched.threat_verdict = ThreatVerdict.UNKNOWN.value
                db.commit()

            result = {
                "ioc_id": str(enriched.id),
                "indicator_type": enriched.indicator_type,
                "value": enriched.value,
                "verdict": enriched.threat_verdict,
                "confidence_score": enriched.confidence_score,
                "severity": enriched.severity,
            }

            if job:
                job.status = JobStatus.COMPLETED.value
                job.completed_at = datetime.now(timezone.utc)
                job.result_summary = result
                db.commit()

            return {"status": "COMPLETED", "data": result}

        except Exception as exc:
            logger.error("Failed to enrich IOC %s: %s", ioc_id, exc, exc_info=True)
            if job:
                job.status = JobStatus.FAILED.value
                job.completed_at = datetime.now(timezone.utc)
                job.error_message = str(exc)[:500]
                db.commit()
            return {"status": "FAILED", "error": str(exc)}


@celery_app.task(name="app.tasks.threat_intel_tasks.scheduled_threat_intel_refresh_task")
def scheduled_threat_intel_refresh_task(batch_limit: int = 50) -> int:
    """
    Periodic job: identifies stale or un-enriched IOCs and enqueues background refreshes.
    Respects provider rate-limit bounds via batch limits.
    """
    now = datetime.now(timezone.utc)
    enqueued_count = 0

    with database.SessionLocal() as db:
        stale_iocs = db.scalars(
            select(IndicatorOfCompromise)
            .where(
                IndicatorOfCompromise.is_false_positive == False,
                or_(
                    IndicatorOfCompromise.enriched_at.is_(None),
                    IndicatorOfCompromise.expires_at <= now,
                ),
            )
            .limit(batch_limit)
        ).all()

        for ioc in stale_iocs:
            safe_apply_async(
                refresh_threat_intel_task,
                args=[str(ioc.id), str(ioc.tenant_id), True],
            )
            enqueued_count += 1

    return enqueued_count

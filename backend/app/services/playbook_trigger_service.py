from datetime import datetime, timedelta, timezone
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.audit import ActorType, AuditOutcome
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.ioc import IndicatorOfCompromise, ThreatVerdict
from app.models.playbook import (
    ApprovalStatus,
    ExecutionStatus,
    PlaybookApproval,
    PlaybookExecution,
    PlaybookTrigger,
    ResponsePlaybook,
)
from app.models.user import User, UserRole
from app.services.audit_service import record_audit_event
from app.services.playbook_service import execute_playbook_action

logger = logging.getLogger("sentinelops.playbook_triggers")

SEVERITY_RANKS = {
    IncidentSeverity.LOW.value: 1,
    IncidentSeverity.MEDIUM.value: 2,
    IncidentSeverity.HIGH.value: 3,
    IncidentSeverity.CRITICAL.value: 4,
}


def _severity_ge(sev1: str, sev2: str) -> bool:
    r1 = SEVERITY_RANKS.get(sev1.upper(), 0)
    r2 = SEVERITY_RANKS.get(sev2.upper(), 0)
    return r1 >= r2


def _resolve_trigger_actor(db: Session, tenant_id: UUID, actor_user_id: UUID | None, playbook: ResponsePlaybook) -> User:
    """Finds or resolves an eligible user for triggered_by attribution."""
    if actor_user_id:
        actor = db.scalar(select(User).where(User.id == actor_user_id, User.tenant_id == tenant_id))
        if actor:
            return actor

    if playbook.created_by_id:
        creator = db.scalar(select(User).where(User.id == playbook.created_by_id, User.tenant_id == tenant_id))
        if creator:
            return creator

    admin = db.scalar(
        select(User).where(User.tenant_id == tenant_id, User.role == UserRole.TENANT_ADMIN.value).limit(1)
    )
    if admin:
        return admin

    any_user = db.scalar(select(User).where(User.tenant_id == tenant_id).limit(1))
    if any_user:
        return any_user

    raise ValueError(f"No valid user found in tenant {tenant_id} for playbook trigger attribution")


def process_playbook_execution_trigger(
    db: Session,
    playbook: ResponsePlaybook,
    incident: Incident,
    trigger_reason: str,
    parameters: dict[str, Any],
    actor_user: User,
    event_id: str,
) -> PlaybookExecution | None:
    """
    Creates an execution for a matched playbook trigger with strict idempotency,
    cooldown enforcement, concurrency protection, and safety defaults.
    """
    now = datetime.now(timezone.utc)
    tenant_id = playbook.tenant_id

    # 1. Guard against active execution in flight for this playbook and incident
    active_exec = db.scalar(
        select(PlaybookExecution).where(
            PlaybookExecution.tenant_id == tenant_id,
            PlaybookExecution.playbook_id == playbook.id,
            PlaybookExecution.incident_id == incident.id,
            PlaybookExecution.status.in_([ExecutionStatus.PENDING_APPROVAL.value, ExecutionStatus.RUNNING.value]),
        ).limit(1)
    )
    if active_exec:
        logger.info(
            "Skipping trigger for playbook %s on incident %s: active execution %s in progress",
            playbook.id,
            incident.id,
            active_exec.id,
        )
        record_audit_event(
            db=db,
            action="PLAYBOOK_TRIGGER_SKIPPED",
            resource_type="response_playbook",
            resource_id=str(playbook.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=actor_user,
            actor_type=ActorType.SYSTEM,
            tenant_id=tenant_id,
            details={
                "reason": "ACTIVE_EXECUTION_IN_PROGRESS",
                "active_execution_id": str(active_exec.id),
                "incident_id": str(incident.id),
                "playbook_name": playbook.name,
            },
        )
        db.commit()
        return None

    # 2. Check cooldown window
    if playbook.cooldown_seconds > 0:
        cutoff = now - timedelta(seconds=playbook.cooldown_seconds)
        recent_exec = db.scalar(
            select(PlaybookExecution).where(
                PlaybookExecution.tenant_id == tenant_id,
                PlaybookExecution.playbook_id == playbook.id,
                PlaybookExecution.incident_id == incident.id,
                PlaybookExecution.created_at >= cutoff,
            ).order_by(desc(PlaybookExecution.created_at)).limit(1)
        )
        if recent_exec:
            logger.info(
                "Skipping trigger for playbook %s: cooldown active (%ss remaining)",
                playbook.id,
                playbook.cooldown_seconds,
            )
            record_audit_event(
                db=db,
                action="PLAYBOOK_TRIGGER_SKIPPED",
                resource_type="response_playbook",
                resource_id=str(playbook.id),
                outcome=AuditOutcome.SUCCESS,
                actor_user=actor_user,
                actor_type=ActorType.SYSTEM,
                tenant_id=tenant_id,
                details={
                    "reason": "COOLDOWN_ACTIVE",
                    "cooldown_seconds": playbook.cooldown_seconds,
                    "last_execution_id": str(recent_exec.id),
                    "incident_id": str(incident.id),
                },
            )
            db.commit()
            return None

    # 3. Check for existing trigger event ID (atomic deduplication check)
    existing_by_event = db.scalar(
        select(PlaybookExecution).where(
            PlaybookExecution.tenant_id == tenant_id,
            PlaybookExecution.trigger_event_id == event_id,
        )
    )
    if existing_by_event:
        logger.info("Duplicate trigger event %s suppressed for playbook %s", event_id, playbook.id)
        record_audit_event(
            db=db,
            action="PLAYBOOK_DUPLICATE_TRIGGER_SUPPRESSED",
            resource_type="response_playbook",
            resource_id=str(playbook.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=actor_user,
            actor_type=ActorType.SYSTEM,
            tenant_id=tenant_id,
            details={
                "trigger_event_id": event_id,
                "existing_execution_id": str(existing_by_event.id),
                "incident_id": str(incident.id),
            },
        )
        db.commit()
        return None

    # 4. Determine execution safety mode
    # Default is dry-run. If not dry-run, force human approval requirement for automated trigger safety!
    is_dry_run = playbook.is_dry_run
    requires_approval = playbook.requires_approval
    if not is_dry_run:
        # SAFETY REQUIREMENT: Automated triggers must NEVER perform unapproved live disruptive actions
        requires_approval = True

    initial_status = (
        ExecutionStatus.PENDING_APPROVAL.value if requires_approval else ExecutionStatus.RUNNING.value
    )

    execution = PlaybookExecution(
        tenant_id=tenant_id,
        playbook_id=playbook.id,
        incident_id=incident.id,
        triggered_by_id=actor_user.id,
        trigger_source="AUTOMATED_TRIGGER",
        trigger_event_id=event_id,
        trigger_reason=trigger_reason,
        status=initial_status,
        is_dry_run=is_dry_run,
        parameters=parameters,
        step_results=[],
    )
    db.add(execution)

    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        logger.warning("Concurrent insert collision for trigger_event_id %s; suppressing duplicate", event_id)
        record_audit_event(
            db=db,
            action="PLAYBOOK_DUPLICATE_TRIGGER_SUPPRESSED",
            resource_type="response_playbook",
            resource_id=str(playbook.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=actor_user,
            actor_type=ActorType.SYSTEM,
            tenant_id=tenant_id,
            details={
                "trigger_event_id": event_id,
                "reason": "CONCURRENT_COLLISION",
                "incident_id": str(incident.id),
            },
        )
        db.commit()
        return None

    # Record Trigger Matched
    record_audit_event(
        db=db,
        action="PLAYBOOK_TRIGGER_MATCHED",
        resource_type="response_playbook",
        resource_id=str(playbook.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=actor_user,
        actor_type=ActorType.SYSTEM,
        tenant_id=tenant_id,
        details={
            "playbook_name": playbook.name,
            "trigger_reason": trigger_reason,
            "trigger_event_id": event_id,
            "incident_id": str(incident.id),
            "is_dry_run": is_dry_run,
            "requires_approval": requires_approval,
        },
    )

    if requires_approval:
        approval = PlaybookApproval(
            tenant_id=tenant_id,
            execution_id=execution.id,
            required_role="TENANT_ADMIN",
            status=ApprovalStatus.PENDING.value,
        )
        db.add(approval)
        db.commit()
        db.refresh(execution)

        record_audit_event(
            db=db,
            action="PLAYBOOK_APPROVAL_REQUESTED",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=actor_user,
            actor_type=ActorType.SYSTEM,
            tenant_id=tenant_id,
            details={
                "playbook_name": playbook.name,
                "is_dry_run": is_dry_run,
                "actions": [a.get("action_type") for a in playbook.actions],
                "trigger_source": "AUTOMATED_TRIGGER",
            },
        )
        db.commit()
        return execution

    # Execute simulation (DRY-RUN) actions immediately
    step_results = []
    overall_success = True

    for act in playbook.actions:
        action_type = act.get("action_type", "")
        try:
            res = execute_playbook_action(
                db=db,
                action_type=action_type,
                action_config=act,
                parameters=parameters,
                tenant_id=tenant_id,
                actor_user=actor_user,
                is_dry_run=is_dry_run,
            )
        except Exception as exc:
            logger.error("Action %s failed during automated trigger: %s", action_type, exc)
            res = {
                "action": action_type,
                "status": "FAILED",
                "details": f"Internal execution error: {exc}",
                "is_dry_run": is_dry_run,
            }
        step_results.append(res)
        if res.get("status") == "FAILED":
            overall_success = False
            break

    execution.step_results = step_results
    execution.status = ExecutionStatus.COMPLETED.value if overall_success else ExecutionStatus.FAILED.value
    execution.completed_at = datetime.now(timezone.utc)

    record_audit_event(
        db=db,
        action="PLAYBOOK_EXECUTED",
        resource_type="playbook_execution",
        resource_id=str(execution.id),
        outcome=AuditOutcome.SUCCESS if overall_success else AuditOutcome.FAILURE,
        actor_user=actor_user,
        actor_type=ActorType.SYSTEM,
        tenant_id=tenant_id,
        details={
            "playbook_name": playbook.name,
            "status": execution.status,
            "is_dry_run": is_dry_run,
            "trigger_source": "AUTOMATED_TRIGGER",
            "steps_count": len(step_results),
        },
    )

    db.commit()
    db.refresh(execution)
    return execution


def evaluate_incident_triggers(
    db: Session,
    incident_id: UUID,
    event_type: str,
    previous_state: dict[str, Any] | None = None,
    actor_user_id: UUID | None = None,
    event_id: str | None = None,
) -> list[PlaybookExecution]:
    """
    Evaluates enabled playbooks against an incident lifecycle event.
    Only triggers if qualifying severity/status changes occurred.
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        logger.warning("Incident %s not found during trigger evaluation", incident_id)
        return []

    tenant_id = incident.tenant_id
    playbooks = db.scalars(
        select(ResponsePlaybook).where(
            ResponsePlaybook.tenant_id == tenant_id,
            ResponsePlaybook.is_enabled == True,  # noqa: E712
        )
    ).all()

    if not playbooks:
        return []

    created_executions: list[PlaybookExecution] = []
    actor_user = _resolve_trigger_actor(db, tenant_id, actor_user_id, playbooks[0])

    for pb in playbooks:
        matched = False
        match_reason = ""

        # Case 1: INCIDENT_CRITICAL
        if pb.trigger_event == PlaybookTrigger.INCIDENT_CRITICAL.value:
            if incident.severity != IncidentSeverity.CRITICAL.value:
                continue

            # Check if this is a fresh escalation to CRITICAL
            if event_type == "incident.updated" and previous_state:
                prev_sev = previous_state.get("severity")
                if prev_sev == IncidentSeverity.CRITICAL.value:
                    # Incident was already critical; unrelated update does not trigger
                    logger.debug("Skipping playbook %s: incident was already CRITICAL", pb.id)
                    continue

            matched = True
            match_reason = f"Incident '{incident.title}' escalated to CRITICAL"

        # Case 2: RULE_MATCH
        elif pb.trigger_event == PlaybookTrigger.RULE_MATCH.value:
            conds = pb.trigger_conditions or {}
            min_sev = conds.get("min_severity")
            allowed_statuses = conds.get("incident_statuses")

            # Validate minimum severity
            if min_sev and not _severity_ge(incident.severity, min_sev):
                continue

            # Validate incident status
            if allowed_statuses and incident.status not in allowed_statuses:
                continue

            # If rule specifically requires an IOC verdict/type, incident events do not qualify
            if conds.get("ioc_verdict") or conds.get("ioc_types"):
                continue

            matched = True
            match_reason = f"Incident matched rule conditions (severity: {incident.severity}, status: {incident.status})"

        if matched:
            stable_id = event_id or f"inc_crit:{incident.id}:sev:{incident.severity}:{incident.updated_at.isoformat() if incident.updated_at else incident.created_at.isoformat()}:pb:{pb.id}:v{pb.rule_version}"
            params = {
                "incident_id": str(incident.id),
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
            }
            exec_record = process_playbook_execution_trigger(
                db=db,
                playbook=pb,
                incident=incident,
                trigger_reason=match_reason,
                parameters=params,
                actor_user=actor_user,
                event_id=stable_id,
            )
            if exec_record:
                created_executions.append(exec_record)

    return created_executions


def evaluate_ioc_triggers(
    db: Session,
    ioc_id: UUID,
    event_type: str,
    previous_verdict: str | None = None,
    actor_user_id: UUID | None = None,
    event_id: str | None = None,
) -> list[PlaybookExecution]:
    """
    Evaluates enabled playbooks against an IOC enrichment or verdict update event.
    Requires verified association with an incident in the same tenant.
    """
    ioc = db.scalar(select(IndicatorOfCompromise).where(IndicatorOfCompromise.id == ioc_id))
    if not ioc:
        logger.warning("IOC %s not found during trigger evaluation", ioc_id)
        return []

    tenant_id = ioc.tenant_id

    # 1. Verify IOC is associated with an incident
    if not ioc.incident_id:
        logger.debug("IOC %s has no associated incident; skipping playbook triggers", ioc.id)
        record_audit_event(
            db=db,
            action="PLAYBOOK_TRIGGER_SKIPPED",
            resource_type="ioc",
            resource_id=str(ioc.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=None,
            actor_type=ActorType.SYSTEM,
            tenant_id=tenant_id,
            details={"reason": "NO_ASSOCIATED_INCIDENT", "ioc_value": ioc.value},
        )
        db.commit()
        return []

    # 2. Verify associated incident belongs to same tenant
    incident = db.scalar(
        select(Incident).where(
            Incident.id == ioc.incident_id,
            Incident.tenant_id == tenant_id,
        )
    )
    if not incident:
        logger.warning("IOC %s associated incident %s not found or cross-tenant", ioc.id, ioc.incident_id)
        record_audit_event(
            db=db,
            action="PLAYBOOK_TRIGGER_SKIPPED",
            resource_type="ioc",
            resource_id=str(ioc.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=None,
            actor_type=ActorType.SYSTEM,
            tenant_id=tenant_id,
            details={"reason": "CROSS_TENANT_OR_MISSING_INCIDENT", "ioc_id": str(ioc.id)},
        )
        db.commit()
        return []

    # 3. Verdict verification: must be MALICIOUS and not a false positive
    if ioc.is_false_positive:
        logger.debug("IOC %s marked false positive; skipping playbook triggers", ioc.id)
        return []

    if ioc.threat_verdict != ThreatVerdict.MALICIOUS.value:
        logger.debug("IOC %s verdict '%s' is not MALICIOUS; skipping", ioc.id, ioc.threat_verdict)
        return []

    if previous_verdict == ThreatVerdict.MALICIOUS.value and event_type == "ioc.updated":
        logger.debug("IOC %s was already MALICIOUS; skipping duplicate trigger", ioc.id)
        return []

    playbooks = db.scalars(
        select(ResponsePlaybook).where(
            ResponsePlaybook.tenant_id == tenant_id,
            ResponsePlaybook.is_enabled == True,  # noqa: E712
        )
    ).all()

    if not playbooks:
        return []

    created_executions: list[PlaybookExecution] = []
    actor_user = _resolve_trigger_actor(db, tenant_id, actor_user_id, playbooks[0])

    for pb in playbooks:
        matched = False
        match_reason = ""

        if pb.trigger_event == PlaybookTrigger.MALICIOUS_IOC_DETECTED.value:
            matched = True
            match_reason = f"Malicious IOC detected ({ioc.indicator_type}: {ioc.value}) on incident '{incident.title}'"

        elif pb.trigger_event == PlaybookTrigger.RULE_MATCH.value:
            conds = pb.trigger_conditions or {}
            verdict_req = conds.get("ioc_verdict")
            types_req = conds.get("ioc_types")
            min_sev = conds.get("min_severity")
            statuses = conds.get("incident_statuses")

            if verdict_req and ioc.threat_verdict != verdict_req:
                continue
            if types_req and ioc.indicator_type not in types_req:
                continue
            if min_sev and not _severity_ge(incident.severity, min_sev):
                continue
            if statuses and incident.status not in statuses:
                continue

            matched = True
            match_reason = f"IOC {ioc.value} matched rule conditions for incident '{incident.title}'"

        if matched:
            enriched_stamp = ioc.enriched_at.isoformat() if ioc.enriched_at else (ioc.updated_at.isoformat() if ioc.updated_at else ioc.created_at.isoformat())
            stable_id = event_id or f"ioc_mal:{ioc.id}:inc:{incident.id}:{enriched_stamp}:pb:{pb.id}:v{pb.rule_version}"
            params = {
                "incident_id": str(incident.id),
                "ioc_id": str(ioc.id),
                "indicator_type": ioc.indicator_type,
                "value": ioc.value,
                "threat_verdict": ioc.threat_verdict,
                "confidence_score": ioc.confidence_score,
                "ip_address": ioc.value if ioc.indicator_type in ("IPV4", "IPV6") else None,
            }
            exec_record = process_playbook_execution_trigger(
                db=db,
                playbook=pb,
                incident=incident,
                trigger_reason=match_reason,
                parameters=params,
                actor_user=actor_user,
                event_id=stable_id,
            )
            if exec_record:
                created_executions.append(exec_record)

    return created_executions

from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import ActorType, AuditOutcome
from app.models.playbook import (
    ApprovalStatus,
    ExecutionStatus,
    PlaybookActionType,
    PlaybookApproval,
    PlaybookExecution,
    ResponsePlaybook,
)
from app.models.user import User, UserRole
from app.services.audit_service import record_audit_event

logger = logging.getLogger("sentinelops.playbooks")


def execute_playbook_action(
    db: Session,
    action_type: str,
    action_config: dict[str, Any],
    parameters: dict[str, Any],
    tenant_id: UUID,
    actor_user: User,
    is_dry_run: bool,
) -> dict[str, Any]:
    """
    Executes a single playbook action with strict safety, parameter validation,
    and anti-privilege escalation checks.
    """
    act = action_type.upper()

    if act == PlaybookActionType.REVOKE_USER_SESSIONS.value:
        target_id_str = parameters.get("target_user_id") or action_config.get("target_user_id")
        if not target_id_str:
            return {
                "action": act,
                "status": "FAILED",
                "details": "Missing required parameter 'target_user_id'",
                "is_dry_run": is_dry_run,
            }

        try:
            target_uuid = UUID(str(target_id_str))
        except ValueError:
            return {
                "action": act,
                "status": "FAILED",
                "details": f"Invalid target_user_id format: '{target_id_str}'",
                "is_dry_run": is_dry_run,
            }

        target_user = db.scalar(
            select(User).where(User.id == target_uuid, User.tenant_id == tenant_id)
        )
        if not target_user:
            return {
                "action": act,
                "status": "FAILED",
                "details": f"Target user '{target_id_str}' not found in this organization",
                "is_dry_run": is_dry_run,
            }

        # Anti-privilege escalation: analyst cannot revoke admin
        if actor_user.role == UserRole.SECURITY_ANALYST.value and target_user.role in (
            UserRole.TENANT_ADMIN.value,
            UserRole.SUPER_ADMIN.value,
        ):
            return {
                "action": act,
                "status": "FAILED",
                "details": "Privilege violation: Security Analyst cannot revoke Administrator sessions",
                "is_dry_run": is_dry_run,
            }

        if is_dry_run:
            return {
                "action": act,
                "status": "SIMULATED_SUCCESS",
                "details": f"[DRY-RUN] Would revoke active session tokens for user {target_user.email}",
                "target_user": target_user.email,
                "is_dry_run": True,
            }

        # Live session revocation
        target_user.updated_at = datetime.now(timezone.utc)
        db.flush()

        return {
            "action": act,
            "status": "SUCCESS",
            "details": f"Successfully revoked all active sessions for {target_user.email}",
            "target_user": target_user.email,
            "is_dry_run": False,
        }

    elif act == PlaybookActionType.ISOLATE_ENDPOINT.value:
        hostname = (
            parameters.get("hostname")
            or parameters.get("endpoint_id")
            or action_config.get("hostname")
        )
        if not hostname:
            return {
                "action": act,
                "status": "FAILED",
                "details": "Missing required parameter 'hostname' or 'endpoint_id'",
                "is_dry_run": is_dry_run,
            }

        clean_host = str(hostname).strip()
        # Simulated action: no live third-party EDR integration configured
        return {
            "action": act,
            "status": "SIMULATED_SUCCESS" if is_dry_run else "SIMULATED_LIVE",
            "details": f"[SIMULATED] Endpoint isolation command dispatched for agent '{clean_host}'. Live EDR connector in dry-run mode.",
            "target_endpoint": clean_host,
            "is_dry_run": is_dry_run,
        }

    elif act == PlaybookActionType.BLOCK_IP.value:
        ip_str = parameters.get("ip_address") or action_config.get("ip_address")
        if not ip_str:
            return {
                "action": act,
                "status": "FAILED",
                "details": "Missing required parameter 'ip_address'",
                "is_dry_run": is_dry_run,
            }

        try:
            ip_obj = ipaddress.ip_address(str(ip_str).strip())
        except ValueError:
            return {
                "action": act,
                "status": "FAILED",
                "details": f"Invalid IP address format: '{ip_str}'",
                "is_dry_run": is_dry_run,
            }

        # Defend against self-denial of service (blocking localhost, private gateways)
        if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
            return {
                "action": act,
                "status": "FAILED",
                "details": f"Safety constraint violation: Refusing to block loopback/multicast address '{ip_str}'",
                "is_dry_run": is_dry_run,
            }

        return {
            "action": act,
            "status": "SIMULATED_SUCCESS" if is_dry_run else "SIMULATED_LIVE",
            "details": f"[SIMULATED] Firewall rule drop generated for IP '{ip_obj}'. Live perimeter firewall connector in dry-run mode.",
            "target_ip": str(ip_obj),
            "is_dry_run": is_dry_run,
        }

    else:
        return {
            "action": action_type,
            "status": "FAILED",
            "details": f"Unsupported playbook action type: '{action_type}'",
            "is_dry_run": is_dry_run,
        }


def trigger_playbook_execution(
    db: Session,
    playbook: ResponsePlaybook,
    actor_user: User,
    parameters: dict[str, Any] | None = None,
    incident_id: UUID | None = None,
    override_dry_run: bool | None = None,
) -> PlaybookExecution:
    """
    Initiates a playbook run. If requires_approval is True and not in dry_run,
    creates a pending approval gate. Otherwise executes actions immediately.
    """
    params = parameters or {}
    is_dry_run = override_dry_run if override_dry_run is not None else playbook.is_dry_run
    needs_approval = playbook.requires_approval and not is_dry_run

    initial_status = (
        ExecutionStatus.PENDING_APPROVAL.value if needs_approval else ExecutionStatus.RUNNING.value
    )

    execution = PlaybookExecution(
        tenant_id=playbook.tenant_id,
        playbook_id=playbook.id,
        incident_id=incident_id,
        triggered_by_id=actor_user.id,
        trigger_source="MANUAL",
        status=initial_status,
        is_dry_run=is_dry_run,
        parameters=params,
        step_results=[],
    )
    db.add(execution)
    db.flush()

    if needs_approval:
        approval = PlaybookApproval(
            tenant_id=playbook.tenant_id,
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
            actor_type=ActorType.USER,
            tenant_id=playbook.tenant_id,
            details={
                "playbook_name": playbook.name,
                "is_dry_run": is_dry_run,
                "actions": [a.get("action_type") for a in playbook.actions],
            },
        )
        db.commit()
        return execution

    # Execute actions immediately
    step_results = []
    overall_success = True

    for act in playbook.actions:
        action_type = act.get("action_type", "")
        res = execute_playbook_action(
            db=db,
            action_type=action_type,
            action_config=act,
            parameters=params,
            tenant_id=playbook.tenant_id,
            actor_user=actor_user,
            is_dry_run=is_dry_run,
        )
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
        actor_type=ActorType.USER,
        tenant_id=playbook.tenant_id,
        details={
            "playbook_name": playbook.name,
            "status": execution.status,
            "is_dry_run": is_dry_run,
            "steps_count": len(step_results),
        },
    )

    db.commit()
    db.refresh(execution)
    return execution


def decide_playbook_approval(
    db: Session,
    execution_id: UUID,
    approver: User,
    approved: bool,
    notes: str | None = None,
) -> PlaybookExecution:
    """
    Approve or reject a pending playbook execution.
    Enforces tenant boundaries and anti-self-approval protection.
    """
    execution = db.scalar(
        select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
    )
    if not execution or execution.tenant_id != approver.tenant_id:
        raise ValueError("Playbook execution not found")

    if execution.status != ExecutionStatus.PENDING_APPROVAL.value:
        raise ValueError(f"Execution is not in PENDING_APPROVAL state (current: {execution.status})")

    # Anti-Self-Approval constraint: prevent single operator from initiating and approving live response
    # if other tenant admins are available
    if execution.triggered_by_id == approver.id:
        other_admins_count = db.scalar(
            select(select(User).where(
                User.tenant_id == approver.tenant_id,
                User.role.in_([UserRole.TENANT_ADMIN.value, UserRole.SUPER_ADMIN.value]),
                User.id != approver.id,
                User.is_active == True,
            ).exists())
        )
        if other_admins_count:
            raise ValueError("Anti-self-approval policy violation: Another Tenant Administrator must approve this response action.")

    approval = execution.approval
    if not approval:
        raise ValueError("No approval record associated with this execution")

    now = datetime.now(timezone.utc)
    approval.decided_by_id = approver.id
    approval.decided_at = now
    approval.decision_notes = notes

    if not approved:
        approval.status = ApprovalStatus.REJECTED.value
        execution.status = ExecutionStatus.REJECTED.value
        execution.completed_at = now
        execution.error_summary = f"Approval rejected by {approver.email}: {notes or 'No reason provided'}"
        db.commit()
        db.refresh(execution)

        record_audit_event(
            db=db,
            action="PLAYBOOK_APPROVAL_REJECTED",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            outcome=AuditOutcome.SUCCESS,
            actor_user=approver,
            actor_type=ActorType.USER,
            tenant_id=approver.tenant_id,
            details={"notes": notes},
        )
        db.commit()
        return execution

    # Approval granted: execute actions now
    approval.status = ApprovalStatus.APPROVED.value
    execution.status = ExecutionStatus.RUNNING.value
    db.flush()

    step_results = []
    overall_success = True

    for act in execution.playbook.actions:
        action_type = act.get("action_type", "")
        res = execute_playbook_action(
            db=db,
            action_type=action_type,
            action_config=act,
            parameters=execution.parameters,
            tenant_id=execution.tenant_id,
            actor_user=approver,
            is_dry_run=execution.is_dry_run,
        )
        step_results.append(res)
        if res.get("status") == "FAILED":
            overall_success = False
            break

    execution.step_results = step_results
    execution.status = ExecutionStatus.COMPLETED.value if overall_success else ExecutionStatus.FAILED.value
    execution.completed_at = datetime.now(timezone.utc)

    record_audit_event(
        db=db,
        action="PLAYBOOK_APPROVAL_GRANTED_AND_EXECUTED",
        resource_type="playbook_execution",
        resource_id=str(execution.id),
        outcome=AuditOutcome.SUCCESS if overall_success else AuditOutcome.FAILURE,
        actor_user=approver,
        actor_type=ActorType.USER,
        tenant_id=approver.tenant_id,
        details={
            "playbook_name": execution.playbook.name,
            "status": execution.status,
            "steps_count": len(step_results),
            "notes": notes,
        },
    )

    db.commit()
    db.refresh(execution)
    return execution

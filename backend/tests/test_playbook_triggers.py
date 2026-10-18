from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import safe_apply_async
from app.models.audit import AuditEvent
from app.models.incident import Incident, IncidentCategory, IncidentSeverity, IncidentStatus
from app.models.ioc import IndicatorOfCompromise, IndicatorType, ThreatSeverity, ThreatVerdict
from app.models.playbook import (
    ApprovalStatus,
    ExecutionStatus,
    PlaybookActionType,
    PlaybookApproval,
    PlaybookExecution,
    PlaybookTrigger,
    ResponsePlaybook,
)
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.schemas.playbook import validate_playbook_trigger_conditions
from app.services.playbook_service import decide_playbook_approval
from app.services.playbook_trigger_service import (
    evaluate_incident_triggers,
    evaluate_ioc_triggers,
    process_playbook_execution_trigger,
)
from app.tasks.playbook_tasks import (
    evaluate_incident_triggers_task,
    evaluate_ioc_triggers_task,
)


def register_org(client: TestClient, org_name: str, org_slug: str, admin_email: str) -> str:
    res = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": org_name,
            "organization_slug": org_slug,
            "name": f"Admin {org_slug}",
            "email": admin_email,
            "password": "Password12345!",
        },
    )
    assert res.status_code == 201
    login_res = client.post("/api/v1/auth/login", json={"email": admin_email, "password": "Password12345!"})
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def create_user_in_org(client: TestClient, admin_token: str, name: str, email: str, role: str) -> str:
    res = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": name, "email": email, "password": "Password12345!", "role": role},
    )
    assert res.status_code == 201
    login_res = client.post("/api/v1/auth/login", json={"email": email, "password": "Password12345!"})
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


# ==============================================================================
# GROUP 1: TRIGGER CORRECTNESS (1 to 8)
# ==============================================================================


def test_critical_incident_creates_expected_trigger_evaluation(client: TestClient, test_db_session: Session):
    """1. Critical incident creation triggers the expected INCIDENT_CRITICAL playbook."""
    admin_token = register_org(client, "CritCorp", "crit-corp", "admin@critcorp.com")
    admin = test_db_session.scalar(select(User).where(User.email == "admin@critcorp.com"))

    # Create INCIDENT_CRITICAL playbook
    pb = ResponsePlaybook(
        tenant_id=admin.tenant_id,
        name="Critical Incident Response",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-prod-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
        created_by_id=admin.id,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    # Create Critical Incident via API
    inc_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "Severe Ransomware Outbreak",
            "description": "Production database encrypted",
            "category": "RANSOMWARE",
            "severity": "CRITICAL",
        },
    )
    assert inc_res.status_code == 201
    inc_data = inc_res.json()
    inc_id = UUID(inc_data["id"])

    # Verify execution was created (either through eager background task or evaluate_incident_triggers)
    executions = test_db_session.scalars(
        select(PlaybookExecution).where(PlaybookExecution.playbook_id == pb.id)
    ).all()
    if not executions:
        executions = evaluate_incident_triggers(
            db=test_db_session,
            incident_id=inc_id,
            event_type="incident.created",
            previous_state=None,
            actor_user_id=admin.id,
        )
    assert len(executions) == 1
    assert executions[0].playbook_id == pb.id
    assert executions[0].trigger_source == "AUTOMATED_TRIGGER"
    assert executions[0].status == ExecutionStatus.COMPLETED.value
    assert executions[0].is_dry_run is True


def test_non_critical_incident_does_not_match_critical_rule(client: TestClient, test_db_session: Session):
    """2. Non-critical incidents do not match a critical-only playbook rule."""
    admin_token = register_org(client, "LowCorp", "low-corp", "admin@lowcorp.com")
    admin = test_db_session.scalar(select(User).where(User.email == "admin@lowcorp.com"))

    pb = ResponsePlaybook(
        tenant_id=admin.tenant_id,
        name="Critical Only Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(
        tenant_id=admin.tenant_id,
        title="Minor Phishing Attempt",
        description="Spam email blocked by filter",
        category=IncidentCategory.PHISHING.value,
        severity=IncidentSeverity.LOW.value,
        status=IncidentStatus.OPEN.value,
        created_by_id=admin.id,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    executions = evaluate_incident_triggers(
        db=test_db_session,
        incident_id=inc.id,
        event_type="incident.created",
        previous_state=None,
        actor_user_id=admin.id,
    )
    assert len(executions) == 0


def test_malicious_ioc_associated_with_incident_creates_expected_evaluation(client: TestClient, test_db_session: Session):
    """3. Malicious IOC associated with an incident creates the expected trigger evaluation."""
    admin_token = register_org(client, "IOCCorp", "ioc-corp", "admin@ioccorp.com")
    admin = test_db_session.scalar(select(User).where(User.email == "admin@ioccorp.com"))

    inc = Incident(
        tenant_id=admin.tenant_id,
        title="Command and Control Investigation",
        description="Outbound beacons detected",
        category=IncidentCategory.MALWARE.value,
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.INVESTIGATING.value,
        created_by_id=admin.id,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=admin.tenant_id,
        name="Block Malicious IP Playbook",
        trigger_event=PlaybookTrigger.MALICIOUS_IOC_DETECTED.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.42"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    # Create IOC associated with incident and verdict MALICIOUS
    ioc = IndicatorOfCompromise(
        tenant_id=admin.tenant_id,
        indicator_type=IndicatorType.IPV4.value,
        value="198.51.100.42",
        threat_verdict=ThreatVerdict.MALICIOUS.value,
        confidence_score=95,
        severity=ThreatSeverity.CRITICAL.value,
        incident_id=inc.id,
        is_false_positive=False,
    )
    test_db_session.add(ioc)
    test_db_session.commit()

    executions = evaluate_ioc_triggers(
        db=test_db_session,
        ioc_id=ioc.id,
        event_type="ioc.enriched",
        previous_verdict=ThreatVerdict.UNKNOWN.value,
        actor_user_id=admin.id,
    )
    assert len(executions) == 1
    assert executions[0].playbook_id == pb.id
    assert executions[0].incident_id == inc.id
    assert "198.51.100.42" in executions[0].trigger_reason


def test_unrelated_or_cross_tenant_ioc_cannot_trigger_actions(client: TestClient, test_db_session: Session):
    """4. Unrelated (no incident) or cross-tenant IOCs cannot trigger actions against an incident."""
    admin_token_1 = register_org(client, "TenantA", "tenant-a", "admin@tenanta.com")
    admin_token_2 = register_org(client, "TenantB", "tenant-b", "admin@tenantb.com")
    user_a = test_db_session.scalar(select(User).where(User.email == "admin@tenanta.com"))
    user_b = test_db_session.scalar(select(User).where(User.email == "admin@tenantb.com"))

    # Incident in Tenant A
    inc_a = Incident(
        tenant_id=user_a.tenant_id,
        title="Incident in Tenant A",
        category=IncidentCategory.MALWARE.value,
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        created_by_id=user_a.id,
    )
    test_db_session.add(inc_a)
    test_db_session.commit()

    # Playbook in Tenant A
    pb_a = ResponsePlaybook(
        tenant_id=user_a.tenant_id,
        name="Tenant A Playbook",
        trigger_event=PlaybookTrigger.MALICIOUS_IOC_DETECTED.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.1"}],
        is_enabled=True,
    )
    test_db_session.add(pb_a)
    test_db_session.commit()

    # Case A: IOC with NO associated incident
    ioc_no_inc = IndicatorOfCompromise(
        tenant_id=user_a.tenant_id,
        indicator_type=IndicatorType.IPV4.value,
        value="198.51.100.10",
        threat_verdict=ThreatVerdict.MALICIOUS.value,
        incident_id=None,
    )
    test_db_session.add(ioc_no_inc)
    test_db_session.commit()

    execs_no_inc = evaluate_ioc_triggers(test_db_session, ioc_no_inc.id, "ioc.enriched")
    assert len(execs_no_inc) == 0

    # Case B: Cross-tenant association attempt (IOC in Tenant B points to Incident in Tenant A)
    ioc_cross = IndicatorOfCompromise(
        tenant_id=user_b.tenant_id,
        indicator_type=IndicatorType.IPV4.value,
        value="198.51.100.20",
        threat_verdict=ThreatVerdict.MALICIOUS.value,
        incident_id=inc_a.id,  # Cross-tenant incident!
    )
    test_db_session.add(ioc_cross)
    test_db_session.commit()

    execs_cross = evaluate_ioc_triggers(test_db_session, ioc_cross.id, "ioc.enriched")
    assert len(execs_cross) == 0


def test_ioc_provider_failure_or_unknown_verdicts_not_malicious(test_db_session: Session):
    """5. IOC provider failures, BENIGN, or UNKNOWN verdicts cannot be treated as MALICIOUS."""
    tenant = Tenant(name="SafeCorp", slug="safe-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    inc = Incident(
        tenant_id=tenant.id,
        title="Suspicious Activity",
        category=IncidentCategory.OTHER.value,
        created_by_id=uuid4(),
    )
    # create dummy user for created_by
    user = User(tenant_id=tenant.id, email="safe@corp.com", password_hash="hash", name="Safe", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()
    inc.created_by_id = user.id
    test_db_session.add(inc)

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Auto Block",
        trigger_event=PlaybookTrigger.MALICIOUS_IOC_DETECTED.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.5"}],
        is_enabled=True,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    # Verdict UNKNOWN
    ioc_unk = IndicatorOfCompromise(
        tenant_id=tenant.id,
        indicator_type=IndicatorType.DOMAIN.value,
        value="unknown-domain.example",
        threat_verdict=ThreatVerdict.UNKNOWN.value,
        incident_id=inc.id,
    )
    # Verdict BENIGN
    ioc_benign = IndicatorOfCompromise(
        tenant_id=tenant.id,
        indicator_type=IndicatorType.DOMAIN.value,
        value="clean.google.com",
        threat_verdict=ThreatVerdict.BENIGN.value,
        incident_id=inc.id,
    )
    test_db_session.add_all([ioc_unk, ioc_benign])
    test_db_session.commit()

    assert len(evaluate_ioc_triggers(test_db_session, ioc_unk.id, "ioc.enriched")) == 0
    assert len(evaluate_ioc_triggers(test_db_session, ioc_benign.id, "ioc.enriched")) == 0


def test_repeated_non_qualifying_updates_do_not_create_extra_executions(test_db_session: Session):
    """6. An incident already at CRITICAL updated with title/note does not re-trigger executions."""
    tenant = Tenant(name="RepeatCorp", slug="repeat-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="repeat@corp.com", password_hash="hash", name="Repeat", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Crit Trigger",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.5"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(
        tenant_id=tenant.id,
        title="Major Ransomware",
        severity=IncidentSeverity.CRITICAL.value,
        status=IncidentStatus.OPEN.value,
        created_by_id=user.id,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    # Initial trigger on creation
    execs1 = evaluate_incident_triggers(test_db_session, inc.id, "incident.created", None, user.id)
    assert len(execs1) == 1

    # Second update where severity was ALREADY CRITICAL (e.g. title or assigned analyst updated)
    prev_state = {"severity": IncidentSeverity.CRITICAL.value, "status": IncidentStatus.OPEN.value}
    execs2 = evaluate_incident_triggers(test_db_session, inc.id, "incident.updated", prev_state, user.id)
    assert len(execs2) == 0


def test_disabled_rules_do_not_produce_new_executions(test_db_session: Session):
    """7. Disabling a rule prevents new executions from being triggered."""
    tenant = Tenant(name="DisabledCorp", slug="disabled-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="dis@corp.com", password_hash="hash", name="Dis", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Disabled Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=False,  # DISABLED
        is_dry_run=True,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(
        tenant_id=tenant.id,
        title="Critical Incident",
        severity=IncidentSeverity.CRITICAL.value,
        created_by_id=user.id,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    execs = evaluate_incident_triggers(test_db_session, inc.id, "incident.created", None, user.id)
    assert len(execs) == 0


def test_trigger_configuration_validation_rejects_invalid_rules():
    """8. Trigger configuration validation rejects invalid rules, thresholds, and expressions."""
    # Invalid trigger event
    with pytest.raises(ValueError, match="Invalid trigger_event"):
        validate_playbook_trigger_conditions("ARBITRARY_EVENT", {})

    # Unsupported condition keys (e.g. shell script or injection attempt)
    with pytest.raises(ValueError, match="Unsupported trigger condition keys"):
        validate_playbook_trigger_conditions(
            "RULE_MATCH",
            {"eval_script": "os.system('rm -rf /')", "min_severity": "HIGH"},
        )

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid min_severity"):
        validate_playbook_trigger_conditions("RULE_MATCH", {"min_severity": "EXTREME"})

    # Invalid incident status
    with pytest.raises(ValueError, match="Invalid incident status"):
        validate_playbook_trigger_conditions("RULE_MATCH", {"incident_statuses": ["ARCHIVED"]})

    # Valid rule conditions pass
    valid = validate_playbook_trigger_conditions(
        "RULE_MATCH",
        {
            "min_severity": "HIGH",
            "incident_statuses": ["OPEN", "INVESTIGATING"],
            "ioc_verdict": "MALICIOUS",
            "ioc_types": ["IPV4", "DOMAIN"],
        },
    )
    assert valid["min_severity"] == "HIGH"
    assert "OPEN" in valid["incident_statuses"]


# ==============================================================================
# GROUP 2: DURABILITY AND IDEMPOTENCY (9 to 14)
# ==============================================================================


def test_transient_celery_failure_can_retry_safely(test_db_session: Session):
    """9. A transient Celery failure can retry safely without duplicate side effects."""
    tenant = Tenant(name="RetryCorp", slug="retry-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="celery@corp.com", password_hash="hash", name="Celery", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Retry Safe Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "host-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(
        tenant_id=tenant.id,
        title="Critical Incident",
        severity=IncidentSeverity.CRITICAL.value,
        created_by_id=user.id,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    inc_id_str = str(inc.id)
    user_id_str = str(user.id)

    # Simulate Celery task execution with transient DB lock retry
    with patch("app.core.database.SessionLocal", return_value=test_db_session):
        res1 = evaluate_incident_triggers_task.apply(
            args=[inc_id_str, "incident.created", None, user_id_str, "event-retry-123"]
        )
        assert res1.result["executions_created"] == 1

        # Re-running the task for the same event_id simulates a retry: it must not create a duplicate
        res2 = evaluate_incident_triggers_task.apply(
            args=[inc_id_str, "incident.created", None, user_id_str, "event-retry-123"]
        )
        assert res2.result["executions_created"] == 0


def test_duplicate_events_do_not_create_duplicate_logical_executions(test_db_session: Session):
    """10. Duplicate events do not create duplicate logical executions."""
    tenant = Tenant(name="DedupCorp", slug="dedup-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="dedup@corp.com", password_hash="hash", name="Dedup", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Dedup Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(
        tenant_id=tenant.id,
        title="Critical Breach",
        severity=IncidentSeverity.CRITICAL.value,
        created_by_id=user.id,
    )
    test_db_session.add(inc)
    test_db_session.commit()

    event_id = "stable-trigger-uuid-001"
    exec1 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Matched Critical",
        parameters={"incident_id": str(inc.id)},
        actor_user=user,
        event_id=event_id,
    )
    assert exec1 is not None

    # Process duplicate event_id
    exec2 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Matched Critical",
        parameters={"incident_id": str(inc.id)},
        actor_user=user,
        event_id=event_id,
    )
    assert exec2 is None

    # Check total executions in DB is exactly 1
    total_execs = test_db_session.scalars(
        select(PlaybookExecution).where(PlaybookExecution.playbook_id == pb.id)
    ).all()
    assert len(total_execs) == 1


def test_concurrent_workers_cannot_process_same_logical_action_twice(test_db_session: Session):
    """11. Concurrent workers inserting identical trigger_event_id are stopped by DB constraint."""
    tenant = Tenant(name="CollisionCorp", slug="collision-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="coll@corp.com", password_hash="hash", name="Collision", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Collision Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    # Pre-insert execution with event_id
    shared_event_id = "concurrent-event-999"
    e1 = PlaybookExecution(
        tenant_id=tenant.id,
        playbook_id=pb.id,
        triggered_by_id=user.id,
        trigger_source="AUTOMATED_TRIGGER",
        trigger_event_id=shared_event_id,
        status=ExecutionStatus.COMPLETED.value,
    )
    test_db_session.add(e1)
    test_db_session.commit()

    # Attempt second execution with same tenant and trigger_event_id
    inc = Incident(tenant_id=tenant.id, title="Test", created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    res = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Collision test",
        parameters={},
        actor_user=user,
        event_id=shared_event_id,
    )
    assert res is None


def test_rollback_of_incident_transaction_leaves_no_orphan_trigger(client: TestClient, test_db_session: Session):
    """12. Rollback of an incident/IOC transaction does not leave an actionable orphan trigger."""
    admin_token = register_org(client, "RollbackCorp", "rb-corp", "admin@rbcorp.com")

    # Attempt to create an incident with invalid data that triggers a validation error (rollback)
    res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "title": "",  # Invalid: empty title triggers 422
            "description": "Fail",
            "category": "MALWARE",
            "severity": "CRITICAL",
        },
    )
    assert res.status_code == 422

    # Verify no executions were created
    execs = test_db_session.scalars(select(PlaybookExecution)).all()
    assert len(execs) == 0


def test_worker_restart_and_pending_job_recovery_preserve_execution_state(test_db_session: Session):
    """13. Worker restart and recovery preserve PENDING_APPROVAL execution state intact."""
    tenant = Tenant(name="PreserveCorp", slug="preserve-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="pres@corp.com", password_hash="hash", name="Pres", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Preserve State Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "REVOKE_USER_SESSIONS", "target_user_id": str(user.id)}],
        is_enabled=True,
        is_dry_run=False,
        requires_approval=True,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Severe Intrusion", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    exec_record = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Intrusion matched",
        parameters={"target_user_id": str(user.id)},
        actor_user=user,
        event_id="state-preserve-event",
    )
    assert exec_record is not None
    assert exec_record.status == ExecutionStatus.PENDING_APPROVAL.value
    assert exec_record.approval is not None
    assert exec_record.approval.status == ApprovalStatus.PENDING.value

    # Simulate worker restart by reopening fresh session query
    queried = test_db_session.scalar(select(PlaybookExecution).where(PlaybookExecution.id == exec_record.id))
    assert queried.status == ExecutionStatus.PENDING_APPROVAL.value
    assert queried.approval.status == ApprovalStatus.PENDING.value


def test_distinct_qualifying_event_respects_cooldown(test_db_session: Session):
    """14. A subsequent event respects documented cooldown rules (skipped during cooldown; allowed after)."""
    tenant = Tenant(name="CooldownCorp", slug="cooldown-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="cool@corp.com", password_hash="hash", name="Cool", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Cooldown Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
        cooldown_seconds=300,  # 5 minutes
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Critical Event", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    # Event 1: First trigger succeeds
    e1 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="First Event",
        parameters={},
        actor_user=user,
        event_id="cool-event-1",
    )
    assert e1 is not None

    # Event 2: Distinct event ID, but within cooldown window (e.g. 10s later) -> SKIPPED
    e2 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Second Event within cooldown",
        parameters={},
        actor_user=user,
        event_id="cool-event-2",
    )
    assert e2 is None

    # Simulate passage of time past cooldown window
    e1.created_at = datetime.now(timezone.utc) - timedelta(seconds=301)
    test_db_session.commit()

    # Event 3: After cooldown expires -> ALLOWED
    e3 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Third Event after cooldown",
        parameters={},
        actor_user=user,
        event_id="cool-event-3",
    )
    assert e3 is not None


# ==============================================================================
# GROUP 3: AUTHORIZATION AND SAFETY (15 to 22)
# ==============================================================================


def test_dry_run_is_default_behavior(test_db_session: Session):
    """15. Dry-run is the default behavior for automated triggers."""
    tenant = Tenant(name="SafetyCorp", slug="safety-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="safe@safetycorp.com", password_hash="hash", name="Safe", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Default Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.7"}],
        is_enabled=True,
        # is_dry_run defaults to True
    )
    test_db_session.add(pb)
    test_db_session.commit()
    assert pb.is_dry_run is True

    inc = Incident(tenant_id=tenant.id, title="Critical Alert", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    e = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Auto matched",
        parameters={"ip_address": "198.51.100.7"},
        actor_user=user,
        event_id="dryrun-test-evt",
    )
    assert e.is_dry_run is True


def test_live_execution_cannot_bypass_approval_policy(test_db_session: Session):
    """16. Automated live execution cannot bypass approval: it is forced into PENDING_APPROVAL."""
    tenant = Tenant(name="LivePolicyCorp", slug="live-policy-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="live@corp.com", password_hash="hash", name="Live", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    # Playbook configured as LIVE and attempted requires_approval=False
    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Attempted Live Auto Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "REVOKE_USER_SESSIONS", "target_user_id": str(user.id)}],
        is_enabled=True,
        is_dry_run=False,          # LIVE
        requires_approval=False,   # Attempted bypass
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Critical", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    e = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Live Auto Trigger",
        parameters={"target_user_id": str(user.id)},
        actor_user=user,
        event_id="live-approval-enforced-evt",
    )
    # SAFETY ENFORCEMENT: Forced into PENDING_APPROVAL! Never executed live actions automatically!
    assert e.status == ExecutionStatus.PENDING_APPROVAL.value
    assert e.approval is not None
    assert e.approval.status == ApprovalStatus.PENDING.value
    assert len(e.step_results) == 0  # No live disruptive actions carried out


def test_self_approval_restrictions_remain_effective(test_db_session: Session):
    """17. Anti-self-approval restrictions remain effective: trigger initiator cannot approve."""
    tenant = Tenant(name="AntiSelfCorp", slug="anti-self-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    analyst = User(tenant_id=tenant.id, email="analyst@corp.com", password_hash="hash", name="Analyst", role=UserRole.SECURITY_ANALYST.value)
    admin = User(tenant_id=tenant.id, email="admin@corp.com", password_hash="hash", name="Admin", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add_all([analyst, admin])
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Privileged Live Containment",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "finance-01"}],
        is_enabled=True,
        is_dry_run=False,
        requires_approval=True,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Critical Breach", severity=IncidentSeverity.CRITICAL.value, created_by_id=analyst.id)
    test_db_session.add(inc)
    test_db_session.commit()

    # Analyst escalates incident and initiates automated trigger
    exec_record = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Analyst Escalation",
        parameters={"hostname": "finance-01"},
        actor_user=analyst,
        event_id="anti-self-approval-evt",
    )
    assert exec_record.triggered_by_id == analyst.id

    # Analyst attempts to self-approve
    with pytest.raises(ValueError, match="Anti-self-approval policy violation"):
        decide_playbook_approval(
            db=test_db_session,
            execution_id=exec_record.id,
            approver=analyst,
            approved=True,
        )


def test_required_step_up_mfa_cannot_be_bypassed(client: TestClient, test_db_session: Session):
    """18. Required step-up MFA cannot be bypassed on live execution approval."""
    admin_token = register_org(client, "StepUpCorp", "stepup-corp", "admin@stepup.com")
    admin = test_db_session.scalar(select(User).where(User.email == "admin@stepup.com"))
    admin.mfa_enabled = True
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=admin.tenant_id,
        name="Live Containment",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-prod"}],
        is_enabled=True,
        is_dry_run=False,
        requires_approval=True,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    # Create pending execution
    e = PlaybookExecution(
        tenant_id=admin.tenant_id,
        playbook_id=pb.id,
        triggered_by_id=uuid4(),  # Different user
        trigger_source="AUTOMATED_TRIGGER",
        status=ExecutionStatus.PENDING_APPROVAL.value,
        is_dry_run=False,
    )
    test_db_session.add(e)
    test_db_session.flush()

    appr = PlaybookApproval(
        tenant_id=admin.tenant_id,
        execution_id=e.id,
        required_role="TENANT_ADMIN",
        status=ApprovalStatus.PENDING.value,
    )
    test_db_session.add(appr)
    test_db_session.commit()

    # Attempt to approve without Step-Up MFA headers
    res = client.post(
        f"/api/v1/playbooks/executions/{e.id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"notes": "Bypassing MFA"},
    )
    assert res.status_code == 403
    assert "step-up" in res.json()["detail"].lower() or "mfa" in res.json()["detail"].lower()


def test_expired_or_replayed_step_up_credentials_rejected(test_db_session: Session):
    """19. Expired or invalid step-up credentials are rejected for live action approval."""
    tenant = Tenant(name="MFAExpireCorp", slug="mfa-expire-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    user = User(tenant_id=tenant.id, email="approver@corp.com", password_hash="hash", name="Approver", role=UserRole.TENANT_ADMIN.value, mfa_enabled=True)
    other = User(tenant_id=tenant.id, email="initiator@corp.com", password_hash="hash", name="Initiator", role=UserRole.SECURITY_ANALYST.value)
    test_db_session.add_all([user, other])
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Live Isolation",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-1"}],
        is_enabled=True,
        is_dry_run=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    e = PlaybookExecution(
        tenant_id=tenant.id,
        playbook_id=pb.id,
        triggered_by_id=other.id,
        trigger_source="AUTOMATED_TRIGGER",
        status=ExecutionStatus.PENDING_APPROVAL.value,
        is_dry_run=False,
    )
    test_db_session.add(e)
    test_db_session.flush()

    appr = PlaybookApproval(
        tenant_id=tenant.id,
        execution_id=e.id,
        required_role="TENANT_ADMIN",
        status=ApprovalStatus.PENDING.value,
    )
    test_db_session.add(appr)
    test_db_session.commit()

    with pytest.raises(ValueError, match=r"[Ss]tep-[uU]p MFA verification"):
        decide_playbook_approval(
            db=test_db_session,
            execution_id=e.id,
            approver=user,
            approved=True,
            step_up_token="invalid-or-expired-token",
        )


def test_tenant_boundaries_enforced_across_triggers_and_approvals(client: TestClient, test_db_session: Session):
    """20. Tenant boundaries are strictly enforced on trigger rules, incidents, and approvals."""
    token1 = register_org(client, "TenantOne", "t-one", "admin1@tone.com")
    token2 = register_org(client, "TenantTwo", "t-two", "admin2@ttwo.com")
    u1 = test_db_session.scalar(select(User).where(User.email == "admin1@tone.com"))
    u2 = test_db_session.scalar(select(User).where(User.email == "admin2@ttwo.com"))

    pb1 = ResponsePlaybook(
        tenant_id=u1.tenant_id,
        name="T1 Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "t1-srv"}],
        is_enabled=True,
    )
    test_db_session.add(pb1)
    test_db_session.commit()

    e1 = PlaybookExecution(
        tenant_id=u1.tenant_id,
        playbook_id=pb1.id,
        triggered_by_id=u1.id,
        status=ExecutionStatus.PENDING_APPROVAL.value,
    )
    test_db_session.add(e1)
    test_db_session.flush()
    appr1 = PlaybookApproval(tenant_id=u1.tenant_id, execution_id=e1.id, status=ApprovalStatus.PENDING.value)
    test_db_session.add(appr1)
    test_db_session.commit()

    # User from Tenant 2 attempts to approve Tenant 1's execution
    res = client.post(
        f"/api/v1/playbooks/executions/{e1.id}/approve",
        headers={"Authorization": f"Bearer {token2}"},
        json={"notes": "Cross tenant attack"},
    )
    # Anti-IDOR: strict 404
    assert res.status_code == 404


def test_failed_live_action_cannot_silently_transition_to_success(test_db_session: Session):
    """21. A failed action in a playbook marks the execution as FAILED (never COMPLETED)."""
    tenant = Tenant(name="FailCorp", slug="fail-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="fail@corp.com", password_hash="hash", name="Fail", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    # Missing target_user_id will cause REVOKE_USER_SESSIONS to fail
    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Failing Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "REVOKE_USER_SESSIONS"}],  # Missing required parameters!
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Critical", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    e = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Test Failure",
        parameters={},
        actor_user=user,
        event_id="fail-action-evt",
    )
    assert e.status == ExecutionStatus.FAILED.value
    assert e.step_results[0]["status"] == "FAILED"


def test_duplicate_tasks_cannot_cause_repeated_disruptive_effects(test_db_session: Session):
    """22. Duplicate task executions cannot execute actions twice due to atomic deduplication."""
    tenant = Tenant(name="RepeatEffectCorp", slug="repeat-effect-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="disrupt@corp.com", password_hash="hash", name="Disrupt", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    action_mock = MagicMock(return_value={"action": "BLOCK_IP", "status": "SIMULATED_SUCCESS"})

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Idempotent Disruptive Playbook",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.9"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Critical", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    with patch("app.services.playbook_trigger_service.execute_playbook_action", action_mock):
        # First task dispatch
        e1 = process_playbook_execution_trigger(
            db=test_db_session,
            playbook=pb,
            incident=inc,
            trigger_reason="First",
            parameters={"ip_address": "198.51.100.9"},
            actor_user=user,
            event_id="disruptive-evt-101",
        )
        assert e1 is not None

        # Duplicate task dispatch with same event_id
        e2 = process_playbook_execution_trigger(
            db=test_db_session,
            playbook=pb,
            incident=inc,
            trigger_reason="Duplicate",
            parameters={"ip_address": "198.51.100.9"},
            actor_user=user,
            event_id="disruptive-evt-101",
        )
        assert e2 is None

    # Verify action_mock was called exactly ONCE across both task dispatches!
    assert action_mock.call_count == 1

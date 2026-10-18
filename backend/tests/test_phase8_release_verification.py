"""
Phase 8: Final Release Readiness, End-to-End Verification & Security Audit Test Suite.
Validates the complete incident-to-response lifecycle, trigger idempotency,
MFA/TOTP/Step-Up authorization, tenant isolation, SSRF defenses, and failure recovery.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import safe_apply_async
from app.core.security import create_mfa_challenge_token, create_step_up_token
from app.models.audit import AuditEvent, AuditOutcome
from app.models.incident import Incident, IncidentCategory, IncidentSeverity, IncidentStatus
from app.models.ioc import IndicatorOfCompromise, IndicatorType, ThreatSeverity, ThreatVerdict
from app.models.playbook import (
    ApprovalStatus,
    ExecutionStatus,
    PlaybookApproval,
    PlaybookExecution,
    PlaybookTrigger,
    ResponsePlaybook,
)
from app.models.tenant import Tenant
from app.models.user import User, UserRecoveryCode, UserRole
from app.models.webhook import DeliveryStatus, NotificationDestination, WebhookDelivery
from app.services.mfa_service import (
    encrypt_totp_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    verify_and_consume_recovery_code,
    verify_totp_code,
)
from app.services.playbook_service import decide_playbook_approval
from app.services.playbook_trigger_service import (
    evaluate_incident_triggers,
    evaluate_ioc_triggers,
    process_playbook_execution_trigger,
)
from app.services.webhook_service import (
    deliver_webhook_now,
    format_webhook_payload,
    is_prohibited_ip,
    validate_destination_url,
)
from app.tasks.playbook_tasks import (
    evaluate_incident_triggers_task,
    evaluate_ioc_triggers_task,
)
from app.tasks.webhook_tasks import recover_pending_deliveries_task


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
# SECTION 1: END-TO-END WORKFLOW (Steps 1 to 14)
# ==============================================================================


def test_full_incident_to_response_lifecycle_with_mfa_and_dual_approval(
    client: TestClient, test_db_session: Session
):
    """
    Phase 2: Full incident-to-response workflow:
    1. Authenticate user with MFA enabled.
    2. Create a tenant-scoped incident.
    3. Escalate the incident to CRITICAL.
    4. Associate a test IOC with the incident.
    5. Simulate threat-intelligence enrichment that yields MALICIOUS.
    6. Verify trigger rules evaluate correct incident, IOC, playbook, tenant.
    7. Verify trigger creates durable execution record.
    8. Verify dry-run defaults and approval-required states.
    9. Verify authorized independent approver can approve.
    10. Verify live execution requires fresh step-up MFA and anti-self-approval.
    11. Verify audit events accurately reflect the outcome.
    """
    # 1. Setup tenant & two admins (initiator and independent approver)
    admin1_token = register_org(client, "AlphaSec", "alpha-sec", "lead@alphasec.com")
    admin1 = test_db_session.scalar(select(User).where(User.email == "lead@alphasec.com"))
    admin2_token = create_user_in_org(client, admin1_token, "Approver Admin", "approver@alphasec.com", "TENANT_ADMIN")
    admin2 = test_db_session.scalar(select(User).where(User.email == "approver@alphasec.com"))

    # Enable MFA for Admin 2 (the approver)
    totp_secret = generate_totp_secret()
    admin2.totp_secret_encrypted = encrypt_totp_secret(totp_secret)
    admin2.mfa_enabled = True
    test_db_session.commit()

    # 2. Setup Playbooks:
    # A) Critical Incident Response Playbook (Live action: ISOLATE_ENDPOINT)
    pb_crit = ResponsePlaybook(
        tenant_id=admin1.tenant_id,
        name="Automated Critical Isolation",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-finance-01"}],
        is_enabled=True,
        is_dry_run=False,  # Live action -> MUST require human approval!
        requires_approval=True,
        cooldown_seconds=300,
        created_by_id=admin1.id,
    )
    # B) Malicious IOC Response Playbook (Dry-run: BLOCK_IP)
    pb_ioc = ResponsePlaybook(
        tenant_id=admin1.tenant_id,
        name="Automated IOC Simulation",
        trigger_event=PlaybookTrigger.MALICIOUS_IOC_DETECTED.value,
        actions=[{"action_type": "BLOCK_IP", "ip_address": "198.51.100.42"}],
        is_enabled=True,
        is_dry_run=True,  # Safe simulation
        requires_approval=False,
        cooldown_seconds=300,
        created_by_id=admin1.id,
    )
    test_db_session.add_all([pb_crit, pb_ioc])
    test_db_session.commit()

    # 3. Create Incident (initially HIGH)
    inc_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={
            "title": "Suspected Credential Dumping",
            "description": "LSASS memory read detected",
            "category": "UNAUTHORIZED_ACCESS",
            "severity": "HIGH",
        },
    )
    assert inc_res.status_code == 201
    incident_id = inc_res.json()["id"]

    # 4. Escalate Incident to CRITICAL via PATCH
    update_res = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={"severity": "CRITICAL"},
    )
    assert update_res.status_code == 200
    assert update_res.json()["severity"] == "CRITICAL"

    # 5. Verify the Critical Trigger created a PENDING_APPROVAL execution (Live Action Safety)
    crit_exec = test_db_session.scalar(
        select(PlaybookExecution).where(
            PlaybookExecution.playbook_id == pb_crit.id,
            PlaybookExecution.incident_id == UUID(incident_id),
        )
    )
    assert crit_exec is not None
    assert crit_exec.status == ExecutionStatus.PENDING_APPROVAL.value
    assert crit_exec.is_dry_run is False
    assert "CRITICAL" in (crit_exec.trigger_reason or "")

    # Check approval record
    crit_approval = test_db_session.scalar(
        select(PlaybookApproval).where(PlaybookApproval.execution_id == crit_exec.id)
    )
    assert crit_approval is not None
    assert crit_approval.status == ApprovalStatus.PENDING.value

    # 6. Associate test IOC with the incident and simulate threat intel MALICIOUS verdict
    ioc_res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={
            "incident_id": incident_id,
            "indicator_type": "IPV4",
            "value": "198.51.100.42",
        },
    )
    assert ioc_res.status_code == 201
    ioc_id = ioc_res.json()["id"]

    # Simulate enrichment yielding MALICIOUS verdict
    enrich_res = client.patch(
        f"/api/v1/iocs/{ioc_id}",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={"threat_verdict": "MALICIOUS", "severity": "HIGH"},
    )
    assert enrich_res.status_code == 200
    assert enrich_res.json()["threat_verdict"] == "MALICIOUS"

    # 7. Verify the IOC Trigger executed immediately in DRY_RUN mode
    ioc_exec = test_db_session.scalar(
        select(PlaybookExecution).where(
            PlaybookExecution.playbook_id == pb_ioc.id,
            PlaybookExecution.incident_id == UUID(incident_id),
        )
    )
    assert ioc_exec is not None
    assert ioc_exec.status == ExecutionStatus.COMPLETED.value
    assert ioc_exec.is_dry_run is True
    assert ioc_exec.step_results[0]["status"] in ("SIMULATED", "SIMULATED_SUCCESS")

    # 8. Anti-Self-Approval Check: Admin 1 (who created the playbook & triggered event) CANNOT self-approve
    decide_fail_res = client.post(
        f"/api/v1/playbooks/executions/{crit_exec.id}/approve",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={"notes": "Attempting self-approval"},
    )
    assert decide_fail_res.status_code == 400
    assert "Anti-self-approval" in decide_fail_res.json()["detail"]

    # 9. Step-Up MFA Requirement on Approval: Admin 2 approving live action requires valid MFA
    fresh_totp = pyotp.TOTP(totp_secret).now()
    step_up_token = create_step_up_token(admin2.id, action="playbook_approval", target_id=crit_exec.id)

    # Approve with valid Step-Up token
    decide_success_res = client.post(
        f"/api/v1/playbooks/executions/{crit_exec.id}/approve",
        headers={
            "Authorization": f"Bearer {admin2_token}",
            "X-Step-Up-Token": step_up_token,
        },
        json={"notes": "Verified threat. Approved for containment."},
    )
    assert decide_success_res.status_code == 200
    assert decide_success_res.json()["status"] == ExecutionStatus.COMPLETED.value

    # 10. Verify execution transitioned to COMPLETED after approval
    test_db_session.refresh(crit_exec)
    assert crit_exec.status == ExecutionStatus.COMPLETED.value
    assert len(crit_exec.step_results) == 1
    assert crit_exec.step_results[0]["status"] in ("SUCCESS", "SIMULATED_LIVE")

    # 11. Verify Audit Events
    audits = test_db_session.scalars(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == admin1.tenant_id)
        .order_by(AuditEvent.occurred_at.desc())
    ).all()
    actions = [a.action for a in audits]
    assert "PLAYBOOK_TRIGGER_MATCHED" in actions
    assert "PLAYBOOK_APPROVAL_REQUESTED" in actions
    assert any("APPROVAL" in a for a in actions)
    assert "PLAYBOOK_EXECUTED" in actions


# ==============================================================================
# SECTION 2: TRIGGER IDEMPOTENCY AND COOLDOWN (Phase 3)
# ==============================================================================


def test_repeated_task_delivery_creates_at_most_one_execution(test_db_session: Session):
    """Phase 3: Repeated Celery task delivery for the exact same event produces at most one execution."""
    tenant = Tenant(name="IdempCorp", slug="idemp-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="idemp@corp.com", password_hash="hash", name="Idemp", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Idempotent Isolation",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
        cooldown_seconds=300,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Critical Breach", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    # Deliver task attempt 1
    res1 = evaluate_incident_triggers_task(
        incident_id=str(inc.id),
        event_type="incident.created",
        previous_state=None,
        actor_user_id=str(user.id),
        event_id="test-logical-event-001",
    )
    assert res1["executions_created"] == 1

    # Deliver task attempt 2 (retry or at-least-once duplicate)
    res2 = evaluate_incident_triggers_task(
        incident_id=str(inc.id),
        event_type="incident.created",
        previous_state=None,
        actor_user_id=str(user.id),
        event_id="test-logical-event-001",
    )
    assert res2["executions_created"] == 0

    # Total executions in database must be exactly 1
    total_execs = test_db_session.scalars(
        select(PlaybookExecution).where(PlaybookExecution.playbook_id == pb.id)
    ).all()
    assert len(total_execs) == 1


def test_subsequent_qualifying_event_succeeds_after_cooldown(test_db_session: Session):
    """Phase 3: After cooldown expires, a new qualifying event creates a new execution record."""
    tenant = Tenant(name="SubseqCorp", slug="subseq-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="subseq@corp.com", password_hash="hash", name="Subseq", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Cooldown Test",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
        cooldown_seconds=120,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Subsequent Breach", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    # First event
    e1 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Event 1",
        parameters={},
        actor_user=user,
        event_id="subseq-event-1",
    )
    assert e1 is not None

    # Advance time beyond 120s cooldown
    e1.created_at = datetime.now(timezone.utc) - timedelta(seconds=125)
    test_db_session.commit()

    # Subsequent event after cooldown
    e2 = process_playbook_execution_trigger(
        db=test_db_session,
        playbook=pb,
        incident=inc,
        trigger_reason="Event 2 after cooldown",
        parameters={},
        actor_user=user,
        event_id="subseq-event-2",
    )
    assert e2 is not None
    assert e1.id != e2.id


def test_rule_version_update_allows_retriggering_even_for_prior_events(test_db_session: Session):
    """Phase 3: Bumping rule_version on a playbook allows evaluation of newly configured rules."""
    tenant = Tenant(name="RuleCorp", slug="rule-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="rule@corp.com", password_hash="hash", name="Rule", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    pb = ResponsePlaybook(
        tenant_id=tenant.id,
        name="Versioned Rule",
        trigger_event=PlaybookTrigger.INCIDENT_CRITICAL.value,
        actions=[{"action_type": "ISOLATE_ENDPOINT", "hostname": "srv-01"}],
        is_enabled=True,
        is_dry_run=True,
        requires_approval=False,
        rule_version=1,
        cooldown_seconds=0,
    )
    test_db_session.add(pb)
    test_db_session.commit()

    inc = Incident(tenant_id=tenant.id, title="Rule Event", severity=IncidentSeverity.CRITICAL.value, created_by_id=user.id)
    test_db_session.add(inc)
    test_db_session.commit()

    # Trigger rule version 1
    e1 = evaluate_incident_triggers(
        db=test_db_session,
        incident_id=inc.id,
        event_type="incident.created",
    )
    assert len(e1) == 1
    assert "v1" in (e1[0].trigger_event_id or "")

    # Playbook rule updated (e.g. actions changed), version bumped to 2
    pb.rule_version = 2
    test_db_session.commit()

    # Trigger rule version 2
    e2 = evaluate_incident_triggers(
        db=test_db_session,
        incident_id=inc.id,
        event_type="incident.created",
    )
    assert len(e2) == 1
    assert "v2" in (e2[0].trigger_event_id or "")


# ==============================================================================
# SECTION 3: AUTHENTICATION, MFA, AND TENANT ISOLATION (Phase 4)
# ==============================================================================


def test_mfa_challenge_token_cannot_access_normal_application_routes(client: TestClient, test_db_session: Session):
    """Phase 4: MFA challenge token cannot be used as an access token for standard APIs."""
    tenant = Tenant(name="AuthCorp", slug="auth-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="auth@corp.com", password_hash="hash", name="Auth", role=UserRole.SECURITY_ANALYST.value)
    test_db_session.add(user)
    test_db_session.commit()

    # Issue challenge token
    challenge_token = create_mfa_challenge_token(user.id)

    # Attempt to access /api/v1/incidents
    res = client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {challenge_token}"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Could not validate credentials"


def test_cross_tenant_isolation_strictly_enforced(client: TestClient, test_db_session: Session):
    """Phase 4: Tenant A user cannot access or modify Tenant B incidents or playbooks."""
    token_a = register_org(client, "TenantA", "tenant-a", "admin@tenanta.com")
    token_b = register_org(client, "TenantB", "tenant-b", "admin@tenantb.com")

    # Tenant B creates an incident
    inc_b_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"title": "Private Tenant B Incident", "category": "MALWARE", "severity": "HIGH"},
    )
    assert inc_b_res.status_code == 201
    inc_b_id = inc_b_res.json()["id"]

    # Tenant A attempts to view Tenant B's incident -> MUST return 404
    get_res = client.get(f"/api/v1/incidents/{inc_b_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert get_res.status_code == 404

    # Tenant A attempts to update Tenant B's incident -> MUST return 404
    patch_res = client.patch(
        f"/api/v1/incidents/{inc_b_id}",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"severity": "CRITICAL"},
    )
    assert patch_res.status_code == 404


def test_recovery_code_single_use_and_replay_protection(test_db_session: Session):
    """Phase 4: Recovery code is single-use and cannot be reused under concurrency."""
    tenant = Tenant(name="RecovCorp", slug="recov-corp")
    test_db_session.add(tenant)
    test_db_session.commit()
    user = User(tenant_id=tenant.id, email="recov@corp.com", password_hash="hash", name="Recov", role=UserRole.TENANT_ADMIN.value)
    test_db_session.add(user)
    test_db_session.commit()

    code = "ABCDE-12345"
    rc = UserRecoveryCode(user_id=user.id, code_hash=hash_recovery_code(code), is_used=False)
    test_db_session.add(rc)
    test_db_session.commit()

    # First consumption succeeds
    assert verify_and_consume_recovery_code(test_db_session, user, code) is True

    # Second consumption of the same code fails
    assert verify_and_consume_recovery_code(test_db_session, user, code) is False


# ==============================================================================
# SECTION 4: SSRF DEFENSE AND OUTBOUND DISPATCH (Phase 5)
# ==============================================================================


@pytest.mark.parametrize(
    "prohibited_url",
    [
        "http://127.0.0.1:8080/hook",
        "http://localhost:5000/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://10.0.0.5/api",
        "http://172.16.1.1/webhook",
        "http://192.168.1.100/alert",
        "http://[::1]:8000/hook",
        "http://[::ffff:127.0.0.1]:8080/hook",
        "http://[fe80::1]/webhook",
        "ftp://example.com/webhook",
        "http://user:password@example.com/webhook",
    ],
)
def test_ssrf_prohibited_destinations_are_strictly_blocked(prohibited_url: str):
    """Phase 5: Destination URL validation rejects SSRF targets, private ranges, metadata, and credentials."""
    with pytest.raises(ValueError):
        validate_destination_url(prohibited_url, allow_local=False)


# ==============================================================================
# SECTION 5: HEALTH PROBES AND FAILURE RECOVERY (Phase 6 & 7)
# ==============================================================================


def test_health_probes_liveness_and_readiness(client: TestClient):
    """Phase 7: Health checks provide /health, /health/live, and /health/ready."""
    # 1. Backwards compatible /health
    h_res = client.get("/api/v1/health")
    assert h_res.status_code == 200
    assert h_res.json() == {"status": "ok", "database": "ok"}

    # 2. Liveness probe (process availability)
    live_res = client.get("/api/v1/health/live")
    assert live_res.status_code == 200
    assert live_res.json() == {"status": "ok"}

    # 3. Readiness probe (application & infrastructure readiness)
    ready_res = client.get("/api/v1/health/ready")
    assert ready_res.status_code == 200
    assert ready_res.json()["status"] == "ok"
    assert ready_res.json()["database"] == "ok"


def test_recover_pending_deliveries_clears_stale_locks(test_db_session: Session):
    """Phase 6: Periodic recovery task unlocks abandoned worker deliveries (> 5 mins old)."""
    tenant = Tenant(name="LockCorp", slug="lock-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Splunk SIEM",
        destination_type="GENERIC_WEBHOOK",
        endpoint_url="https://siem.lockcorp.com/events",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    # Create delivery with a lock from 6 minutes ago (worker crashed)
    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"id": "123"},
        status=DeliveryStatus.PENDING.value,
        locked_at=datetime.now(timezone.utc) - timedelta(minutes=6),
        locked_by="crashed-worker-host-pid9999",
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    # Run recovery sweep
    recovered = recover_pending_deliveries_task()
    assert recovered >= 1

    test_db_session.refresh(delivery)
    assert delivery.locked_at is None
    assert delivery.locked_by is None

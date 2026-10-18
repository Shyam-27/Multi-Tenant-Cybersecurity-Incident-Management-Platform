from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import safe_apply_async
from app.core.config import get_settings
from app.models.ioc import IndicatorOfCompromise, ThreatSeverity, ThreatVerdict
from app.models.job import BackgroundJob, JobStatus, JobType
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.models.webhook import DeliveryStatus, NotificationDestination, WebhookDelivery
from app.services.webhook_service import dispatch_event_to_destinations, format_webhook_payload
from app.tasks.threat_intel_tasks import refresh_threat_intel_task, scheduled_threat_intel_refresh_task
from app.tasks.webhook_tasks import (
    compute_backoff_seconds,
    dispatch_webhook_delivery_task,
    is_permanent_client_error,
    recover_pending_deliveries_task,
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


def test_intent_persisted_before_ack(test_db_session: Session):
    """1. Webhook delivery intent is strictly persisted in PostgreSQL (PENDING status) before worker execution."""
    tenant = Tenant(name="Intent Corp", slug="intent-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Security Splunk",
        destination_type="SPLUNK_HEC",
        endpoint_url="https://splunk.internal.example/hec",
        is_enabled=True,
        event_types=["incident.created"],
    )
    test_db_session.add(dest)
    test_db_session.commit()

    with patch("app.core.celery_app.safe_apply_async") as mock_safe_apply:
        deliveries = dispatch_event_to_destinations(
            db=test_db_session,
            tenant_id=tenant.id,
            event_type="incident.created",
            payload={"id": "inc-001", "title": "Test Incident"},
            sync=False,
        )
        assert len(deliveries) == 1
        d = deliveries[0]
        # Intent was persisted with PENDING status
        assert d.status == DeliveryStatus.PENDING.value
        assert d.attempt_count == 0
        assert d.max_attempts == 5

        # Check in DB directly
        persisted = test_db_session.scalar(select(WebhookDelivery).where(WebhookDelivery.id == d.id))
        assert persisted is not None
        assert persisted.status == DeliveryStatus.PENDING.value

        # Associated BackgroundJob created for tenant observability
        job = test_db_session.scalar(select(BackgroundJob).where(BackgroundJob.resource_id == str(d.id)))
        assert job is not None
        assert job.status == JobStatus.QUEUED.value
        assert job.tenant_id == tenant.id

        mock_safe_apply.assert_called_once()


def test_worker_recovery_of_pending_deliveries(test_db_session: Session):
    """2. Worker recovery on restart sweeps unpicked PENDING and expired locked deliveries."""
    tenant = Tenant(name="Recovery Corp", slug="recovery-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Target Webhook",
        destination_type="MS_TEAMS",
        endpoint_url="https://teams.microsoft.example/webhook",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    now = datetime.now(timezone.utc)
    # Stale pending delivery (created > 30s ago)
    stale_pending = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.status.changed",
        payload={"id": "1"},
        status=DeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
        created_at=now - timedelta(seconds=45),
    )
    # Stale locked delivery (abandoned worker crash > 5 mins ago)
    stale_locked = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.status.changed",
        payload={"id": "2"},
        status=DeliveryStatus.PENDING.value,
        attempt_count=1,
        max_attempts=5,
        locked_at=now - timedelta(minutes=6),
        locked_by="crashed-worker-host",
    )
    # Due retrying delivery
    due_retrying = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.status.changed",
        payload={"id": "3"},
        status=DeliveryStatus.RETRYING.value,
        attempt_count=2,
        max_attempts=5,
        next_retry_at=now - timedelta(seconds=10),
    )
    test_db_session.add_all([stale_pending, stale_locked, due_retrying])
    test_db_session.commit()

    with patch("app.core.celery_app.safe_apply_async") as mock_enqueue:
        recovered = recover_pending_deliveries_task.apply().result
        assert recovered >= 3
        # Stale lock must be unlocked
        test_db_session.refresh(stale_locked)
        assert stale_locked.locked_at is None
        assert stale_locked.locked_by is None


def test_exponential_backoff_and_jitter():
    """3. Backoff calculation follows 10s * 2^(attempt-1) with ±20% jitter bounds."""
    for attempt, base in [(1, 10.0), (2, 20.0), (3, 40.0), (4, 80.0)]:
        delays = [compute_backoff_seconds(attempt, base_seconds=10.0, jitter_factor=0.2) for _ in range(50)]
        min_allowed = base * 0.8
        max_allowed = base * 1.2
        assert all(min_allowed <= d <= max_allowed for d in delays)
        # Verify non-zero variance (jitter present)
        assert len(set(delays)) > 1


def test_transient_failure_triggers_retry(test_db_session: Session):
    """4. Transient failures (503 Service Unavailable / Timeout) trigger RETRYING state with backoff."""
    tenant = Tenant(name="Transient Corp", slug="transient-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Flaky Endpoint",
        destination_type="SLACK",
        endpoint_url="https://hooks.slack.com/services/flaky",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"title": "High Alert"},
        status=DeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    with patch("app.services.webhook_service.deliver_webhook_now", return_value=(False, 503, "HTTP 503: Service Unavailable")):
        with patch("app.tasks.webhook_tasks.safe_apply_async") as mock_enqueue:
            res = dispatch_webhook_delivery_task.apply(args=[str(delivery.id)]).result
            test_db_session.refresh(delivery)

            assert delivery.status == DeliveryStatus.RETRYING.value
            assert delivery.attempt_count == 1
            assert delivery.is_terminal_failure is False
            assert delivery.last_error_category == "SERVER_ERROR"
            assert delivery.next_retry_at is not None
            mock_enqueue.assert_called_once()


def test_permanent_failure_immediate_terminal(test_db_session: Session):
    """5. Permanent client error (400 Bad Request, 401 Unauthorized) sets is_terminal_failure=True immediately."""
    tenant = Tenant(name="Permanent Corp", slug="permanent-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Auth Fail Endpoint",
        destination_type="ELASTIC_SIEM",
        endpoint_url="https://elastic.cloud.example/in",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"title": "Test"},
        status=DeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    with patch("app.services.webhook_service.deliver_webhook_now", return_value=(False, 401, "HTTP 401: Unauthorized")):
        with patch("app.core.celery_app.safe_apply_async") as mock_enqueue:
            dispatch_webhook_delivery_task.apply(args=[str(delivery.id)])
            test_db_session.refresh(delivery)

            assert delivery.status == DeliveryStatus.FAILED.value
            assert delivery.is_terminal_failure is True
            assert delivery.last_error_category == "CLIENT_ERROR"
            assert delivery.next_retry_at is None
            # No further retries should be enqueued
            mock_enqueue.assert_not_called()


def test_max_attempts_ceiling_transitions_to_terminal_failure(test_db_session: Session):
    """6. Reaching max_attempts (5) transitions delivery to terminal FAILED state."""
    tenant = Tenant(name="Max Attempt Corp", slug="max-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Dead Endpoint",
        destination_type="SPLUNK_HEC",
        endpoint_url="https://splunk.dead.example/in",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"title": "Test"},
        status=DeliveryStatus.RETRYING.value,
        attempt_count=4,  # Next attempt is 5 (max)
        max_attempts=5,
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    with patch("app.services.webhook_service.deliver_webhook_now", return_value=(False, 500, "Internal Server Error")):
        with patch("app.core.celery_app.safe_apply_async") as mock_enqueue:
            dispatch_webhook_delivery_task.apply(args=[str(delivery.id)])
            test_db_session.refresh(delivery)

            assert delivery.attempt_count == 5
            assert delivery.status == DeliveryStatus.FAILED.value
            assert delivery.is_terminal_failure is True
            mock_enqueue.assert_not_called()


def test_concurrent_worker_protection(test_db_session: Session):
    """7. Concurrency guard prevents duplicate processing of already claimed deliveries."""
    tenant = Tenant(name="Concurrency Corp", slug="concurrency-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Endpoint",
        destination_type="SLACK",
        endpoint_url="https://hooks.slack.com/services/concurrent",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    # Delivery already marked SUCCESS
    completed_delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={},
        status=DeliveryStatus.SUCCESS.value,
        attempt_count=1,
    )
    test_db_session.add(completed_delivery)
    test_db_session.commit()

    with patch("app.services.webhook_service.deliver_webhook_now") as mock_deliver:
        res = dispatch_webhook_delivery_task.apply(args=[str(completed_delivery.id)]).result
        assert res["status"] == "SKIPPED"
        mock_deliver.assert_not_called()


def test_destination_url_revalidation_at_dispatch(test_db_session: Session):
    """8. Re-validation of URL at dispatch time blocks SSRF even if destination record exists."""
    tenant = Tenant(name="SSRF Corp", slug="ssrf-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    # Destination pointing to local metadata
    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Metadata SSRF Attack",
        destination_type="SLACK",
        endpoint_url="http://169.254.169.254/latest/meta-data",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"alert": "secret"},
        status=DeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    with patch("httpx.Client.post") as mock_post:
        dispatch_webhook_delivery_task.apply(args=[str(delivery.id)])
        test_db_session.refresh(delivery)

        assert delivery.status == DeliveryStatus.FAILED.value
        assert delivery.is_terminal_failure is True
        assert delivery.last_error_category == "SSRF_BLOCKED"
        mock_post.assert_not_called()


def test_redirect_prohibition_security(test_db_session: Session):
    """9. Strict redirect prohibition: HTTP 301/302 treated as security violation."""
    tenant = Tenant(name="Redirect Corp", slug="redirect-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Redirect Hook",
        destination_type="MS_TEAMS",
        endpoint_url="https://webhook.teams.example/in",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"id": "test"},
        status=DeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    with patch("app.services.webhook_service.deliver_webhook_now", return_value=(False, 302, "Redirects are prohibited for security")):
        dispatch_webhook_delivery_task.apply(args=[str(delivery.id)])
        test_db_session.refresh(delivery)

        assert delivery.status == DeliveryStatus.FAILED.value
        assert delivery.is_terminal_failure is True
        assert delivery.last_error_category == "REDIRECT_PROHIBITED"


def test_zero_credential_leakage():
    """10. Headers and payload formatting never leak secret tokens in payloads or summaries."""
    secret = "SUPER_SECRET_BEARER_TOKEN_9999"
    headers, body = format_webhook_payload(
        destination_type="SPLUNK_HEC",
        event_type="incident.created",
        raw_payload={"title": "Ransomware Detected", "token": "sensitive-data"},
        secret_token=secret,
    )
    # Token must be in Authorization header, not in body event data
    assert headers["Authorization"] == f"Splunk {secret}"
    body_str = str(body)
    assert secret not in body_str
    # Sensitive keys sanitized
    assert body["event"]["data"]["token"] == "[REDACTED]"


def test_recursion_guard(test_db_session: Session):
    """11. Internal events with forbidden prefixes (audit., webhook., test., job.) are ignored."""
    tenant = Tenant(name="Guard Corp", slug="guard-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="All Events",
        destination_type="SLACK",
        endpoint_url="https://hooks.slack.com/services/all",
        is_enabled=True,
        event_types=["*"],
    )
    test_db_session.add(dest)
    test_db_session.commit()

    for prohibited_type in ["audit.event.logged", "webhook.delivery.failed", "test.ping", "job.status.changed"]:
        deliveries = dispatch_event_to_destinations(
            db=test_db_session,
            tenant_id=tenant.id,
            event_type=prohibited_type,
            payload={"msg": "ping"},
        )
        assert deliveries == []


def test_threat_intel_provider_outage_never_produces_benign(test_db_session: Session):
    """12. Provider outage, error, or timeout during background refresh MUST NOT produce BENIGN verdict."""
    tenant = Tenant(name="Intel Corp", slug="intel-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    ioc = IndicatorOfCompromise(
        tenant_id=tenant.id,
        indicator_type="IPV4",
        value="198.51.100.45",
        threat_verdict=ThreatVerdict.UNKNOWN.value,
        confidence_score=0,
    )
    test_db_session.add(ioc)
    test_db_session.commit()

    with patch("app.services.threat_intel.virustotal.VirusTotalProvider.lookup", side_effect=httpx.ConnectTimeout("VT timeout")):
        with patch("app.services.threat_intel.abuseipdb.AbuseIPDBProvider.lookup", side_effect=httpx.ConnectError("AbuseIPDB down")):
            res = refresh_threat_intel_task.apply(args=[str(ioc.id), str(tenant.id), True]).result
            test_db_session.refresh(ioc)

            # Verdict MUST remain UNKNOWN, never BENIGN
            assert ioc.threat_verdict != ThreatVerdict.BENIGN.value
            assert ioc.threat_verdict == ThreatVerdict.UNKNOWN.value
            assert ioc.confidence_score == 0


def test_tenant_isolation_on_jobs_and_delivery_retry(client: TestClient):
    """13. Tenant A cannot inspect or retry Tenant B's deliveries or background jobs (Anti-IDOR)."""
    token_a = register_org(client, "Tenant Alpha", "tenant-alpha", "admin-alpha@example.com")
    token_b = register_org(client, "Tenant Beta", "tenant-beta", "admin-beta@example.com")

    with patch("app.api.destinations.validate_destination_url", return_value="https://webhook.org.com/in"):
        with patch("app.services.webhook_service.validate_destination_url", return_value="https://webhook.org.com/in"):
            # Create destination in Tenant A
            dest_a_res = client.post(
                "/api/v1/destinations",
                headers={"Authorization": f"Bearer {token_a}"},
                json={
                    "name": "Alpha Webhook",
                    "destination_type": "SLACK",
                    "endpoint_url": "https://webhook.org.com/in",
                },
            )
            assert dest_a_res.status_code == 201
            dest_a_id = dest_a_res.json()["id"]

    # Test ping to create a delivery in Tenant A
    ping_res = client.post(
        f"/api/v1/destinations/{dest_a_id}/test",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert ping_res.status_code == 200

    # Get deliveries for destination A
    delivs_res = client.get(
        f"/api/v1/destinations/{dest_a_id}/deliveries",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    items = delivs_res.json()["items"]
    assert len(items) >= 1
    delivery_a_id = items[0]["id"]

    # Tenant B tries to retry Tenant A's delivery -> strict 404
    retry_b_res = client.post(
        f"/api/v1/destinations/deliveries/{delivery_a_id}/retry",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert retry_b_res.status_code == 404

    # Tenant A retrying its own delivery -> 200 OK
    with patch("app.core.celery_app.safe_apply_async"):
        retry_a_res = client.post(
            f"/api/v1/destinations/deliveries/{delivery_a_id}/retry",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert retry_a_res.status_code == 200
        assert retry_a_res.json()["delivery"]["status"] == "PENDING"

    # Tenant B lists background jobs -> cannot see Tenant A's jobs
    jobs_b_res = client.get(
        "/api/v1/jobs",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert jobs_b_res.status_code == 200
    b_job_ids = [j["resource_id"] for j in jobs_b_res.json()["items"]]
    assert delivery_a_id not in b_job_ids


def test_api_resilience_when_celery_broker_unreachable(test_db_session: Session):
    """14. When Celery/Redis broker is unreachable, safe_apply_async handles error gracefully without 500 error."""
    tenant = Tenant(name="Offline Corp", slug="offline-corp")
    test_db_session.add(tenant)
    test_db_session.commit()

    dest = NotificationDestination(
        tenant_id=tenant.id,
        name="Resilience Target",
        destination_type="SLACK",
        endpoint_url="https://hooks.slack.com/services/resilience",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.commit()

    # Simulate broker connection failure in safe_apply_async
    mock_task = MagicMock()
    mock_task.apply_async.side_effect = Exception("Redis ConnectionRefusedError: [Errno 111]")

    result = safe_apply_async(mock_task, args=["deliv-123"])
    assert result is None  # Handled cleanly without raising exception

    # In dispatch_event_to_destinations, delivery intent is still persisted
    with patch("app.core.celery_app.safe_apply_async", return_value=None):
        deliveries = dispatch_event_to_destinations(
            db=test_db_session,
            tenant_id=tenant.id,
            event_type="incident.created",
            payload={"id": "inc-resilient", "title": "Critical Alert"},
            sync=False,
        )
        assert len(deliveries) == 1
        assert deliveries[0].status == DeliveryStatus.PENDING.value
        # Persisted in DB
        db_record = test_db_session.scalar(select(WebhookDelivery).where(WebhookDelivery.id == deliveries[0].id))
        assert db_record is not None
        assert db_record.status == DeliveryStatus.PENDING.value

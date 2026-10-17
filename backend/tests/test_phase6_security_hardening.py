from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ioc import IndicatorType, ThreatSeverity, ThreatVerdict
from app.models.playbook import ApprovalStatus, ExecutionStatus, PlaybookExecution, ResponsePlaybook
from app.models.user import User, UserRole
from app.models.webhook import DeliveryStatus, DestinationType, NotificationDestination, WebhookDelivery
from app.services.playbook_service import decide_playbook_approval, execute_playbook_action, trigger_playbook_execution
from app.services.threat_intel.normalizer import normalize_indicator
from app.services.threat_intel.otx import AlienVaultOTXProvider
from app.services.threat_intel.service import ThreatIntelService
from app.services.threat_intel.virustotal import VirusTotalProvider
from app.services.webhook_service import (
    deliver_webhook_now,
    dispatch_event_to_destinations,
    format_webhook_payload,
    retry_pending_webhook_deliveries,
    send_test_webhook,
    validate_destination_url,
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
# 1. Threat Intel Security Verification
# ==============================================================================

def test_otx_404_verdict_is_unknown_not_benign():
    """Verify that OTX 404 (not observed) returns UNKNOWN verdict, NOT BENIGN."""
    provider = AlienVaultOTXProvider()
    with patch("app.services.threat_intel.otx.get_settings") as mock_settings:
        mock_settings.return_value.alienvault_otx_api_key = "test-otx-key"
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            result = provider.lookup(IndicatorType.IPV4.value, "198.51.100.22")

            assert result["verdict"] == ThreatVerdict.UNKNOWN.value
            assert result["confidence"] == 0
            assert result["severity"] == ThreatSeverity.UNKNOWN.value
            assert "no threat pulses found" in result["summary"].lower()


def test_threat_intel_provider_error_prevents_benign_aggregation(test_db_session: Session):
    """A failed lookup or provider error must NEVER result in an aggregated BENIGN verdict."""
    service = ThreatIntelService()

    # Mock two providers: one returns BENIGN, other encounters an error / timeout
    mock_p1 = MagicMock()
    mock_p1.name = "ProviderOK"
    mock_p1.supports_type.return_value = True
    mock_p1.lookup.return_value = {
        "provider": "ProviderOK",
        "verdict": ThreatVerdict.BENIGN.value,
        "confidence": 80,
        "severity": ThreatSeverity.LOW.value,
        "summary": "Clean",
        "raw": {},
        "is_mocked": True,
    }

    mock_p2 = MagicMock()
    mock_p2.name = "ProviderFailing"
    mock_p2.supports_type.return_value = True
    mock_p2.lookup.return_value = {
        "provider": "ProviderFailing",
        "verdict": ThreatVerdict.UNKNOWN.value,
        "confidence": 0,
        "severity": ThreatSeverity.UNKNOWN.value,
        "summary": "Connection timeout",
        "raw": {},
        "error": "Connection timed out",
        "is_mocked": False,
    }

    service.providers = [mock_p1, mock_p2]

    # Create dummy indicator
    from app.models.ioc import IndicatorOfCompromise
    ioc = IndicatorOfCompromise(
        tenant_id=uuid4(),
        indicator_type=IndicatorType.DOMAIN.value,
        value="clean-or-unknown.example.com",
        threat_verdict=ThreatVerdict.UNKNOWN.value,
        confidence_score=0,
        severity=ThreatSeverity.UNKNOWN.value,
        raw_enrichment_data={},
    )
    test_db_session.add(ioc)
    test_db_session.flush()

    enriched = service.enrich_indicator(test_db_session, ioc, force_refresh=True)

    # Must NOT be BENIGN because ProviderFailing had an error
    assert enriched.threat_verdict == ThreatVerdict.UNKNOWN.value
    assert enriched.confidence_score == 0
    assert enriched.severity == ThreatSeverity.UNKNOWN.value


def test_virustotal_ipv6_support():
    """Verify VirusTotal supports IPv6 and maps endpoint correctly."""
    vt = VirusTotalProvider()
    assert vt.supports_type(IndicatorType.IPV6.value) is True

    with patch("app.services.threat_intel.virustotal.get_settings") as mock_settings:
        mock_settings.return_value.virustotal_api_key = "test-vt-key"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 20},
                    "reputation": 5,
                }
            }
        }
        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            res = vt.lookup(IndicatorType.IPV6.value, "2001:db8::1")
            assert res["verdict"] == ThreatVerdict.BENIGN.value
            mock_client.get.assert_called_once()
            called_url = mock_client.get.call_args[0][0]
            assert "ip_addresses/2001:db8::1" in called_url


def test_normalizer_rejects_empty_hostname_and_strips_credentials():
    """Verify normalizer rejects URLs with empty hostnames and strips userinfo credentials."""
    with pytest.raises(ValueError, match="valid hostname"):
        normalize_indicator("URL", "http:///path/to/resource")

    with pytest.raises(ValueError, match="valid hostname"):
        normalize_indicator("URL", "http://:8080/path")

    # URL with user credentials should have credentials stripped safely
    itype, norm_url = normalize_indicator("URL", "http://user:pass@evil-domain.com:8080/test/path?foo=bar#anchor")
    assert itype == IndicatorType.URL.value
    assert "user:pass" not in norm_url
    assert norm_url == "http://evil-domain.com:8080/test/path?foo=bar"


# ==============================================================================
# 2. Webhook & SIEM Security Verification
# ==============================================================================

def test_ssrf_rejects_ipv4_mapped_ipv6_and_credentials():
    """Ensure SSRF protection detects IPv4-mapped IPv6 loopback, private IPs, and metadata."""
    # IPv4-mapped IPv6 loopback
    with pytest.raises(ValueError, match="prohibited IP address"):
        validate_destination_url("http://[::ffff:127.0.0.1]/webhook")

    # IPv4-mapped IPv6 link-local cloud metadata
    with pytest.raises(ValueError, match="prohibited IP address"):
        validate_destination_url("http://[::ffff:169.254.169.254]/webhook")

    # IPv4-mapped IPv6 private 10.x.x.x
    with pytest.raises(ValueError, match="prohibited IP address"):
        validate_destination_url("http://[::ffff:10.0.0.5]/webhook")

    # Embedded credentials in webhook URL
    with pytest.raises(ValueError, match="embedded user credentials"):
        validate_destination_url("https://admin:secret@api.example.com/alerts")


def test_deliver_webhook_dispatch_time_revalidation_and_no_redirects():
    """Verify deliver_webhook_now revalidates at dispatch time and refuses HTTP redirects."""
    tenant_id = uuid4()
    # Create destination with loopback URL (simulating subsequent modification / DNS rebinding)
    dest = NotificationDestination(
        id=uuid4(),
        tenant_id=tenant_id,
        name="Rebinding Target",
        destination_type=DestinationType.SPLUNK_HEC.value,
        endpoint_url="http://127.0.0.1:8080/internal-drain",
        is_enabled=True,
    )

    # Attempting to deliver must fail at dispatch time due to SSRF revalidation
    success, code, err = deliver_webhook_now(dest, "incident.created", {"id": "123"})
    assert success is False
    assert "dispatch-time security check" in err
    assert code is None

    # Test redirect refusal: server responds with 302 redirect
    dest_public = NotificationDestination(
        id=uuid4(),
        tenant_id=tenant_id,
        name="Redirecting Target",
        destination_type=DestinationType.SPLUNK_HEC.value,
        endpoint_url="https://api.sentinelops-test-siem.com/webhook",
        is_enabled=True,
    )

    mock_redirect_resp = MagicMock()
    mock_redirect_resp.status_code = 302
    mock_redirect_resp.text = "Redirecting"

    mock_client = MagicMock()
    mock_client.post.return_value = mock_redirect_resp

    with patch("app.services.webhook_service.validate_destination_url", return_value=dest_public.endpoint_url):
        success, code, err = deliver_webhook_now(
            dest_public,
            "incident.created",
            {"id": "123"},
            client=mock_client,
        )
        assert success is False
        assert code == 302
        assert "Redirects are prohibited" in err


def test_webhook_synthetic_flag_and_recursion_guard(test_db_session: Session):
    """Verify synthetic tagging on test pings and recursion guard on internal audit/webhook events."""
    tenant_id = uuid4()
    dest = NotificationDestination(
        id=uuid4(),
        tenant_id=tenant_id,
        name="Synthetic SIEM",
        destination_type=DestinationType.SPLUNK_HEC.value,
        endpoint_url="https://siem.sentinelops-valid.org/events",
        is_enabled=True,
    )
    test_db_session.add(dest)
    test_db_session.flush()

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp

    with patch("app.services.webhook_service.validate_destination_url", return_value=dest.endpoint_url):
        success, code, err = send_test_webhook(test_db_session, dest, client=mock_client)
        assert success is True
        assert code == 200

        # Check call headers for X-SentinelOps-Synthetic
        called_headers = mock_client.post.call_args[1]["headers"]
        called_body = mock_client.post.call_args[1]["json"]
        assert called_headers.get("X-SentinelOps-Synthetic") == "true"
        assert "[SYNTHETIC TEST]" in called_body["event"]["data"]["message"]
        assert called_body["event"]["data"]["is_synthetic"] is True

    # Test recursion guard
    deliveries = dispatch_event_to_destinations(
        db=test_db_session,
        tenant_id=tenant_id,
        event_type="audit.event.logged",
        payload={"id": "audit-123"},
        client=mock_client,
    )
    assert deliveries == []  # Blocked by recursion guard prefix 'audit.'


def test_destinations_deliveries_list_endpoint_and_isolation(client: TestClient):
    """Verify GET /api/v1/destinations/deliveries/list supports pagination and enforces tenant isolation."""
    token_t1 = register_org(client, "Delivery Org 1", "del-org-1", "admin-del1@example.com")
    token_t2 = register_org(client, "Delivery Org 2", "del-org-2", "admin-del2@example.com")

    # Create destination in Tenant 1 with local allowed for test harness
    with patch("app.services.webhook_service.validate_destination_url", return_value="https://webhook.org1.com/in"):
        create_res = client.post(
            "/api/v1/destinations",
            headers={"Authorization": f"Bearer {token_t1}"},
            json={
                "name": "Org 1 Webhook",
                "destination_type": "SPLUNK_HEC",
                "endpoint_url": "https://webhook.org1.com/in",
            },
        )
        assert create_res.status_code == 201
        dest_id = create_res.json()["id"]

        # Send test ping
        with patch("app.services.webhook_service.deliver_webhook_now", return_value=(True, 200, None)):
            test_res = client.post(
                f"/api/v1/destinations/{dest_id}/test",
                headers={"Authorization": f"Bearer {token_t1}"},
            )
            assert test_res.status_code == 200

    # Tenant 1 queries deliveries list
    list_res1 = client.get(
        "/api/v1/destinations/deliveries/list?page=1&page_size=20",
        headers={"Authorization": f"Bearer {token_t1}"},
    )
    assert list_res1.status_code == 200
    data1 = list_res1.json()
    assert data1["total"] >= 1
    assert data1["items"][0]["destination_id"] == dest_id

    # Tenant 2 queries deliveries list -> isolation verified (0 items)
    list_res2 = client.get(
        "/api/v1/destinations/deliveries/list?page=1&page_size=20",
        headers={"Authorization": f"Bearer {token_t2}"},
    )
    assert list_res2.status_code == 200
    data2 = list_res2.json()
    assert data2["total"] == 0
    assert len(data2["items"]) == 0


def test_retry_pending_webhook_deliveries(test_db_session: Session):
    """Verify durable retry mechanism re-attempts deliveries in RETRYING status."""
    tenant_id = uuid4()
    dest = NotificationDestination(
        id=uuid4(),
        tenant_id=tenant_id,
        name="Retry Destination",
        destination_type=DestinationType.SPLUNK_HEC.value,
        endpoint_url="https://valid-target.sentinelops.test/hook",
        is_enabled=True,
    )
    test_db_session.add(dest)

    # Create a delivery in RETRYING state with past retry timestamp
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    delivery = WebhookDelivery(
        tenant_id=tenant_id,
        destination_id=dest.id,
        event_type="incident.created",
        payload={"id": "inc-999"},
        status=DeliveryStatus.RETRYING.value,
        attempt_count=1,
        max_attempts=3,
        last_attempt_at=past,
        next_retry_at=past,
    )
    test_db_session.add(delivery)
    test_db_session.commit()

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp

    with patch("app.services.webhook_service.validate_destination_url", return_value=dest.endpoint_url):
        processed = retry_pending_webhook_deliveries(test_db_session, client=mock_client)
        assert processed == 1

        test_db_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.SUCCESS.value
        assert delivery.attempt_count == 2
        assert delivery.response_status_code == 200


# ==============================================================================
# 3. Incident Response & Playbook Safety Verification
# ==============================================================================

def test_anti_privilege_escalation_tenant_admin_cannot_revoke_super_admin(test_db_session: Session):
    """Verify Tenant Administrator cannot revoke Super Administrator sessions."""
    tenant_id = uuid4()
    tenant_admin = User(
        id=uuid4(),
        tenant_id=tenant_id,
        name="Tenant Admin",
        email="tadmin@org.corp",
        password_hash="argon2_hash",
        role=UserRole.TENANT_ADMIN.value,
    )
    super_admin = User(
        id=uuid4(),
        tenant_id=tenant_id,
        name="Super Admin",
        email="superadmin@corp.global",
        password_hash="argon2_hash",
        role=UserRole.SUPER_ADMIN.value,
    )
    test_db_session.add_all([tenant_admin, super_admin])
    test_db_session.flush()

    res = execute_playbook_action(
        db=test_db_session,
        action_type="REVOKE_USER_SESSIONS",
        action_config={},
        parameters={"target_user_id": str(super_admin.id)},
        tenant_id=tenant_id,
        actor_user=tenant_admin,
        is_dry_run=False,
    )

    assert res["status"] == "FAILED"
    assert "Tenant Administrator cannot revoke Super Administrator" in res["details"]


def test_anti_self_approval_and_cross_tenant_rejection(client: TestClient):
    """Verify operator cannot self-approve, and cross-tenant approval returns 404."""
    token_t1 = register_org(client, "Approval Hardening 1", "appr-hard-1", "admin1-hard@example.com")
    token_t2 = register_org(client, "Approval Hardening 2", "appr-hard-2", "admin2-hard@example.com")

    # Create playbook in Tenant 1 requiring approval
    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {token_t1}"},
        json={
            "name": "Containment Playbook",
            "actions": [{"action_type": "BLOCK_IP", "ip_address": "203.0.113.10"}],
            "is_dry_run": False,
            "requires_approval": True,
        },
    )
    assert pb_res.status_code == 201
    pb_id = pb_res.json()["id"]

    # Trigger execution
    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {token_t1}"},
    )
    assert exec_res.status_code == 200
    exec_id = exec_res.json()["id"]
    assert exec_res.json()["status"] == "PENDING_APPROVAL"

    # Self-approval attempt by same operator -> 400
    self_res = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {token_t1}"},
        json={"notes": "Approving my own action"},
    )
    assert self_res.status_code == 400
    assert "Anti-self-approval" in self_res.json()["detail"]

    # Cross-tenant approval attempt by Tenant 2 admin -> 404
    cross_res = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {token_t2}"},
        json={"notes": "Cross tenant approval attempt"},
    )
    assert cross_res.status_code == 404
    assert "not found" in cross_res.json()["detail"].lower()

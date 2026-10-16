from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.models.user import UserRole
from app.services.webhook_service import validate_destination_url


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


def test_ssrf_validation_blocks_loopback_and_private_ips():
    # Loopback
    with pytest.raises(ValueError, match="(?i)prohibited"):
        validate_destination_url("http://127.0.0.1:8000/webhook")

    with pytest.raises(ValueError, match="(?i)prohibited"):
        validate_destination_url("http://localhost:5000/webhook")

    # Cloud Metadata
    with pytest.raises(ValueError, match="(?i)prohibited"):
        validate_destination_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(ValueError, match="(?i)prohibited"):
        validate_destination_url("http://metadata.google.internal/computeMetadata/v1/")

    # Private IP blocks
    with pytest.raises(ValueError, match="(?i)prohibited"):
        validate_destination_url("http://10.0.0.1:9000/webhook")

    with pytest.raises(ValueError, match="(?i)prohibited"):
        validate_destination_url("http://192.168.1.1/splunk")

    # Invalid schemes
    with pytest.raises(ValueError, match="scheme must be http or https"):
        validate_destination_url("file:///etc/passwd")


def test_ssrf_validation_allows_valid_public_urls():
    url = validate_destination_url("https://hooks.slack.com/services/T00/B00/XXXX", allow_local=True)
    assert url == "https://hooks.slack.com/services/T00/B00/XXXX"


def test_create_and_list_destinations_tenant_isolation(client: TestClient):
    token_t1 = register_org(client, "Dest Org 1", "dest-org-1", "admin-d1@example.com")
    token_t2 = register_org(client, "Dest Org 2", "dest-org-2", "admin-d2@example.com")

    # Create destination in Tenant 1 (with allow_local=True in test)
    with patch.object(get_settings(), "allow_local_webhooks", True):
        res1 = client.post(
            "/api/v1/destinations",
            headers={"Authorization": f"Bearer {token_t1}"},
            json={
                "name": "SOC Splunk HEC",
                "destination_type": "SPLUNK_HEC",
                "endpoint_url": "https://splunk.example.com:8088/services/collector",
                "secret_token": "hec-token-super-secret-12345",
                "event_types": ["incident.created.critical", "incident.status.changed"],
            },
        )
        assert res1.status_code == 201
        dest1 = res1.json()
        assert dest1["name"] == "SOC Splunk HEC"
        # Verify secret token is NOT returned in response
        assert "secret_token" not in dest1
        assert dest1["has_secret"] is True

        # Tenant 2 cannot see Tenant 1's destination
        res2 = client.get("/api/v1/destinations", headers={"Authorization": f"Bearer {token_t2}"})
        assert res2.status_code == 200
        assert len(res2.json()) == 0

        # Tenant 1 sees their destination
        res_list1 = client.get("/api/v1/destinations", headers={"Authorization": f"Bearer {token_t1}"})
        assert res_list1.status_code == 200
        assert len(res_list1.json()) == 1


def test_webhook_rbac_viewer_cannot_manage_destinations(client: TestClient):
    admin_token = register_org(client, "Dest RBAC Org", "dest-rbac-org", "admin-drbac@example.com")
    viewer_token = create_user_in_org(client, admin_token, "Viewer User", "viewer-dest@example.com", UserRole.SECURITY_VIEWER.value)

    # Viewer attempts creation -> 403
    res_create = client.post(
        "/api/v1/destinations",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "name": "Malicious Webhook",
            "destination_type": "SLACK",
            "endpoint_url": "https://hooks.slack.com/services/T/B/X",
        },
    )
    assert res_create.status_code == 403


def test_test_webhook_synthetic_ping(client: TestClient):
    token = register_org(client, "Ping Org", "ping-org", "admin-ping@example.com")

    with patch.object(get_settings(), "allow_local_webhooks", True):
        res = client.post(
            "/api/v1/destinations",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "Teams Ops Channel",
                "destination_type": "MS_TEAMS",
                "endpoint_url": "https://outlook.office.com/webhook/test",
            },
        )
        dest_id = res.json()["id"]

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("app.services.webhook_service.deliver_webhook_now", return_value=(True, 200, None)):
            test_res = client.post(
                f"/api/v1/destinations/{dest_id}/test",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert test_res.status_code == 200
            data = test_res.json()
            assert data["success"] is True
            assert data["status_code"] == 200

            # Check delivery history
            history_res = client.get(
                f"/api/v1/destinations/{dest_id}/deliveries",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert history_res.status_code == 200
            items = history_res.json()["items"]
            assert len(items) == 1
            assert items[0]["event_type"] == "test.ping"
            assert items[0]["status"] == "SUCCESS"


def test_critical_incident_triggers_webhook_dispatch(client: TestClient):
    token = register_org(client, "Alert Org", "alert-org", "admin-alert@example.com")

    # Set up destination subscribed to incident.created.critical
    with patch.object(get_settings(), "allow_local_webhooks", True):
        dest_res = client.post(
            "/api/v1/destinations",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "Critical Alerts Slack",
                "destination_type": "SLACK",
                "endpoint_url": "https://hooks.slack.com/services/alert",
                "event_types": ["incident.created.critical"],
            },
        )
        dest_id = dest_res.json()["id"]

        with patch("app.services.webhook_service.deliver_webhook_now", return_value=(True, 200, None)):
            # Create a CRITICAL incident
            inc_res = client.post(
                "/api/v1/incidents",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "title": "Critical Ransomware Outbreak",
                    "category": "RANSOMWARE",
                    "severity": "CRITICAL",
                },
            )
            assert inc_res.status_code == 201

            # Verify delivery was recorded
            deliv_res = client.get(
                f"/api/v1/destinations/{dest_id}/deliveries",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert deliv_res.status_code == 200
            items = deliv_res.json()["items"]
            assert len(items) == 1
            assert items[0]["event_type"] == "incident.created.critical"
            assert items[0]["status"] == "SUCCESS"


def test_webhook_failure_does_not_rollback_incident(client: TestClient):
    token = register_org(client, "FailSafe Org", "failsafe-org", "admin-fail@example.com")

    with patch.object(get_settings(), "allow_local_webhooks", True):
        dest_res = client.post(
            "/api/v1/destinations",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "Flaky SIEM",
                "destination_type": "SPLUNK_HEC",
                "endpoint_url": "https://splunk.flaky.com/hec",
                "event_types": ["incident.created.critical"],
            },
        )
        dest_id = dest_res.json()["id"]

        with patch("app.services.webhook_service.deliver_webhook_now", return_value=(False, 503, "HTTP status 503: Service Unavailable")):
            # Creating incident should STILL SUCCEED (201) even if webhook fails
            inc_res = client.post(
                "/api/v1/incidents",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "title": "Critical Server Crash",
                    "category": "OTHER",
                    "severity": "CRITICAL",
                },
            )
            assert inc_res.status_code == 201

            # Delivery recorded as RETRYING or FAILED
            deliv_res = client.get(
                f"/api/v1/destinations/{dest_id}/deliveries",
                headers={"Authorization": f"Bearer {token}"},
            )
            items = deliv_res.json()["items"]
            assert len(items) == 1
            assert items[0]["status"] in ("RETRYING", "FAILED")
            assert "HTTP status 503" in items[0]["error_summary"]

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.ioc import IndicatorOfCompromise, IndicatorType, ThreatSeverity, ThreatVerdict
from app.models.user import UserRole
from app.services.threat_intel.normalizer import normalize_indicator


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


def test_ioc_normalization_and_validation():
    # IPv4
    t, v = normalize_indicator("ipv4", "  198.51.100.25  ")
    assert t == "IPV4"
    assert v == "198.51.100.25"

    # IPv6
    t, v = normalize_indicator("IPV6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert t == "IPV6"
    assert v == "2001:db8:85a3::8a2e:370:7334"

    # Domain
    t, v = normalize_indicator("DOMAIN", "  MALICIOUS-C2.EXAMPLE.COM. ")
    assert t == "DOMAIN"
    assert v == "malicious-c2.example.com"

    # URL
    t, v = normalize_indicator("url", "https://EVIL.com/payload.exe?token=123")
    assert t == "URL"
    assert v == "https://evil.com/payload.exe?token=123"

    # Hashes
    t, v = normalize_indicator("sha256", "A" * 64)
    assert t == "SHA256"
    assert v == "a" * 64

    t, v = normalize_indicator("sha1", "B" * 40)
    assert t == "SHA1"
    assert v == "b" * 40

    t, v = normalize_indicator("md5", "C" * 32)
    assert t == "MD5"
    assert v == "c" * 32


def test_ioc_invalid_inputs_rejected():
    with pytest.raises(ValueError, match="Invalid IPv4"):
        normalize_indicator("IPV4", "999.999.999.999")

    with pytest.raises(ValueError, match="Invalid domain"):
        normalize_indicator("DOMAIN", "not a domain!@#")

    with pytest.raises(ValueError, match="URL must use http or https"):
        normalize_indicator("URL", "ftp://evil.com/file")

    with pytest.raises(ValueError, match="SHA-256 hash must be exactly 64"):
        normalize_indicator("SHA256", "short_hash")

    with pytest.raises(ValueError, match="Unsupported indicator type"):
        normalize_indicator("UNKNOWN_TYPE", "value")


def test_create_and_list_iocs_tenant_isolation(client: TestClient):
    token_t1 = register_org(client, "IOC Org 1", "ioc-org-1", "admin-ioc1@example.com")
    token_t2 = register_org(client, "IOC Org 2", "ioc-org-2", "admin-ioc2@example.com")

    # Create IOC in Tenant 1
    res1 = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token_t1}"},
        json={
            "indicator_type": "IPV4",
            "value": "203.0.113.50",
            "notes": "Cobalt Strike C2 server",
            "source": "THREAT_REPORT",
        },
    )
    assert res1.status_code == 201
    ioc1 = res1.json()
    assert ioc1["value"] == "203.0.113.50"
    assert ioc1["threat_verdict"] == "UNKNOWN"

    # Tenant 2 cannot see Tenant 1's IOC
    res2 = client.get("/api/v1/iocs", headers={"Authorization": f"Bearer {token_t2}"})
    assert res2.status_code == 200
    t2_items = res2.json()["items"]
    assert len(t2_items) == 0

    # Tenant 1 sees their IOC
    res_list1 = client.get("/api/v1/iocs", headers={"Authorization": f"Bearer {token_t1}"})
    assert res_list1.status_code == 200
    assert len(res_list1.json()["items"]) == 1


def test_cross_tenant_ioc_detail_returns_404(client: TestClient):
    token_t1 = register_org(client, "IOC Cross 1", "ioc-cross-1", "admin-cross1@example.com")
    token_t2 = register_org(client, "IOC Cross 2", "ioc-cross-2", "admin-cross2@example.com")

    res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token_t1}"},
        json={"indicator_type": "DOMAIN", "value": "apt-c2.evil.com"},
    )
    ioc_id = res.json()["id"]

    # Tenant 2 accesses Tenant 1 IOC -> 404
    cross_res = client.get(f"/api/v1/iocs/{ioc_id}", headers={"Authorization": f"Bearer {token_t2}"})
    assert cross_res.status_code == 404
    assert cross_res.json()["detail"] == "Indicator not found"


def test_ioc_duplicate_rejected(client: TestClient):
    token = register_org(client, "IOC Dup Org", "ioc-dup-org", "admin-dup@example.com")

    payload = {"indicator_type": "SHA256", "value": "e" * 64}
    res1 = client.post("/api/v1/iocs", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res1.status_code == 201

    # Duplicate in same tenant -> 409
    res2 = client.post("/api/v1/iocs", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"]


def test_ioc_rbac_viewer_cannot_create_or_enrich(client: TestClient):
    admin_token = register_org(client, "IOC RBAC Org", "ioc-rbac-org", "admin-rbac@example.com")
    viewer_token = create_user_in_org(client, admin_token, "Viewer User", "viewer-ioc@example.com", UserRole.SECURITY_VIEWER.value)

    # Viewer attempts creation -> 403
    res_create = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"indicator_type": "IPV4", "value": "198.51.100.99"},
    )
    assert res_create.status_code == 403

    # Admin creates IOC
    res_admin = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"indicator_type": "IPV4", "value": "198.51.100.99"},
    )
    ioc_id = res_admin.json()["id"]

    # Viewer can read IOC -> 200
    res_get = client.get(f"/api/v1/iocs/{ioc_id}", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_get.status_code == 200

    # Viewer attempts enrichment -> 403
    res_enrich = client.post(
        f"/api/v1/iocs/{ioc_id}/enrich",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res_enrich.status_code == 403


def test_virustotal_mocked_lookup_success(client: TestClient):
    token = register_org(client, "VT Org", "vt-org", "admin-vt@example.com")

    res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token}"},
        json={"indicator_type": "SHA256", "value": "f" * 64},
    )
    ioc_id = res.json()["id"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 2,
                    "harmless": 20,
                    "undetected": 30,
                },
                "reputation": -50,
                "tags": ["trojan", "ransomware"],
            }
        }
    }

    with patch.object(get_settings(), "virustotal_api_key", "test_vt_api_key_12345"):
        with patch("httpx.Client.get", return_value=mock_resp):
            enrich_res = client.post(
                f"/api/v1/iocs/{ioc_id}/enrich",
                headers={"Authorization": f"Bearer {token}"},
                json={"providers": ["VirusTotal"]},
            )
            assert enrich_res.status_code == 200
            data = enrich_res.json()
            assert data["threat_verdict"] == "MALICIOUS"
            assert data["confidence_score"] >= 80
            assert data["severity"] == "CRITICAL"
            assert "VirusTotal" in data["raw_enrichment_data"]["providers"]


def test_abuseipdb_mocked_lookup_success(client: TestClient):
    token = register_org(client, "Abuse Org", "abuse-org", "admin-abuse@example.com")

    res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token}"},
        json={"indicator_type": "IPV4", "value": "198.51.100.88"},
    )
    ioc_id = res.json()["id"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 92,
            "totalReports": 45,
            "countryCode": "US",
            "isp": "Evil Host LLC",
            "isWhitelisted": False,
        }
    }

    with patch.object(get_settings(), "abuseipdb_api_key", "test_abuse_key_12345"):
        with patch("httpx.Client.get", return_value=mock_resp):
            enrich_res = client.post(
                f"/api/v1/iocs/{ioc_id}/enrich",
                headers={"Authorization": f"Bearer {token}"},
                json={"providers": ["AbuseIPDB"]},
            )
            assert enrich_res.status_code == 200
            data = enrich_res.json()
            assert data["threat_verdict"] == "MALICIOUS"
            assert data["confidence_score"] == 92
            assert data["severity"] == "CRITICAL"


def test_threat_intel_cache_ttl(client: TestClient, test_db_session: Session):
    token = register_org(client, "Cache Org", "cache-org", "admin-cache@example.com")

    res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token}"},
        json={"indicator_type": "DOMAIN", "value": "cached-domain.com"},
    )
    ioc_id = res.json()["id"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 10}
            }
        }
    }

    call_count = 0

    def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_resp

    with patch.object(get_settings(), "virustotal_api_key", "test_key"):
        with patch("httpx.Client.get", side_effect=mock_get):
            # First enrichment -> invokes remote call
            client.post(
                f"/api/v1/iocs/{ioc_id}/enrich",
                headers={"Authorization": f"Bearer {token}"},
                json={"providers": ["VirusTotal"]},
            )
            assert call_count == 1

            # Second enrichment within TTL -> should use cache, not call remote
            client.post(
                f"/api/v1/iocs/{ioc_id}/enrich",
                headers={"Authorization": f"Bearer {token}"},
                json={"providers": ["VirusTotal"], "force_refresh": False},
            )
            assert call_count == 1

            # Third enrichment with force_refresh=True -> calls remote again
            client.post(
                f"/api/v1/iocs/{ioc_id}/enrich",
                headers={"Authorization": f"Bearer {token}"},
                json={"providers": ["VirusTotal"], "force_refresh": True},
            )
            assert call_count == 2


def test_missing_api_keys_handled_gracefully(client: TestClient):
    token = register_org(client, "NoKey Org", "nokey-org", "admin-nokey@example.com")

    res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token}"},
        json={"indicator_type": "IPV4", "value": "198.51.100.12"},
    )
    ioc_id = res.json()["id"]

    # When keys are None
    with patch.object(get_settings(), "virustotal_api_key", None):
        with patch.object(get_settings(), "abuseipdb_api_key", None):
            with patch.object(get_settings(), "alienvault_otx_api_key", None):
                enrich_res = client.post(
                    f"/api/v1/iocs/{ioc_id}/enrich",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert enrich_res.status_code == 200
                data = enrich_res.json()
                # Must not falsely mark as clean
                assert data["threat_verdict"] == "UNKNOWN"
                # Provider results record error state
                providers = data["raw_enrichment_data"]["providers"]
                for p_name, p_data in providers.items():
                    assert p_data["error"] == "API key not configured"


def test_mark_false_positive_and_update_notes(client: TestClient):
    token = register_org(client, "FP Org", "fp-org", "admin-fp@example.com")

    res = client.post(
        "/api/v1/iocs",
        headers={"Authorization": f"Bearer {token}"},
        json={"indicator_type": "IPV4", "value": "198.51.100.15"},
    )
    ioc_id = res.json()["id"]

    patch_res = client.patch(
        f"/api/v1/iocs/{ioc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"is_false_positive": True, "notes": "Whitelisted vulnerability scanner IP"},
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["is_false_positive"] is True
    assert "Whitelisted" in data["notes"]

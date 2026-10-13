import hashlib
import io
import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.database import Base, get_db
from app.main import app
from app.models.incident import IncidentCategory, IncidentSeverity, IncidentStatus
from app.models.user import UserRole


@pytest.fixture
def temp_upload_dir():
    temp_dir = tempfile.mkdtemp()
    settings = get_settings()
    original_upload_dir = settings.upload_dir
    settings.upload_dir = temp_dir
    yield temp_dir
    settings.upload_dir = original_upload_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_db_session():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(test_db_session: Session, temp_upload_dir: str) -> TestClient:
    def override_db():
        yield test_db_session

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


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


def create_sample_incident(client: TestClient, token: str, title: str = "Investigation Incident") -> dict:
    res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": title,
            "description": "Evidence test incident",
            "category": IncidentCategory.MALWARE.value,
            "severity": IncidentSeverity.HIGH.value,
        },
    )
    assert res.status_code == 201
    return res.json()


# 1. Successful upload of a valid log file computes SHA-256 and records metadata
def test_upload_valid_log_file_computes_sha256(client: TestClient):
    token = register_org(client, "Org A", "org-a", "admin-a@example.com")
    incident = create_sample_incident(client, token)

    content = b"2026-10-13 12:00:00 [CRITICAL] Unauthorized root access detected\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("syslog_auth.log", io.BytesIO(content), "text/plain")},
        data={"description": "Auth log snippet from target host"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["filename"] == "syslog_auth.log"
    assert data["file_size_bytes"] == len(content)
    assert data["sha256_hash"] == expected_sha256
    assert data["mime_type"] == "text/plain"
    assert data["description"] == "Auth log snippet from target host"
    assert data["incident_id"] == incident["id"]
    assert data["uploaded_by_name"] == "Admin org-a"


# 2. Successful upload of a valid PCAP capture file
def test_upload_valid_pcap_file(client: TestClient):
    token = register_org(client, "Org B", "org-b", "admin-b@example.com")
    incident = create_sample_incident(client, token)

    pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 500
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("capture.pcap", io.BytesIO(pcap_header), "application/octet-stream")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["mime_type"] == "application/vnd.tcpdump.pcap"
    assert data["sha256_hash"] == hashlib.sha256(pcap_header).hexdigest()


# 3. Successful upload of a valid PCAPNG capture file
def test_upload_valid_pcapng_file(client: TestClient):
    token = register_org(client, "Org C", "org-c", "admin-c@example.com")
    incident = create_sample_incident(client, token)

    pcapng_header = b"\x0a\x0d\x0d\x0a" + b"\x00" * 600
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("network_dump.pcapng", io.BytesIO(pcapng_header), "application/octet-stream")},
    )
    assert response.status_code == 201
    assert response.json()["mime_type"] == "application/x-pcapng"


# 4. Successful upload of a valid ZIP archive file
def test_upload_valid_zip_archive(client: TestClient):
    token = register_org(client, "Org D", "org-d", "admin-d@example.com")
    incident = create_sample_incident(client, token)

    zip_header = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 300
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("memory_dump.zip", io.BytesIO(zip_header), "application/zip")},
    )
    assert response.status_code == 201
    assert response.json()["mime_type"] == "application/zip"


# 5. Successful upload of valid JSON structured report
def test_upload_valid_json_report(client: TestClient):
    token = register_org(client, "Org E", "org-e", "admin-e@example.com")
    incident = create_sample_incident(client, token)

    json_content = b'{"ioc": "198.51.100.24", "threat_actor": "APT29", "confidence": 95}'
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("threat_intel.json", io.BytesIO(json_content), "application/json")},
    )
    assert response.status_code == 201
    assert response.json()["mime_type"] == "application/json"


# 6. Successful upload of valid CSV telemetry export
def test_upload_valid_csv_export(client: TestClient):
    token = register_org(client, "Org F", "org-f", "admin-f@example.com")
    incident = create_sample_incident(client, token)

    csv_content = b"timestamp,src_ip,dest_ip,port\n2026-10-13T10:00:00Z,10.0.0.1,192.0.2.1,443\n"
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("firewall_flows.csv", io.BytesIO(csv_content), "text/csv")},
    )
    assert response.status_code == 201
    assert response.json()["mime_type"] == "text/csv"


# 7. Disallowed file extension rejected (400 Bad Request)
def test_disallowed_file_extension_rejected(client: TestClient):
    token = register_org(client, "Org G", "org-g", "admin-g@example.com")
    incident = create_sample_incident(client, token)

    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00somebinarydata"), "application/x-msdownload")},
    )
    assert response.status_code == 400
    assert "not permitted" in response.json()["detail"]


# 8. Executable disguised as .txt/.log rejected by magic byte inspection (400 Bad Request)
def test_executable_disguised_as_txt_rejected(client: TestClient):
    token = register_org(client, "Org H", "org-h", "admin-h@example.com")
    incident = create_sample_incident(client, token)

    # Windows PE executable header MZ
    disguised_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("notes.txt", io.BytesIO(disguised_pe), "text/plain")},
    )
    assert response.status_code == 400
    assert "executable" in response.json()["detail"].lower()

    # Linux ELF executable header \x7fELF disguised as .log
    disguised_elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
    response_elf = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("system.log", io.BytesIO(disguised_elf), "text/plain")},
    )
    assert response_elf.status_code == 400
    assert "executable" in response_elf.json()["detail"].lower()


# 9. Invalid magic bytes for PCAP extension rejected
def test_invalid_pcap_magic_rejected(client: TestClient):
    token = register_org(client, "Org I", "org-i", "admin-i@example.com")
    incident = create_sample_incident(client, token)

    fake_pcap = b"INVALID_MAGIC_HEADER_FOR_PCAP" + b"\x00" * 500
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("corrupt.pcap", io.BytesIO(fake_pcap), "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "File signature validation failed" in response.json()["detail"]


# 10. File exceeding size limit rejected (413 Request Entity Too Large)
def test_file_exceeding_max_size_rejected(client: TestClient):
    token = register_org(client, "Org J", "org-j", "admin-j@example.com")
    incident = create_sample_incident(client, token)

    settings = get_settings()
    # Temporarily set a small max size limit to test streaming enforcement
    original_max = settings.max_upload_size
    settings.max_upload_size = 1024  # 1 KB limit
    try:
        large_content = b"A" * 2048  # 2 KB file
        response = client.post(
            f"/api/v1/incidents/{incident['id']}/evidence",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("large_log.txt", io.BytesIO(large_content), "text/plain")},
        )
        assert response.status_code == 413
        assert "exceeds maximum allowed size" in response.json()["detail"]
    finally:
        settings.max_upload_size = original_max


# 11. Path traversal in uploaded filename is sanitized
def test_filename_path_traversal_sanitized(client: TestClient):
    token = register_org(client, "Org K", "org-k", "admin-k@example.com")
    incident = create_sample_incident(client, token)

    content = b"harmless log text"
    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("../../../../etc/passwd.log", io.BytesIO(content), "text/plain")},
    )
    assert response.status_code == 201
    sanitized_name = response.json()["filename"]
    assert "/" not in sanitized_name
    assert "\\" not in sanitized_name
    assert ".." not in sanitized_name


# 12. Cross-tenant evidence upload rejected with 404 (Anti-IDOR)
def test_cross_tenant_evidence_upload_rejected_with_404(client: TestClient):
    token_tenant1 = register_org(client, "Tenant One", "tenant-one", "admin1@example.com")
    token_tenant2 = register_org(client, "Tenant Two", "tenant-two", "admin2@example.com")

    incident_t1 = create_sample_incident(client, token_tenant1, "Tenant 1 Incident")

    # Tenant 2 tries to upload evidence to Tenant 1's incident
    response = client.post(
        f"/api/v1/incidents/{incident_t1['id']}/evidence",
        headers={"Authorization": f"Bearer {token_tenant2}"},
        files={"file": ("test.log", io.BytesIO(b"log data"), "text/plain")},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


# 13. Cross-tenant evidence listing rejected with 404 (Anti-IDOR)
def test_cross_tenant_evidence_list_rejected_with_404(client: TestClient):
    token_tenant1 = register_org(client, "Org L1", "org-l1", "admin-l1@example.com")
    token_tenant2 = register_org(client, "Org L2", "org-l2", "admin-l2@example.com")

    incident_t1 = create_sample_incident(client, token_tenant1)

    response = client.get(
        f"/api/v1/incidents/{incident_t1['id']}/evidence",
        headers={"Authorization": f"Bearer {token_tenant2}"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


# 14. Cross-tenant evidence download rejected with 404 (Anti-IDOR)
def test_cross_tenant_evidence_download_rejected_with_404(client: TestClient):
    token_tenant1 = register_org(client, "Org M1", "org-m1", "admin-m1@example.com")
    token_tenant2 = register_org(client, "Org M2", "org-m2", "admin-m2@example.com")

    incident_t1 = create_sample_incident(client, token_tenant1)
    upload_res = client.post(
        f"/api/v1/incidents/{incident_t1['id']}/evidence",
        headers={"Authorization": f"Bearer {token_tenant1}"},
        files={"file": ("evidence1.log", io.BytesIO(b"incident 1 logs"), "text/plain")},
    )
    evidence_id = upload_res.json()["id"]

    # Tenant 2 attempts to download Tenant 1's evidence
    download_res = client.get(
        f"/api/v1/incidents/{incident_t1['id']}/evidence/{evidence_id}/download",
        headers={"Authorization": f"Bearer {token_tenant2}"},
    )
    assert download_res.status_code == 404
    assert download_res.json()["detail"] == "Incident not found"


# 15. RBAC: SECURITY_VIEWER cannot upload evidence (403 Forbidden)
def test_rbac_security_viewer_cannot_upload_evidence(client: TestClient):
    admin_token = register_org(client, "Org N", "org-n", "admin-n@example.com")
    viewer_token = create_user_in_org(client, admin_token, "Viewer User", "viewer-n@example.com", UserRole.SECURITY_VIEWER.value)

    incident = create_sample_incident(client, admin_token)

    response = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {viewer_token}"},
        files={"file": ("view_evidence.log", io.BytesIO(b"log data"), "text/plain")},
    )
    assert response.status_code == 403
    assert "not permitted to upload evidence" in response.json()["detail"]


# 16. RBAC: SECURITY_VIEWER can list and download evidence
def test_rbac_security_viewer_can_list_and_download_evidence(client: TestClient):
    admin_token = register_org(client, "Org O", "org-o", "admin-o@example.com")
    viewer_token = create_user_in_org(client, admin_token, "Viewer User", "viewer-o@example.com", UserRole.SECURITY_VIEWER.value)

    incident = create_sample_incident(client, admin_token)
    file_bytes = b"Incident evidence verified for viewers"
    upload_res = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("security_report.txt", io.BytesIO(file_bytes), "text/plain")},
    )
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["id"]

    # Viewer lists evidence
    list_res = client.get(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1
    assert list_res.json()[0]["filename"] == "security_report.txt"

    # Viewer downloads evidence
    download_res = client.get(
        f"/api/v1/incidents/{incident['id']}/evidence/{evidence_id}/download",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert download_res.status_code == 200
    assert download_res.content == file_bytes


# 17. RBAC: SECURITY_ANALYST can upload, list, and download evidence
def test_rbac_security_analyst_can_upload_and_download_evidence(client: TestClient):
    admin_token = register_org(client, "Org P", "org-p", "admin-p@example.com")
    analyst_token = create_user_in_org(client, admin_token, "Analyst User", "analyst-p@example.com", UserRole.SECURITY_ANALYST.value)

    incident = create_sample_incident(client, admin_token)
    file_bytes = b"Log analysis created by analyst"

    # Analyst uploads
    upload_res = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {analyst_token}"},
        files={"file": ("analyst_findings.txt", io.BytesIO(file_bytes), "text/plain")},
    )
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["id"]

    # Analyst downloads
    download_res = client.get(
        f"/api/v1/incidents/{incident['id']}/evidence/{evidence_id}/download",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert download_res.status_code == 200
    assert download_res.content == file_bytes


# 18. Download endpoint includes nosniff and attachment headers
def test_download_headers_prevent_mime_sniffing(client: TestClient):
    token = register_org(client, "Org Q", "org-q", "admin-q@example.com")
    incident = create_sample_incident(client, token)

    content = b"sample network audit data\n"
    upload_res = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("audit.log", io.BytesIO(content), "text/plain")},
    )
    evidence_id = upload_res.json()["id"]

    res = client.get(
        f"/api/v1/incidents/{incident['id']}/evidence/{evidence_id}/download",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert 'attachment; filename="audit.log"' in res.headers.get("content-disposition", "")
    assert res.content == content


# 19. Incident detail endpoint includes populated evidence collection
def test_incident_detail_includes_evidence_collection(client: TestClient):
    token = register_org(client, "Org R", "org-r", "admin-r@example.com")
    incident = create_sample_incident(client, token)

    content = b"incident timeline exported"
    client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("timeline.txt", io.BytesIO(content), "text/plain")},
        data={"description": "Timeline log"},
    )

    detail_res = client.get(
        f"/api/v1/incidents/{incident['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert detail_res.status_code == 200
    data = detail_res.json()
    assert "evidence" in data
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["filename"] == "timeline.txt"
    assert data["evidence"][0]["description"] == "Timeline log"


# 20. Unauthenticated access rejected with 401
def test_unauthenticated_evidence_access_rejected(client: TestClient):
    token = register_org(client, "Org S", "org-s", "admin-s@example.com")
    incident = create_sample_incident(client, token)

    # Missing token for list
    list_res = client.get(f"/api/v1/incidents/{incident['id']}/evidence")
    assert list_res.status_code == 401

    # Missing token for upload
    upload_res = client.post(
        f"/api/v1/incidents/{incident['id']}/evidence",
        files={"file": ("test.log", io.BytesIO(b"data"), "text/plain")},
    )
    assert upload_res.status_code == 401

    # Missing token for download
    download_res = client.get(f"/api/v1/incidents/{incident['id']}/evidence/{uuid4()}/download")
    assert download_res.status_code == 401


# 21. Non-existent incident or evidence ID returns 404
def test_nonexistent_evidence_returns_404(client: TestClient):
    token = register_org(client, "Org T", "org-t", "admin-t@example.com")
    incident = create_sample_incident(client, token)

    fake_id = uuid4()
    # Non-existent incident
    res = client.get(f"/api/v1/incidents/{fake_id}/evidence", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 404

    # Non-existent evidence ID
    res_evidence = client.get(
        f"/api/v1/incidents/{incident['id']}/evidence/{fake_id}/download",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_evidence.status_code == 404

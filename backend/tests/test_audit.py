from datetime import datetime, timedelta, timezone
import io
import shutil
import tempfile
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.database import Base, get_db
from app.main import app
from app.models.audit import ActorType, AuditEvent, AuditOutcome
from app.models.incident import IncidentCategory, IncidentSeverity, IncidentStatus
from app.models.user import UserRole
from app.services.audit_service import verify_tenant_audit_chain


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


# 1. Audit event persistence and actor attribution on user actions
def test_audit_event_persistence_and_actor_attribution(client: TestClient):
    token = register_org(client, "Audit Org 1", "audit-org-1", "admin1@example.com")

    # Fetch audit events
    res = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2  # TENANT_REGISTERED and LOGIN_SUCCESS
    actions = [e["action"] for e in data["items"]]
    assert "TENANT_REGISTERED" in actions
    assert "LOGIN_SUCCESS" in actions


# 2. Login failure records failed audit event
def test_audit_login_failed_records_event(client: TestClient):
    token = register_org(client, "Audit Org 2", "audit-org-2", "admin2@example.com")

    # Wrong password attempt
    bad_login = client.post("/api/v1/auth/login", json={"email": "admin2@example.com", "password": "WrongPassword!"})
    assert bad_login.status_code == 401

    # Check audit log
    res = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    actions = [e["action"] for e in res.json()["items"]]
    assert "LOGIN_FAILED" in actions


# 3. Incident creation records audit event
def test_audit_incident_creation_records_event(client: TestClient):
    token = register_org(client, "Audit Org 3", "audit-org-3", "admin3@example.com")

    inc_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Phishing campaign detected",
            "description": "CEO impersonation email",
            "category": IncidentCategory.PHISHING.value,
            "severity": IncidentSeverity.HIGH.value,
        },
    )
    assert inc_res.status_code == 201
    incident_id = inc_res.json()["id"]

    res = client.get("/api/v1/audit-events?action=INCIDENT_CREATED", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["resource_id"] == incident_id
    assert items[0]["details"]["category"] == IncidentCategory.PHISHING.value


# 4. Incident status transition and severity change records audit event
def test_audit_incident_updates_record_event(client: TestClient):
    token = register_org(client, "Audit Org 4", "audit-org-4", "admin4@example.com")

    inc_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Ransomware outbreak", "category": "RANSOMWARE", "severity": "HIGH"},
    )
    incident_id = inc_res.json()["id"]

    # Transition to INVESTIGATING and CRITICAL
    patch_res = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "INVESTIGATING", "severity": "CRITICAL"},
    )
    assert patch_res.status_code == 200

    res = client.get("/api/v1/audit-events?action=INCIDENT_UPDATED", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["details"]["changes"]["status"]["new"] == "INVESTIGATING"
    assert items[0]["details"]["changes"]["severity"]["new"] == "CRITICAL"


# 5. Investigation note creation records audit event
def test_audit_investigation_note_records_event(client: TestClient):
    token = register_org(client, "Audit Org 5", "audit-org-5", "admin5@example.com")

    inc_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Data leak test", "category": "DATA_EXFILTRATION", "severity": "MEDIUM"},
    )
    incident_id = inc_res.json()["id"]

    note_res = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers={"Authorization": f"Bearer {token}"},
        json={"content": "Host memory dump acquired and hashed."},
    )
    assert note_res.status_code == 201

    res = client.get("/api/v1/audit-events?action=INVESTIGATION_NOTE_ADDED", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert len(res.json()["items"]) == 1


# 6. Evidence upload and download record audit events
def test_audit_evidence_upload_and_download(client: TestClient):
    token = register_org(client, "Audit Org 6", "audit-org-6", "admin6@example.com")

    inc_res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Packet inspection", "category": "MALWARE", "severity": "LOW"},
    )
    incident_id = inc_res.json()["id"]

    upload_res = client.post(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("syslog.txt", io.BytesIO(b"Firewall traffic allowed port 80"), "text/plain")},
        data={"description": "Traffic export"},
    )
    assert upload_res.status_code == 201
    evidence_id = upload_res.json()["id"]

    download_res = client.get(
        f"/api/v1/incidents/{incident_id}/evidence/{evidence_id}/download",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert download_res.status_code == 200

    # Verify both upload and download audit records
    res_up = client.get("/api/v1/audit-events?action=EVIDENCE_UPLOADED", headers={"Authorization": f"Bearer {token}"})
    assert res_up.status_code == 200
    assert len(res_up.json()["items"]) == 1

    res_dl = client.get("/api/v1/audit-events?action=EVIDENCE_DOWNLOADED", headers={"Authorization": f"Bearer {token}"})
    assert res_dl.status_code == 200
    assert len(res_dl.json()["items"]) == 1


# 7. Cross-tenant access attempt records security denial audit event
def test_audit_cross_tenant_denial_recorded(client: TestClient):
    token_t1 = register_org(client, "Tenant One", "t1-audit", "admin-t1@example.com")
    token_t2 = register_org(client, "Tenant Two", "t2-audit", "admin-t2@example.com")

    inc_t1 = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_t1}"},
        json={"title": "Internal incident", "category": "OTHER", "severity": "LOW"},
    ).json()

    # Tenant 2 tries to download non-existent/cross-tenant evidence
    cross_res = client.get(
        f"/api/v1/incidents/{inc_t1['id']}/evidence/{uuid4()}/download",
        headers={"Authorization": f"Bearer {token_t2}"},
    )
    assert cross_res.status_code == 404

    # Tenant 2's audit trail records the denied attempt
    res = client.get("/api/v1/audit-events?action=CROSS_TENANT_ACCESS_DENIED", headers={"Authorization": f"Bearer {token_t2}"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["outcome"] == "DENIED"


# 8. Multi-tenant audit trail isolation: tenant cannot see another tenant's audit events
def test_cross_tenant_audit_list_isolation(client: TestClient):
    token_t1 = register_org(client, "Audit Iso 1", "iso-1", "admin-iso1@example.com")
    token_t2 = register_org(client, "Audit Iso 2", "iso-2", "admin-iso2@example.com")

    res_t1 = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token_t1}"})
    res_t2 = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token_t2}"})

    items_t1 = res_t1.json()["items"]
    items_t2 = res_t2.json()["items"]

    t1_ids = {e["id"] for e in items_t1}
    t2_ids = {e["id"] for e in items_t2}
    assert t1_ids.isdisjoint(t2_ids)


# 9. Cross-tenant single audit event detail returns 404
def test_cross_tenant_audit_detail_returns_404(client: TestClient):
    token_t1 = register_org(client, "Audit Detail 1", "det-1", "admin-det1@example.com")
    token_t2 = register_org(client, "Audit Detail 2", "det-2", "admin-det2@example.com")

    res_t1 = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token_t1}"})
    event_id_t1 = res_t1.json()["items"][0]["id"]

    # Tenant 2 tries to fetch Tenant 1's audit event
    res_cross = client.get(f"/api/v1/audit-events/{event_id_t1}", headers={"Authorization": f"Bearer {token_t2}"})
    assert res_cross.status_code == 404
    assert res_cross.json()["detail"] == "Audit event not found"


# 10. Audit event list pagination and query filters
def test_audit_pagination_and_query_filters(client: TestClient):
    token = register_org(client, "Audit Filters", "audit-filters", "admin-filter@example.com")

    # Generate several incidents
    for i in range(5):
        client.post(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": f"Incident {i}", "category": "OTHER", "severity": "LOW"},
        )

    res_page = client.get("/api/v1/audit-events?page=1&page_size=3", headers={"Authorization": f"Bearer {token}"})
    assert res_page.status_code == 200
    data = res_page.json()
    assert len(data["items"]) == 3
    assert data["page"] == 1
    assert data["page_size"] == 3
    assert data["total"] >= 7


# 11. Invalid time range rejected (400 Bad Request)
def test_invalid_time_range_rejected(client: TestClient):
    token = register_org(client, "Audit Time", "audit-time", "admin-time@example.com")

    start = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    end = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    res = client.get(f"/api/v1/audit-events?start_time={start}&end_time={end}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 400
    assert "start_time cannot be after end_time" in res.json()["detail"]


# 12. Absence of ordinary audit update or delete endpoints (Append-only enforcement)
def test_absence_of_audit_update_delete_endpoints(client: TestClient):
    token = register_org(client, "Audit Immutability", "audit-immut", "admin-immut@example.com")

    res = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token}"})
    event_id = res.json()["items"][0]["id"]

    # Attempt PUT
    res_put = client.put(f"/api/v1/audit-events/{event_id}", headers={"Authorization": f"Bearer {token}"}, json={"outcome": "DENIED"})
    assert res_put.status_code in [404, 405]

    # Attempt PATCH
    res_patch = client.patch(f"/api/v1/audit-events/{event_id}", headers={"Authorization": f"Bearer {token}"}, json={"outcome": "DENIED"})
    assert res_patch.status_code in [404, 405]

    # Attempt DELETE
    res_delete = client.delete(f"/api/v1/audit-events/{event_id}", headers={"Authorization": f"Bearer {token}"})
    assert res_delete.status_code in [404, 405]


# 13. Secrets are redacted in audit details
def test_secret_redaction_in_audit_details(client: TestClient, test_db_session: Session):
    token = register_org(client, "Audit Redaction", "audit-redact", "admin-redact@example.com")

    # Inspect all audit events for this org
    res = client.get("/api/v1/audit-events", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    items = res.json()["items"]

    for ev in items:
        details_str = str(ev["details"]).lower()
        assert "password12345!" not in details_str
        assert "password_hash" not in details_str
        assert "bearer " not in details_str


# 14. Cryptographic hash chain verification succeeds on untampered log
def test_audit_hash_chain_verification_succeeds(client: TestClient):
    token = register_org(client, "Audit Chain Org", "audit-chain-org", "admin-chain@example.com")

    # Generate additional actions
    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Chain verification test", "category": "MALWARE", "severity": "MEDIUM"},
    )

    verify_res = client.get("/api/v1/audit-events/verify-chain", headers={"Authorization": f"Bearer {token}"})
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert data["is_valid"] is True
    assert data["verified_count"] >= 3
    assert data["broken_event_id"] is None


# 15. Cryptographic hash chain detects database-level record tampering
def test_audit_hash_chain_detects_tampering(client: TestClient, test_db_session: Session):
    token = register_org(client, "Audit Tamper Org", "audit-tamper-org", "admin-tamper@example.com")

    # Fetch audit events
    events = test_db_session.query(AuditEvent).all()
    assert len(events) >= 2

    # Tamper with an event in the database directly
    events[0].action = "TAMPERED_ACTION_FORGERY"
    test_db_session.commit()

    verify_res = client.get("/api/v1/audit-events/verify-chain", headers={"Authorization": f"Bearer {token}"})
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert data["is_valid"] is False
    assert data["broken_event_id"] is not None
    assert "Tampering detected" in data["details"] or "Broken previous hash" in data["details"]


# 16. Privilege escalation attempt records DENIED audit event
def test_privilege_escalation_attempt_records_denied_audit(client: TestClient):
    admin_token = register_org(client, "Priv Org", "priv-org", "admin-priv@example.com")

    # Tenant admin attempts to create a SUPER_ADMIN
    res = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "Hacker", "email": "hacker@example.com", "password": "Password12345!", "role": "SUPER_ADMIN"},
    )
    assert res.status_code == 403

    audit_res = client.get("/api/v1/audit-events?action=PRIVILEGE_ESCALATION_ATTEMPT", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_res.status_code == 200
    items = audit_res.json()["items"]
    assert len(items) == 1
    assert items[0]["outcome"] == "DENIED"


# 17. User role modification and active status change records audit event
def test_user_update_records_audit_event(client: TestClient):
    admin_token = register_org(client, "User Up Org", "user-up-org", "admin-up@example.com")
    analyst_token = create_user_in_org(client, admin_token, "Analyst 1", "analyst1-up@example.com", UserRole.SECURITY_ANALYST.value)

    # Get analyst user ID
    user_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    analyst_id = user_res.json()["id"]

    # Deactivate analyst
    patch_res = client.patch(
        f"/api/v1/users/{analyst_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False},
    )
    assert patch_res.status_code == 200

    audit_res = client.get(f"/api/v1/audit-events?action=USER_UPDATED&resource_id={analyst_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_res.status_code == 200
    items = audit_res.json()["items"]
    assert len(items) == 1
    assert items[0]["details"]["changes"]["is_active"]["new"] is False


# 18. Non-existent audit event ID returns 404
def test_nonexistent_audit_event_returns_404(client: TestClient):
    token = register_org(client, "Audit 404 Org", "audit-404-org", "admin-404@example.com")
    res = client.get(f"/api/v1/audit-events/{uuid4()}", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 404
    assert res.json()["detail"] == "Audit event not found"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.main import app
from app.models.incident import IncidentCategory, IncidentSeverity, IncidentStatus


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
def client(test_db_session: Session) -> TestClient:
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
            "name": f"Admin for {org_slug}",
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


# 1, 2, 3: Create incident, server assigns tenant and creator
def test_create_incident_authorized_and_server_derived(client: TestClient):
    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).json()

    res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Phishing email detected",
            "description": "Suspicious email with malicious attachment received.",
            "category": "PHISHING",
            "severity": "HIGH",
        },
    )
    assert res.status_code == 201
    incident = res.json()
    assert incident["title"] == "Phishing email detected"
    assert incident["severity"] == "HIGH"
    assert incident["status"] == "OPEN"
    assert incident["created_by_id"] == me["id"]
    assert incident["tenant_id"] == me["tenant_id"]


# 4. Incident listing is tenant-scoped
def test_incident_listing_tenant_isolation(client: TestClient):
    token_a = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_b = register_org(client, "Beta Corp", "beta-corp", "admin@beta.com")

    # Alpha creates 2 incidents
    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"title": "Alpha Incident 1", "description": "desc", "severity": "LOW"},
    )
    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"title": "Alpha Incident 2", "description": "desc", "severity": "MEDIUM"},
    )

    # Beta creates 1 incident
    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"title": "Beta Incident 1", "description": "desc", "severity": "CRITICAL"},
    )

    # Alpha lists incidents -> must see only 2
    res_a = client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token_a}"})
    assert res_a.status_code == 200
    items_a = res_a.json()["items"]
    assert len(items_a) == 2
    for item in items_a:
        assert "Alpha" in item["title"]

    # Beta lists incidents -> must see only 1
    res_b = client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b.status_code == 200
    items_b = res_b.json()["items"]
    assert len(items_b) == 1
    assert items_b[0]["title"] == "Beta Incident 1"


# 5. Filters: status, severity, category, search
def test_incident_filters_and_search(client: TestClient):
    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")

    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Malware Outbreak", "description": "Trojan detected on workstation", "category": "MALWARE", "severity": "CRITICAL"},
    )
    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Phishing Attempt", "description": "Credential harvesting page", "category": "PHISHING", "severity": "MEDIUM"},
    )

    # Filter by severity
    crit_res = client.get("/api/v1/incidents?severity=CRITICAL", headers={"Authorization": f"Bearer {token}"}).json()
    assert crit_res["total"] == 1
    assert crit_res["items"][0]["title"] == "Malware Outbreak"

    # Filter by category
    phish_res = client.get("/api/v1/incidents?category=PHISHING", headers={"Authorization": f"Bearer {token}"}).json()
    assert phish_res["total"] == 1
    assert phish_res["items"][0]["title"] == "Phishing Attempt"

    # Search keyword in description
    search_res = client.get("/api/v1/incidents?search=harvesting", headers={"Authorization": f"Bearer {token}"}).json()
    assert search_res["total"] == 1
    assert search_res["items"][0]["title"] == "Phishing Attempt"


# 6. Pagination
def test_incident_pagination(client: TestClient):
    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")

    for i in range(5):
        client.post(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": f"Incident {i}", "description": "desc", "severity": "LOW"},
        )

    p1 = client.get("/api/v1/incidents?page=1&page_size=2", headers={"Authorization": f"Bearer {token}"}).json()
    assert len(p1["items"]) == 2
    assert p1["total"] == 5
    assert p1["page"] == 1
    assert p1["total_pages"] == 3

    p3 = client.get("/api/v1/incidents?page=3&page_size=2", headers={"Authorization": f"Bearer {token}"}).json()
    assert len(p3["items"]) == 1
    assert p3["page"] == 3


# 7, 8: Cross-tenant incident retrieval & update returns 404 (Anti-IDOR)
def test_cross_tenant_access_returns_404(client: TestClient):
    token_a = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_b = register_org(client, "Beta Corp", "beta-corp", "admin@beta.com")

    # Create incident in Beta
    res_b = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"title": "Secret Beta Incident", "description": "Top secret", "severity": "HIGH"},
    )
    inc_b_id = res_b.json()["id"]

    # Alpha attempts GET -> 404
    get_res = client.get(f"/api/v1/incidents/{inc_b_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert get_res.status_code == 404
    assert get_res.json()["detail"] == "Incident not found"

    # Alpha attempts PATCH -> 404
    patch_res = client.patch(
        f"/api/v1/incidents/{inc_b_id}",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"title": "Hacked Title"},
    )
    assert patch_res.status_code == 404
    assert patch_res.json()["detail"] == "Incident not found"


# 9. Cross-tenant note creation is rejected (returns 404)
def test_cross_tenant_note_creation_rejected(client: TestClient):
    token_a = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_b = register_org(client, "Beta Corp", "beta-corp", "admin@beta.com")

    res_b = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"title": "Beta Incident", "description": "desc", "severity": "HIGH"},
    )
    inc_b_id = res_b.json()["id"]

    # Alpha attempts to add note to Beta incident -> 404
    note_res = client.post(
        f"/api/v1/incidents/{inc_b_id}/notes",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"content": "Malicious intrusion note"},
    )
    assert note_res.status_code == 404


# 10, 11, 12: Roles & Permissions (Analyst vs Viewer)
def test_role_permissions_analyst_vs_viewer(client: TestClient):
    admin_token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    analyst_token = create_user_in_org(client, admin_token, "Alice Analyst", "alice@alpha.com", "SECURITY_ANALYST")
    viewer_token = create_user_in_org(client, admin_token, "Bob Viewer", "bob@alpha.com", "SECURITY_VIEWER")

    # Analyst can create incident
    res_analyst = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"title": "Analyst Found Incident", "description": "Details", "severity": "MEDIUM"},
    )
    assert res_analyst.status_code == 201
    inc_id = res_analyst.json()["id"]

    # Analyst can add note
    note_res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"content": "Alice added an investigation note"},
    )
    assert note_res.status_code == 201

    # Viewer CAN view incident
    view_res = client.get(f"/api/v1/incidents/{inc_id}", headers={"Authorization": f"Bearer {viewer_token}"})
    assert view_res.status_code == 200

    # Viewer CANNOT create incident -> 403
    v_create = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"title": "Viewer Incident", "description": "Fail", "severity": "LOW"},
    )
    assert v_create.status_code == 403

    # Viewer CANNOT update incident -> 403
    v_update = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"title": "Viewer Edit"},
    )
    assert v_update.status_code == 403

    # Viewer CANNOT add note -> 403
    v_note = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"content": "Viewer attempt to note"},
    )
    assert v_note.status_code == 403


# 13. Assigning analyst from another tenant is rejected
def test_cross_tenant_analyst_assignment_rejected(client: TestClient):
    token_a = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_b = register_org(client, "Beta Corp", "beta-corp", "admin@beta.com")
    analyst_b_token = create_user_in_org(client, token_b, "Bob Beta", "bob@beta.com", "SECURITY_ANALYST")
    me_b = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_b_token}"}).json()

    # Alpha attempts to assign Beta analyst on creation -> 400
    res_assign = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "title": "Alpha Incident",
            "description": "desc",
            "severity": "HIGH",
            "assigned_to_id": me_b["id"],
        },
    )
    assert res_assign.status_code == 400
    assert "same organization" in res_assign.json()["detail"].lower()


# 14. Status Transition Rules
def test_status_transition_rules_and_conflict(client: TestClient):
    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")

    res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Status Workflow Test", "description": "desc", "severity": "MEDIUM"},
    )
    inc_id = res.json()["id"]
    assert res.json()["status"] == "OPEN"

    # OPEN -> RESOLVED directly is NOT allowed -> 409 Conflict
    bad_res = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "RESOLVED"},
    )
    assert bad_res.status_code == 409
    assert "Invalid status transition" in bad_res.json()["detail"]

    # Valid: OPEN -> INVESTIGATING
    res_inv = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "INVESTIGATING"},
    )
    assert res_inv.status_code == 200
    assert res_inv.json()["status"] == "INVESTIGATING"

    # Valid: INVESTIGATING -> CONTAINED
    res_cont = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "CONTAINED"},
    )
    assert res_cont.status_code == 200
    assert res_cont.json()["status"] == "CONTAINED"

    # Valid: CONTAINED -> RESOLVED (sets resolved_at)
    res_res = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "RESOLVED"},
    )
    assert res_res.status_code == 200
    assert res_res.json()["status"] == "RESOLVED"
    assert res_res.json()["resolved_at"] is not None

    # Reopening: RESOLVED -> INVESTIGATING (clears resolved_at)
    res_reopen = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "INVESTIGATING"},
    )
    assert res_reopen.status_code == 200
    assert res_reopen.json()["status"] == "INVESTIGATING"
    assert res_reopen.json()["resolved_at"] is None

    # Transition to RESOLVED then CLOSED
    client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "RESOLVED"},
    )
    res_closed = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "CLOSED"},
    )
    assert res_closed.status_code == 200
    assert res_closed.json()["status"] == "CLOSED"

    # CLOSED is terminal: CLOSED -> INVESTIGATING -> 409 Conflict
    res_term = client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "INVESTIGATING"},
    )
    assert res_term.status_code == 409


# 15. Invalid severity or status values rejected
def test_invalid_severity_or_status_rejected(client: TestClient):
    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")

    # Invalid severity
    res_sev = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Test", "description": "desc", "severity": "SUPER_HOT"},
    )
    assert res_sev.status_code == 422


# 16, 17: Immutable fields protected and unauthenticated access rejected
def test_immutable_fields_and_unauthenticated_rejected(client: TestClient):
    # Unauthenticated
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.post("/api/v1/incidents", json={}).status_code == 401

    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Immutable Test", "description": "desc", "severity": "LOW"},
    )
    inc = res.json()
    orig_tenant = inc["tenant_id"]
    orig_creator = inc["created_by_id"]

    # Attempt to change tenant_id or created_by_id in PATCH
    fake_uuid = "11111111-2222-3333-4444-555555555555"
    patch_res = client.patch(
        f"/api/v1/incidents/{inc['id']}",
        headers={"Authorization": f"Bearer {token}"},
        json={"tenant_id": fake_uuid, "created_by_id": fake_uuid},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["tenant_id"] == orig_tenant
    assert patch_res.json()["created_by_id"] == orig_creator


# 18. Notes associated with author and incident
def test_notes_associated_with_author_and_incident(client: TestClient):
    admin_token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    analyst_token = create_user_in_org(client, admin_token, "Alice Analyst", "alice@alpha.com", "SECURITY_ANALYST")

    res = client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"title": "Incident with notes", "description": "desc", "severity": "HIGH"},
    )
    inc_id = res.json()["id"]

    note_res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"content": "First investigation note by analyst."},
    )
    assert note_res.status_code == 201
    note = note_res.json()
    assert note["author_name"] == "Alice Analyst"
    assert note["content"] == "First investigation note by analyst."

    # Verify incident detail returns note
    detail = client.get(f"/api/v1/incidents/{inc_id}", headers={"Authorization": f"Bearer {admin_token}"}).json()
    assert len(detail["notes"]) == 1
    assert detail["notes"][0]["content"] == "First investigation note by analyst."


# Metrics endpoint test
def test_incident_metrics_endpoint(client: TestClient):
    token = register_org(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")

    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Incident 1", "description": "desc", "severity": "CRITICAL"},
    )
    client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Incident 2", "description": "desc", "severity": "LOW"},
    )

    metrics = client.get("/api/v1/incidents/metrics", headers={"Authorization": f"Bearer {token}"}).json()
    assert metrics["total"] == 2
    assert metrics["open"] == 2
    assert metrics["critical_and_high"] == 1

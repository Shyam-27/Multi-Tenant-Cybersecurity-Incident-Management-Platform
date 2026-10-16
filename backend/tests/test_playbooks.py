from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.models.user import UserRole


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


def test_create_and_list_playbooks_tenant_isolation(client: TestClient):
    token_t1 = register_org(client, "Playbook Org 1", "pb-org-1", "admin-pb1@example.com")
    token_t2 = register_org(client, "Playbook Org 2", "pb-org-2", "admin-pb2@example.com")

    # Create Playbook in Tenant 1
    res1 = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {token_t1}"},
        json={
            "name": "Ransomware Host Containment",
            "description": "Isolate host and revoke user tokens",
            "trigger_event": "INCIDENT_CRITICAL",
            "actions": [
                {"action_type": "ISOLATE_ENDPOINT", "hostname": "finance-srv-01"},
                {"action_type": "BLOCK_IP", "ip_address": "198.51.100.99"},
            ],
            "is_enabled": True,
            "is_dry_run": True,
            "requires_approval": True,
        },
    )
    assert res1.status_code == 201
    pb1 = res1.json()
    assert pb1["name"] == "Ransomware Host Containment"
    assert pb1["is_dry_run"] is True

    # Tenant 2 cannot see Tenant 1's playbook
    res2 = client.get("/api/v1/playbooks", headers={"Authorization": f"Bearer {token_t2}"})
    assert res2.status_code == 200
    assert len(res2.json()) == 0

    # Cross tenant detail -> 404
    cross_res = client.get(f"/api/v1/playbooks/{pb1['id']}", headers={"Authorization": f"Bearer {token_t2}"})
    assert cross_res.status_code == 404


def test_playbook_rbac_viewer_cannot_create_or_execute(client: TestClient):
    admin_token = register_org(client, "PB RBAC Org", "pb-rbac-org", "admin-pbrbac@example.com")
    viewer_token = create_user_in_org(client, admin_token, "Viewer User", "viewer-pb@example.com", UserRole.SECURITY_VIEWER.value)

    res_create = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"name": "Viewer Playbook", "actions": [{"action_type": "BLOCK_IP"}]},
    )
    assert res_create.status_code == 403

    # Admin creates playbook
    res_admin = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Admin Playbook",
            "actions": [{"action_type": "BLOCK_IP", "ip_address": "203.0.113.11"}],
        },
    )
    pb_id = res_admin.json()["id"]

    # Viewer cannot execute -> 403
    res_exec = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res_exec.status_code == 403


def test_playbook_dry_run_execution(client: TestClient):
    token = register_org(client, "DryRun Org", "dryrun-org", "admin-dry@example.com")

    # Create dry-run playbook with simulated IP block and endpoint isolation
    res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Dry Run Triage",
            "actions": [
                {"action_type": "ISOLATE_ENDPOINT"},
                {"action_type": "BLOCK_IP"},
            ],
            "is_dry_run": True,
            "requires_approval": False,
        },
    )
    pb_id = res.json()["id"]

    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "parameters": {
                "hostname": "workstation-101.corp",
                "ip_address": "198.51.100.44",
            }
        },
    )
    assert exec_res.status_code == 200
    data = exec_res.json()
    assert data["status"] == "COMPLETED"
    assert data["is_dry_run"] is True
    step_results = data["step_results"]
    assert len(step_results) == 2
    assert step_results[0]["status"] == "SIMULATED_SUCCESS"
    assert "workstation-101.corp" in step_results[0]["details"]
    assert step_results[1]["status"] == "SIMULATED_SUCCESS"
    assert "198.51.100.44" in step_results[1]["details"]


def test_playbook_action_revoke_user_sessions(client: TestClient):
    admin_token = register_org(client, "Revoke Org", "revoke-org", "admin-rev@example.com")
    analyst_token = create_user_in_org(client, admin_token, "Compromised Analyst", "bad-analyst@example.com", UserRole.SECURITY_ANALYST.value)

    # Get analyst user ID
    user_info = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).json()
    analyst_id = user_info["id"]

    # Admin creates playbook to revoke user sessions
    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Revoke Compromised Account",
            "actions": [{"action_type": "REVOKE_USER_SESSIONS"}],
            "is_dry_run": False,
            "requires_approval": False,
        },
    )
    pb_id = pb_res.json()["id"]

    # Execute playbook targeting analyst
    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"parameters": {"target_user_id": analyst_id}},
    )
    assert exec_res.status_code == 200
    data = exec_res.json()
    assert data["status"] == "COMPLETED"
    assert data["step_results"][0]["status"] == "SUCCESS"
    assert "bad-analyst@example.com" in data["step_results"][0]["details"]


def test_playbook_action_analyst_cannot_revoke_admin(client: TestClient):
    admin_token = register_org(client, "AntiEsc Org", "antiesc-org", "admin-esc@example.com")
    analyst_token = create_user_in_org(client, admin_token, "Analyst Esc", "analyst-esc@example.com", UserRole.SECURITY_ANALYST.value)

    admin_info = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"}).json()
    admin_id = admin_info["id"]

    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Session Revocation Playbook",
            "actions": [{"action_type": "REVOKE_USER_SESSIONS"}],
            "is_dry_run": False,
            "requires_approval": False,
        },
    )
    pb_id = pb_res.json()["id"]

    # Analyst tries to execute and revoke administrator
    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"parameters": {"target_user_id": admin_id}},
    )
    assert exec_res.status_code == 200
    data = exec_res.json()
    assert data["status"] == "FAILED"
    assert "Privilege violation" in data["step_results"][0]["details"]


def test_playbook_safety_prevents_blocking_loopback(client: TestClient):
    token = register_org(client, "Safety Org", "safety-org", "admin-safe@example.com")

    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Firewall Block",
            "actions": [{"action_type": "BLOCK_IP"}],
            "is_dry_run": True,
            "requires_approval": False,
        },
    )
    pb_id = pb_res.json()["id"]

    # Try to block loopback 127.0.0.1
    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {token}"},
        json={"parameters": {"ip_address": "127.0.0.1"}},
    )
    assert exec_res.status_code == 200
    data = exec_res.json()
    assert data["status"] == "FAILED"
    assert "Safety constraint violation" in data["step_results"][0]["details"]


def test_playbook_approval_workflow_and_anti_self_approval(client: TestClient):
    admin1_token = register_org(client, "Approval Org", "appr-org", "admin1-appr@example.com")
    admin2_token = create_user_in_org(client, admin1_token, "Admin Two", "admin2-appr@example.com", UserRole.TENANT_ADMIN.value)

    # Create high-impact playbook requiring approval
    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={
            "name": "Live Critical Containment",
            "actions": [
                {"action_type": "BLOCK_IP", "ip_address": "198.51.100.9"},
                {"action_type": "ISOLATE_ENDPOINT", "hostname": "dc-01.corp"},
            ],
            "is_dry_run": False,
            "requires_approval": True,
        },
    )
    pb_id = pb_res.json()["id"]

    # Admin 1 triggers execution
    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {admin1_token}"},
    )
    assert exec_res.status_code == 200
    exec_id = exec_res.json()["id"]
    assert exec_res.json()["status"] == "PENDING_APPROVAL"

    # Admin 1 attempts self-approval -> 400 rejection (anti-self-approval)
    self_appr = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={"notes": "I approve my own execution"},
    )
    assert self_appr.status_code == 400
    assert "Anti-self-approval policy violation" in self_appr.json()["detail"]

    # Admin 2 approves execution -> 200 SUCCESS
    appr_res = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {admin2_token}"},
        json={"notes": "Corroborated incident telemetry, approved for containment."},
    )
    assert appr_res.status_code == 200
    data = appr_res.json()
    assert data["status"] == "COMPLETED"
    assert data["approval"]["status"] == "APPROVED"
    assert len(data["step_results"]) == 2


def test_playbook_approval_rejection(client: TestClient):
    admin1_token = register_org(client, "Reject Org", "reject-org", "admin1-rej@example.com")
    admin2_token = create_user_in_org(client, admin1_token, "Admin Two", "admin2-rej@example.com", UserRole.TENANT_ADMIN.value)

    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin1_token}"},
        json={
            "name": "Disruptive Host Shutdown",
            "actions": [{"action_type": "ISOLATE_ENDPOINT", "hostname": "prod-db-01"}],
            "is_dry_run": False,
            "requires_approval": True,
        },
    )
    pb_id = pb_res.json()["id"]

    exec_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {admin1_token}"},
    )
    exec_id = exec_res.json()["id"]

    # Admin 2 rejects
    rej_res = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/reject",
        headers={"Authorization": f"Bearer {admin2_token}"},
        json={"notes": "False alarm; routine database maintenance."},
    )
    assert rej_res.status_code == 200
    data = rej_res.json()
    assert data["status"] == "REJECTED"
    assert data["approval"]["status"] == "REJECTED"
    assert "False alarm" in data["approval"]["decision_notes"]

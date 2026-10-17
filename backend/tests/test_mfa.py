from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pyotp
import pytest
from fastapi.testclient import TestClient

from app.core.security import decode_access_token
from app.models.user import User, UserRole


def register_user(client: TestClient, email: str = "mfa_admin@example.com", slug: str = "mfa-org") -> tuple[str, dict]:
    res = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "MFA Security Corp",
            "organization_slug": slug,
            "name": "MFA Admin",
            "email": email,
            "password": "Password12345!",
        },
    )
    assert res.status_code == 201
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Password12345!"},
    )
    assert login_res.status_code == 200
    return login_res.json()["access_token"], login_res.json()


def create_user(client: TestClient, admin_token: str, name: str, email: str, role: str) -> str:
    res = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": name, "email": email, "password": "Password12345!", "role": role},
    )
    assert res.status_code == 201
    login_res = client.post("/api/v1/auth/login", json={"email": email, "password": "Password12345!"})
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def test_mfa_enrollment_lifecycle(client: TestClient):
    token, _ = register_user(client, "alice_enroll@example.com", "mfa-org-1")

    # Status before enrollment
    status_res = client.get("/api/v1/auth/mfa/status", headers={"Authorization": f"Bearer {token}"})
    assert status_res.status_code == 200
    assert status_res.json()["mfa_enabled"] is False
    assert status_res.json()["recovery_codes_remaining"] == 0

    # Start enrollment
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
    assert enroll_res.status_code == 200
    enroll_data = enroll_res.json()
    assert "secret" in enroll_data
    assert "otpauth://" in enroll_data["provisioning_uri"]
    assert "<svg" in (enroll_data.get("qr_code_svg") or enroll_data.get("qr_code"))
    assert len(enroll_data["recovery_codes"]) == 10

    # Status is still False until confirmed
    status_res2 = client.get("/api/v1/auth/mfa/status", headers={"Authorization": f"Bearer {token}"})
    assert status_res2.json()["mfa_enabled"] is False

    # Confirmation with invalid code fails
    confirm_bad = client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {token}"},
        json={"totp_code": "000000"},
    )
    assert confirm_bad.status_code == 400
    assert "invalid" in confirm_bad.json()["detail"].lower()

    # Confirmation with valid code succeeds
    totp = pyotp.TOTP(enroll_data["secret"])
    valid_code = totp.now()
    confirm_ok = client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {token}"},
        json={"totp_code": valid_code},
    )
    assert confirm_ok.status_code == 200

    # Status is now enabled with 10 recovery codes
    status_res3 = client.get("/api/v1/auth/mfa/status", headers={"Authorization": f"Bearer {token}"})
    assert status_res3.json()["mfa_enabled"] is True
    assert status_res3.json()["recovery_codes_remaining"] == 10


def test_two_stage_login_and_token_isolation(client: TestClient):
    token, _ = register_user(client, "bob_login@example.com", "mfa-org-2")

    # Enroll Bob
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
    secret = enroll_res.json()["secret"]
    recovery_code = enroll_res.json()["recovery_codes"][0]
    client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {token}"},
        json={"totp_code": pyotp.TOTP(secret).now()},
    )

    # Bob logs in: must receive MFA challenge, not access token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "bob_login@example.com", "password": "Password12345!"},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["mfa_required"] is True
    assert login_data.get("access_token") is None
    mfa_challenge_token = login_data["mfa_token"]
    assert mfa_challenge_token is not None

    # Challenge token CANNOT access ordinary API endpoints
    me_attempt = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mfa_challenge_token}"})
    assert me_attempt.status_code == 401

    # Verify login with invalid TOTP fails
    verify_bad = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": mfa_challenge_token, "totp_code": "999999"},
    )
    assert verify_bad.status_code in (400, 401)

    # Verify login with single-use recovery code succeeds
    verify_rc = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": mfa_challenge_token, "recovery_code": recovery_code},
    )
    assert verify_rc.status_code == 200
    session_token = verify_rc.json()["access_token"]
    assert session_token is not None

    # Session token CAN access ordinary API endpoints
    me_ok = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {session_token}"})
    assert me_ok.status_code == 200
    assert me_ok.json()["email"] == "bob_login@example.com"

    # Status shows recovery code was consumed (remaining: 9)
    status_res = client.get("/api/v1/auth/mfa/status", headers={"Authorization": f"Bearer {session_token}"})
    assert status_res.json()["recovery_codes_remaining"] == 9

    # Reusing the consumed recovery code fails
    login_res2 = client.post(
        "/api/v1/auth/login",
        json={"email": "bob_login@example.com", "password": "Password12345!"},
    )
    mfa_challenge2 = login_res2.json()["mfa_token"]
    reused_rc = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": mfa_challenge2, "recovery_code": recovery_code},
    )
    assert reused_rc.status_code in (400, 401)


def test_anti_replay_totp_rejection(client: TestClient):
    token, _ = register_user(client, "replay_user@example.com", "mfa-org-3")
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
    secret = enroll_res.json()["secret"]
    totp = pyotp.TOTP(secret)

    client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {token}"},
        json={"totp_code": totp.now()},
    )

    # First login with code in current timestep
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "replay_user@example.com", "password": "Password12345!"},
    )
    code = totp.now()
    verify_res1 = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": login_res.json()["mfa_token"], "totp_code": code},
    )
    assert verify_res1.status_code == 200

    # Replay attack: attempt to use the exact same code again within the same 30s timestep
    login_res2 = client.post(
        "/api/v1/auth/login",
        json={"email": "replay_user@example.com", "password": "Password12345!"},
    )
    verify_res2 = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": login_res2.json()["mfa_token"], "totp_code": code},
    )
    assert verify_res2.status_code in (400, 401)


def test_mfa_lockout_rate_limiting(client: TestClient):
    token, _ = register_user(client, "lockout_user@example.com", "mfa-org-4")
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
    secret = enroll_res.json()["secret"]
    client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {token}"},
        json={"totp_code": pyotp.TOTP(secret).now()},
    )

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "lockout_user@example.com", "password": "Password12345!"},
    )
    challenge_token = login_res.json()["mfa_token"]

    # 5 consecutive failed attempts
    for _ in range(5):
        fail_res = client.post(
            "/api/v1/auth/mfa/verify-login",
            json={"mfa_token": challenge_token, "totp_code": "111111"},
        )
        assert fail_res.status_code in (400, 401, 429)

    # 6th attempt triggers 429 Too Many Requests (Lockout)
    lockout_res = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": challenge_token, "totp_code": "111111"},
    )
    assert lockout_res.status_code == 429
    assert "locked" in lockout_res.json()["detail"].lower()


def test_disable_mfa_and_regenerate_recovery_codes(client: TestClient):
    token, _ = register_user(client, "manage_user@example.com", "mfa-org-5")
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {token}"})
    secret = enroll_res.json()["secret"]
    old_codes = enroll_res.json()["recovery_codes"]
    totp = pyotp.TOTP(secret)

    client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {token}"},
        json={"totp_code": totp.now()},
    )

    # Regenerate recovery codes with valid password and TOTP
    regen_res = client.post(
        "/api/v1/auth/mfa/recovery-codes/regenerate",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "Password12345!", "totp_code": totp.now()},
    )
    assert regen_res.status_code == 200
    new_codes = regen_res.json()["recovery_codes"]
    assert len(new_codes) == 10
    assert set(new_codes) != set(old_codes)

    # Old recovery code should now fail
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "manage_user@example.com", "password": "Password12345!"},
    )
    old_fail = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": login_res.json()["mfa_token"], "recovery_code": old_codes[0]},
    )
    assert old_fail.status_code in (400, 401)

    # Disable MFA requires valid password and fresh TOTP (+30s window offset)
    next_code = totp.at(datetime.now(timezone.utc) + timedelta(seconds=30))
    disable_bad = client.post(
        "/api/v1/auth/mfa/disable",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "WrongPassword!", "totp_code": next_code},
    )
    assert disable_bad.status_code == 401

    disable_ok = client.post(
        "/api/v1/auth/mfa/disable",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": "Password12345!", "totp_code": next_code},
    )
    assert disable_ok.status_code == 200

    # Login now immediately returns access_token (mfa_required=False)
    login_after = client.post(
        "/api/v1/auth/login",
        json={"email": "manage_user@example.com", "password": "Password12345!"},
    )
    assert login_after.status_code == 200
    assert login_after.json()["mfa_required"] is False
    assert login_after.json()["access_token"] is not None


def test_step_up_mfa_live_playbook_execution(client: TestClient):
    admin_token, _ = register_user(client, "admin_stepup@example.com", "mfa-org-6")
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {admin_token}"})
    secret = enroll_res.json()["secret"]
    totp = pyotp.TOTP(secret)

    client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"totp_code": totp.now()},
    )

    # Create a disruptive playbook that does not require approval
    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Live IP Block",
            "description": "Block IP immediately",
            "trigger_event": "MANUAL",
            "actions": [{"action_type": "BLOCK_IP", "ip_address": "198.51.100.1"}],
            "is_enabled": True,
            "is_dry_run": False,
            "requires_approval": False,
        },
    )
    assert pb_res.status_code == 201
    pb_id = pb_res.json()["id"]

    # 1. Live execution without Step-Up credentials fails with 403 Forbidden
    no_step_up = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"override_dry_run": False},
    )
    assert no_step_up.status_code == 403
    assert "step-up" in no_step_up.json()["detail"].lower() or "mfa" in no_step_up.json()["detail"].lower()

    # 2. Live execution with fresh TOTP code succeeds
    fresh_code = totp.now()
    step_up_ok = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {admin_token}", "X-MFA-Code": fresh_code},
        json={"override_dry_run": False},
    )
    assert step_up_ok.status_code == 200
    exec_data = step_up_ok.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["step_up_method"] == "TOTP"
    assert exec_data["step_up_verified_at"] is not None


def test_step_up_mfa_playbook_approval_and_token_exchange(client: TestClient):
    admin_token, _ = register_user(client, "admin_approver@example.com", "mfa-org-7")
    analyst_token = create_user(client, admin_token, "Analyst Requester", "analyst_req@example.com", UserRole.SECURITY_ANALYST.value)

    # Admin enrolls in MFA
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {admin_token}"})
    secret = enroll_res.json()["secret"]
    totp = pyotp.TOTP(secret)
    client.post(
        "/api/v1/auth/mfa/confirm-enroll",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"totp_code": totp.now()},
    )

    # Create a playbook that requires approval for live run
    pb_res = client.post(
        "/api/v1/playbooks",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Live Host Isolation",
            "description": "Isolate host with approval",
            "trigger_event": "MANUAL",
            "actions": [{"action_type": "ISOLATE_ENDPOINT", "hostname": "dc-srv-01"}],
            "is_enabled": True,
            "is_dry_run": False,
            "requires_approval": True,
        },
    )
    assert pb_res.status_code == 201
    pb_id = pb_res.json()["id"]

    # Analyst triggers execution (creates PENDING_APPROVAL)
    trig_res = client.post(
        f"/api/v1/playbooks/{pb_id}/execute",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"override_dry_run": False},
    )
    assert trig_res.status_code == 200
    exec_id = trig_res.json()["id"]
    assert trig_res.json()["status"] == "PENDING_APPROVAL"

    # 1. Admin attempts to approve without step-up MFA -> 403 Forbidden
    no_step_up_approve = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"notes": "Approving without step-up"},
    )
    assert no_step_up_approve.status_code == 403

    # 2. Admin exchanges TOTP for a Step-Up Token bound to this execution
    step_up_res = client.post(
        "/api/v1/auth/mfa/step-up",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "action": "playbook_approval",
            "target_id": exec_id,
            "totp_code": totp.now(),
        },
    )
    assert step_up_res.status_code == 200
    step_up_token = step_up_res.json()["step_up_token"]

    # 3. Approve with Step-Up Token succeeds
    approved_res = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}", "X-Step-Up-Token": step_up_token},
        json={"notes": "Approved with verified step-up token"},
    )
    assert approved_res.status_code == 200
    approved_data = approved_res.json()
    assert approved_data["status"] == "COMPLETED"
    assert approved_data["step_up_method"] == "STEP_UP_TOKEN"
    assert approved_data["step_up_verified_at"] is not None

    # 4. Attempting to replay the consumed Step-Up Token fails
    replay_token = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}", "X-Step-Up-Token": step_up_token},
        json={"notes": "Replay attempt"},
    )
    assert replay_token.status_code in (400, 403)

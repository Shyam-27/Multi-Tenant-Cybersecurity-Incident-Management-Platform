from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.database import Base, get_db
from app.main import app
from app.models.tenant import Tenant
from app.models.user import User, UserRole


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


def register_tenant(client: TestClient, org_name: str, org_slug: str, email: str, password: str = "Password12345!"):
    res = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": org_name,
            "organization_slug": org_slug,
            "name": f"Admin for {org_slug}",
            "email": email,
            "password": password,
        },
    )
    assert res.status_code == 201
    return res.json()


def login_user(client: TestClient, email: str, password: str = "Password12345!"):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"]


# 1. Health endpoint test
def test_health_endpoints_return_ok(client: TestClient):
    res_root = client.get("/health")
    assert res_root.status_code == 200
    assert res_root.json() == {"status": "ok", "database": "ok"}

    res_v1 = client.get("/api/v1/health")
    assert res_v1.status_code == 200
    assert res_v1.json() == {"status": "ok", "database": "ok"}


# 2. Database connectivity
def test_database_connectivity_probed(client: TestClient):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["database"] == "ok"


# 3. Successful login
def test_successful_login_returns_jwt(client: TestClient):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token = login_user(client, "admin@alpha.com")
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # Valid JWT format


# 4. Invalid login (timing safe, generic error)
def test_invalid_login_wrong_password_or_unknown_user(client: TestClient):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")

    # Wrong password
    res1 = client.post("/api/v1/auth/login", json={"email": "admin@alpha.com", "password": "WrongPassword99!"})
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Invalid email or password"

    # Non-existent user
    res2 = client.post("/api/v1/auth/login", json={"email": "unknown@alpha.com", "password": "WrongPassword99!"})
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Invalid email or password"


# 5. Passwords stored as hashes
def test_passwords_stored_as_argon2_hashes(client: TestClient, test_db_session: Session):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com", password="SecurePassword123!")
    user = test_db_session.scalar(select(User).where(User.email == "admin@alpha.com"))
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert "SecurePassword123!" not in user.password_hash


# 6. Access to protected endpoints without a token
def test_protected_endpoints_require_token(client: TestClient):
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/tenants/me").status_code == 401
    assert client.get("/api/v1/users").status_code == 401
    assert client.post("/api/v1/users", json={}).status_code == 401


# 7. Expired or invalid JWTs, and logout token revocation
def test_invalid_and_expired_jwt_rejected(client: TestClient):
    settings = get_settings()

    # Tampered token
    bad_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad_token}"}).status_code == 401

    # Expired token
    expired_payload = {
        "sub": str(uuid4()),
        "type": "access",
        "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
    }
    expired_token = jwt.encode(expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"}).status_code == 401

    # Revoked token via logout
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token = login_user(client, "admin@alpha.com")
    # Verify works before logout
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    # Perform logout
    assert client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 204
    # Token must now be rejected
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# 8. User role permissions (RBAC)
def test_rbac_analyst_cannot_manage_users(client: TestClient):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    admin_token = login_user(client, "admin@alpha.com")

    # Admin creates an analyst
    res = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Jane Analyst",
            "email": "analyst@alpha.com",
            "password": "Password12345!",
            "role": "SECURITY_ANALYST",
        },
    )
    assert res.status_code == 201

    analyst_token = login_user(client, "analyst@alpha.com")

    # Analyst can view self and tenant
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).status_code == 200
    assert client.get("/api/v1/tenants/me", headers={"Authorization": f"Bearer {analyst_token}"}).status_code == 200

    # Analyst CANNOT list users (requires TENANT_ADMIN or SUPER_ADMIN)
    assert client.get("/api/v1/users", headers={"Authorization": f"Bearer {analyst_token}"}).status_code == 403

    # Analyst CANNOT create users
    assert client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "name": "Eve Impostor",
            "email": "eve@alpha.com",
            "password": "Password12345!",
            "role": "SECURITY_ANALYST",
        },
    ).status_code == 403


# 9. Tenant A attempting to access Tenant B's user
def test_cross_tenant_user_access_returns_404(client: TestClient):
    # Setup Tenant A
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_a = login_user(client, "admin@alpha.com")

    # Setup Tenant B
    register_tenant(client, "Beta Corp", "beta-corp", "admin@beta.com")
    token_b = login_user(client, "admin@beta.com")

    # Create a user in Tenant B
    res_b = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {token_b}"},
        json={
            "name": "Bob Analyst",
            "email": "bob@beta.com",
            "password": "Password12345!",
            "role": "SECURITY_ANALYST",
        },
    )
    assert res_b.status_code == 201
    user_b_id = res_b.json()["id"]

    # Tenant A attempts to access Tenant B's user by ID -> MUST return 404 Not Found (no IDOR)
    res_cross = client.get(f"/api/v1/users/{user_b_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert res_cross.status_code == 404
    assert res_cross.json()["detail"] == "User not found"


# 10. Tenant A attempting to access Tenant B's protected resource
def test_tenant_isolation_on_user_list(client: TestClient):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_a = login_user(client, "admin@alpha.com")

    register_tenant(client, "Beta Corp", "beta-corp", "admin@beta.com")
    token_b = login_user(client, "admin@beta.com")

    # List users for Tenant A: must only see Tenant A's user
    users_a = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token_a}"}).json()
    assert len(users_a) == 1
    assert users_a[0]["email"] == "admin@alpha.com"

    # List users for Tenant B: must only see Tenant B's user
    users_b = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token_b}"}).json()
    assert len(users_b) == 1
    assert users_b[0]["email"] == "admin@beta.com"


# 11. Tenant administrator attempting to elevate their own role
def test_tenant_admin_cannot_elevate_own_role(client: TestClient):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_a = login_user(client, "admin@alpha.com")

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_a}"}).json()
    my_id = me["id"]

    # Attempt self-elevation to SUPER_ADMIN
    res = client.patch(
        f"/api/v1/users/{my_id}",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"role": "SUPER_ADMIN"},
    )
    assert res.status_code == 403
    assert "cannot modify their own role" in res.json()["detail"].lower()


# 12. Tenant administrator attempting to create or modify users in another tenant
def test_tenant_admin_cannot_modify_other_tenant_user_or_grant_super_admin(client: TestClient):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token_a = login_user(client, "admin@alpha.com")

    register_tenant(client, "Beta Corp", "beta-corp", "admin@beta.com")
    token_b = login_user(client, "admin@beta.com")
    me_b = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_b}"}).json()

    # Tenant A attempts to modify Tenant B's user -> 404
    res_mod = client.patch(
        f"/api/v1/users/{me_b['id']}",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"name": "Hacked Name"},
    )
    assert res_mod.status_code == 404

    # Tenant A attempts to create a SUPER_ADMIN user -> 403
    res_create_super = client.post(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "name": "Super Hacker",
            "email": "hacker@alpha.com",
            "password": "Password12345!",
            "role": "SUPER_ADMIN",
        },
    )
    assert res_create_super.status_code == 403
    assert "cannot grant super_admin" in res_create_super.json()["detail"].lower()


# 13. Invalid registration data
def test_invalid_registration_data_rejected(client: TestClient):
    # Password too short (<12 chars)
    res1 = client.post(
        "/api/v1/auth/register",
        json={"organization_name": "Org", "organization_slug": "org", "name": "User", "email": "u@test.com", "password": "Short1!"},
    )
    assert res1.status_code == 422

    # Password without digits
    res2 = client.post(
        "/api/v1/auth/register",
        json={"organization_name": "Org", "organization_slug": "org", "name": "User", "email": "u@test.com", "password": "PasswordWithoutDigits!"},
    )
    assert res2.status_code == 422

    # Invalid slug (uppercase or special characters)
    res3 = client.post(
        "/api/v1/auth/register",
        json={"organization_name": "Org", "organization_slug": "Org_Slug!", "name": "User", "email": "u@test.com", "password": "Password12345!"},
    )
    assert res3.status_code == 422


# 14. Inactive user access
def test_inactive_user_cannot_login_or_authenticate(client: TestClient, test_db_session: Session):
    register_tenant(client, "Alpha Corp", "alpha-corp", "admin@alpha.com")
    token = login_user(client, "admin@alpha.com")

    # Deactivate the user
    user = test_db_session.scalar(select(User).where(User.email == "admin@alpha.com"))
    assert user is not None
    user.is_active = False
    test_db_session.commit()

    # Login fails with 401
    assert client.post("/api/v1/auth/login", json={"email": "admin@alpha.com", "password": "Password12345!"}).status_code == 401

    # Existing token fails with 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

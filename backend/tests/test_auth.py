import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.main import app


@pytest.fixture
def client() -> TestClient:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override_db():
        db: Session = test_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def register(client: TestClient, email: str = "analyst@example.com", slug: str = "cybercorp") -> dict:
    response = client.post("/api/v1/auth/register", json={"organization_name": "CyberCorp", "organization_slug": slug, "name": "Security Analyst", "email": email, "password": "CorrectHorse7"})
    assert response.status_code == 201
    return response.json()


def test_registration_hashes_password_and_does_not_return_it(client: TestClient) -> None:
    user = register(client)
    assert user["email"] == "analyst@example.com"
    assert "password" not in user
    assert "password_hash" not in user


def test_duplicate_registration_is_rejected(client: TestClient) -> None:
    register(client)
    response = client.post("/api/v1/auth/register", json={"organization_name": "CyberCorp", "organization_slug": "cybercorp", "name": "Duplicate", "email": "ANALYST@example.com", "password": "CorrectHorse7"})
    assert response.status_code == 409


def test_login_and_current_user(client: TestClient) -> None:
    register(client)
    login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "CorrectHorse7"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "analyst@example.com"
    assert client.get("/api/v1/tenants/me", headers={"Authorization": f"Bearer {token}"}).json()["slug"] == "cybercorp"


def test_invalid_password_and_missing_token_are_rejected(client: TestClient) -> None:
    register(client)
    login = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "incorrect-password"})
    assert login.status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


def test_change_password_invalidates_the_old_password(client: TestClient) -> None:
    register(client)
    token = client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "CorrectHorse7"}).json()["access_token"]
    response = client.post("/api/v1/auth/change-password", headers={"Authorization": f"Bearer {token}"}, json={"current_password": "CorrectHorse7", "new_password": "EvenBetterPass9"})
    assert response.status_code == 204
    assert client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "CorrectHorse7"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "EvenBetterPass9"}).status_code == 200

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-with-at-least-32-characters"

from app.core.config import get_settings
from app.core.database import Base, get_db
from app.main import app


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
def client(test_db_session: Session) -> TestClient:
    def override_db():
        yield test_db_session

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

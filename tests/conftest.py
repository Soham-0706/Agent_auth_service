import os

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "pytest-secret-key-at-least-32-characters-long"
os.environ["ENV"] = "testing"

import sqlalchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

_original_create_engine = sqlalchemy.create_engine


def _create_engine(url, **kwargs):
    if str(url).startswith("sqlite"):
        return _original_create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return _original_create_engine(url, **kwargs)


sqlalchemy.create_engine = _create_engine

import pytest
from fastapi.testclient import TestClient

from app.core.security import create_access_token, create_refresh_token, hash_password
from app.db.database import Base, get_db, engine
import app.models.user  # noqa: F401 — register User model with Base.metadata

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

from app.main import app  # noqa: E402 — must import after engine is created
from app.models.user import User  # noqa: E402


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db_session):
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db_session):
    user = User(
        email="test@example.com",
        username="testuser",
        hashed_password=hash_password("testpassword123"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return {
        "user": user,
        "access_token": create_access_token(user.username),
        "refresh_token": create_refresh_token(user.username),
        "password": "testpassword123",
    }

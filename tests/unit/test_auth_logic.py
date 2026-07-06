from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.auth import login, refresh_token, register
from app.core.security import create_access_token, create_refresh_token, hash_password
from app.models.user import User
from app.schemas.token import RefreshRequest
from app.schemas.user import UserCreate


def _login_form(username: str, password: str) -> SimpleNamespace:
    return SimpleNamespace(username=username, password=password)


def test_register_creates_user_in_database(db_session):
    user_in = UserCreate(email="new@example.com", username="newuser", password="password123")
    result = register(user_in, db_session)

    assert result.email == "new@example.com"
    assert result.username == "newuser"
    assert result.is_active is True

    stored = db_session.query(User).filter(User.username == "newuser").one()
    assert stored.email == "new@example.com"


def test_register_rejects_duplicate_email(db_session):
    register(
        UserCreate(email="dup@example.com", username="user_one", password="password123"),
        db_session,
    )

    with pytest.raises(HTTPException) as exc_info:
        register(
            UserCreate(email="dup@example.com", username="user_two", password="password123"),
            db_session,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Email or username already registered"


def test_register_rejects_duplicate_username(db_session):
    register(
        UserCreate(email="one@example.com", username="same_name", password="password123"),
        db_session,
    )

    with pytest.raises(HTTPException) as exc_info:
        register(
            UserCreate(email="two@example.com", username="same_name", password="password123"),
            db_session,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Email or username already registered"


def test_login_returns_token_pair_for_valid_credentials(db_session):
    register(
        UserCreate(email="login@example.com", username="loginuser", password="password123"),
        db_session,
    )

    tokens = login(_login_form("loginuser", "password123"), db_session)

    assert tokens.access_token
    assert tokens.refresh_token
    assert tokens.token_type == "bearer"


def test_login_rejects_wrong_password(db_session):
    register(
        UserCreate(email="wrong@example.com", username="wrongpass", password="password123"),
        db_session,
    )

    with pytest.raises(HTTPException) as exc_info:
        login(_login_form("wrongpass", "bad-password"), db_session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Incorrect username or password"


def test_login_rejects_nonexistent_user(db_session):
    with pytest.raises(HTTPException) as exc_info:
        login(_login_form("ghost", "password123"), db_session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Incorrect username or password"


def test_login_rejects_inactive_user(db_session):
    user = User(
        email="inactive@example.com",
        username="inactive",
        hashed_password=hash_password("password123"),
        is_active=False,
    )
    db_session.add(user)
    db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        login(_login_form("inactive", "password123"), db_session)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Inactive user"


def test_refresh_returns_new_token_pair_for_valid_refresh_token(db_session):
    register(
        UserCreate(email="refresh@example.com", username="refreshuser", password="password123"),
        db_session,
    )
    refresh = create_refresh_token("refreshuser")

    tokens = refresh_token(RefreshRequest(refresh_token=refresh), db_session)

    assert tokens.access_token
    assert tokens.refresh_token
    assert tokens.token_type == "bearer"


def test_refresh_rejects_invalid_refresh_token(db_session):
    with pytest.raises(HTTPException) as exc_info:
        refresh_token(RefreshRequest(refresh_token="invalid.token.value"), db_session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid refresh token"


def test_refresh_rejects_access_token_used_as_refresh_token(db_session):
    register(
        UserCreate(email="type@example.com", username="typeuser", password="password123"),
        db_session,
    )
    access = create_access_token("typeuser")

    with pytest.raises(HTTPException) as exc_info:
        refresh_token(RefreshRequest(refresh_token=access), db_session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid refresh token"


def test_refresh_rejects_when_user_no_longer_exists(db_session):
    stale_refresh = create_refresh_token("deleted_user")

    with pytest.raises(HTTPException) as exc_info:
        refresh_token(RefreshRequest(refresh_token=stale_refresh), db_session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "User no longer exists"

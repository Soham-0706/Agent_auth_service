from datetime import timedelta

import pytest

from app.core.security import create_access_token, create_refresh_token, create_token


def _register(client, email, username, password="password123"):
    return client.post(
        "/auth/register",
        json={"email": email, "username": username, "password": password},
    )


def _login(client, username, password="password123"):
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
    )


def test_register_success_returns_201_and_user_payload(client):
    response = _register(client, "alice@example.com", "alice")

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["username"] == "alice"
    assert body["is_active"] is True
    assert "id" in body
    assert "hashed_password" not in body


@pytest.mark.parametrize(
    "email, username",
    [
        ("dup@example.com", "user_two"),
        ("other@example.com", "user_one"),
    ],
)
def test_register_duplicate_email_returns_400(client, email, username):
    _register(client, "dup@example.com", "user_one")

    response = _register(client, email, username)

    assert response.status_code == 400
    assert response.json()["detail"] == "Email or username already registered"


def test_register_duplicate_username_returns_400(client):
    _register(client, "first@example.com", "shared_name")

    response = _register(client, "second@example.com", "shared_name")

    assert response.status_code == 400
    assert response.json()["detail"] == "Email or username already registered"


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "username": "bademail", "password": "password123"},
        {"email": "missing-fields", "username": "incomplete"},
        {"username": "noemail", "password": "password123"},
    ],
)
def test_register_invalid_input_returns_422(client, payload):
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 422


def test_login_success_returns_access_and_refresh_tokens(client):
    _register(client, "login@example.com", "loginuser")

    response = _login(client, "loginuser")

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


def test_login_with_wrong_password_returns_401(client):
    _register(client, "wrong@example.com", "wrongpass")

    response = _login(client, "wrongpass", password="bad-password")

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_login_with_nonexistent_user_returns_401(client):
    response = _login(client, "ghost", password="password123")

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_login_with_inactive_user_returns_403(client, db_session):
    from app.core.security import hash_password
    from app.models.user import User

    user = User(
        email="inactive@example.com",
        username="inactive",
        hashed_password=hash_password("password123"),
        is_active=False,
    )
    db_session.add(user)
    db_session.commit()

    response = _login(client, "inactive")

    assert response.status_code == 403
    assert response.json()["detail"] == "Inactive user"


def test_refresh_with_valid_refresh_token_returns_new_token_pair(client):
    _register(client, "refresh@example.com", "refreshuser")
    login_response = _login(client, "refreshuser")
    refresh_token = login_response.json()["refresh_token"]

    response = client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


def test_refresh_with_invalid_refresh_token_returns_401(client):
    response = client.post("/auth/refresh", json={"refresh_token": "invalid.token.value"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token"


def test_refresh_with_expired_refresh_token_returns_401(client):
    _register(client, "expired@example.com", "expireduser")
    expired = create_token({"sub": "expireduser"}, timedelta(seconds=-1), token_type="refresh")

    response = client.post("/auth/refresh", json={"refresh_token": expired})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token"


def test_refresh_with_access_token_as_refresh_token_returns_401(client):
    _register(client, "type@example.com", "typeuser")
    access_token = create_access_token("typeuser")

    response = client.post("/auth/refresh", json={"refresh_token": access_token})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token"

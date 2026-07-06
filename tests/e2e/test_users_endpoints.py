from datetime import timedelta

from app.core.security import create_access_token, create_token


def test_get_me_with_valid_bearer_token_returns_user(client, test_user):
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {test_user['access_token']}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == test_user["user"].id
    assert body["email"] == test_user["user"].email
    assert body["username"] == test_user["user"].username
    assert body["is_active"] is True


def test_get_me_without_token_returns_401(client):
    response = client.get("/users/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_get_me_with_invalid_token_returns_401(client):
    response = client.get(
        "/users/me",
        headers={"Authorization": "Bearer not.a.valid.jwt"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_get_me_with_expired_token_returns_401(client, test_user):
    expired = create_token(
        {"sub": test_user["user"].username},
        timedelta(seconds=-1),
        token_type="access",
    )

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {expired}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_get_me_with_refresh_token_returns_401(client, test_user):
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {test_user['refresh_token']}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_change_password_with_correct_old_password_returns_204(client, test_user):
    response = client.put(
        "/users/me/password",
        json={"old_password": test_user["password"], "new_password": "brand-new-password"},
        headers={"Authorization": f"Bearer {test_user['access_token']}"},
    )

    assert response.status_code == 204
    assert response.content == b""

    login_response = client.post(
        "/auth/login",
        data={"username": test_user["user"].username, "password": "brand-new-password"},
    )
    assert login_response.status_code == 200


def test_change_password_with_wrong_old_password_returns_400(client, test_user):
    response = client.put(
        "/users/me/password",
        json={"old_password": "wrong-old-password", "new_password": "brand-new-password"},
        headers={"Authorization": f"Bearer {test_user['access_token']}"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Old password is incorrect"


def test_change_password_without_auth_returns_401(client):
    response = client.put(
        "/users/me/password",
        json={"old_password": "old", "new_password": "new"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

from datetime import timedelta

import pytest
from jose import jwt

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    create_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_hash_password_and_verify_password_roundtrip():
    hashed = hash_password("s3cret!")
    assert hashed != "s3cret!"
    assert verify_password("s3cret!", hashed) is True


def test_verify_password_rejects_incorrect_password():
    hashed = hash_password("correct-password")
    assert verify_password("wrong-password", hashed) is False


def test_create_access_token_is_valid_decodable_jwt_with_access_type():
    token = create_access_token("alice")
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    assert payload["sub"] == "alice"
    assert payload["type"] == "access"
    assert "exp" in payload


def test_create_refresh_token_is_valid_decodable_jwt_with_refresh_type():
    token = create_refresh_token("bob")
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    assert payload["sub"] == "bob"
    assert payload["type"] == "refresh"
    assert "exp" in payload


def test_decode_token_returns_none_for_garbage_token():
    assert decode_token("not.a.valid.jwt") is None


def test_decode_token_returns_none_for_tampered_token():
    token = create_access_token("alice")
    tampered = token[:-4] + "xxxx"
    assert decode_token(tampered) is None


def test_decode_token_returns_none_for_expired_token():
    expired = create_token(
        {"sub": "alice"},
        timedelta(seconds=-1),
        token_type="access",
    )
    assert decode_token(expired) is None

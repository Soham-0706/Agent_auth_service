import pytest
from fastapi import HTTPException

from app.api.users import change_password
from app.core.security import hash_password, verify_password
from app.models.user import User
from app.schemas.user import PasswordChange


def test_change_password_succeeds_with_correct_old_password(db_session):
    user = User(
        email="change@example.com",
        username="changeuser",
        hashed_password=hash_password("old-password"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    change_password(
        PasswordChange(old_password="old-password", new_password="new-password"),
        current_user=user,
        db=db_session,
    )

    db_session.refresh(user)
    assert verify_password("new-password", user.hashed_password) is True
    assert verify_password("old-password", user.hashed_password) is False


def test_change_password_rejects_incorrect_old_password(db_session):
    user = User(
        email="reject@example.com",
        username="rejectuser",
        hashed_password=hash_password("correct-old"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    with pytest.raises(HTTPException) as exc_info:
        change_password(
            PasswordChange(old_password="wrong-old", new_password="new-password"),
            current_user=user,
            db=db_session,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Old password is incorrect"

    db_session.refresh(user)
    assert verify_password("correct-old", user.hashed_password) is True


def test_change_password_new_password_verifies_after_update(db_session):
    user = User(
        email="verify@example.com",
        username="verifyuser",
        hashed_password=hash_password("initial"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    change_password(
        PasswordChange(old_password="initial", new_password="updated-secret"),
        current_user=user,
        db=db_session,
    )

    db_session.refresh(user)
    assert verify_password("updated-secret", user.hashed_password) is True

import pytest
import hashlib
from unittest.mock import MagicMock, patch
from auth_system import User, Authenticator, Authorizer
from exceptions import UsernameAlreadyExists, PasswordToShort, InvalidUsername, InvalidPassword, NotLoggedInError, \
    NotPermittedError


# Tests for User class


@pytest.fixture
def user():
    username = 'testuser'
    password = 'secure123'
    return User(username, password)


def test_encrypt_pw(monkeypatch):
    class MockSHA256:
        @staticmethod
        def hexdigest():
            return 'fakehash'

    monkeypatch.setattr(hashlib, 'sha256', lambda *args, **kwargs: MockSHA256())

    user = User('dummy', 'password')
    expected_hash = 'fakehash'
    assert user.password == expected_hash


def test_check_password_correct(user):
    assert user.check_password("secure123")


def test_check_password_incorrect(user):
    assert not user.check_password("wrongpassword")


def test_password_with_special_characters():
    user = User("testuser", "@bcd!123")
    assert user.check_password("@bcd!123")


def test_empty_username_and_password():
    user = User("", "")
    assert user.check_password("")


# Tests for Authenticator class

@pytest.fixture
def authenticator():
    auth = Authenticator()
    auth.add_user("testuser", "secure123")
    return auth


def test_add_user_successfully(authenticator):
    username = "newuser"
    password = "securepass"
    authenticator.add_user(username, password)
    assert username in authenticator.users
    assert authenticator.users[username].password == authenticator.users[username]._encrypt_pw(password)


def test_add_user_username_already_exists(authenticator):
    username = "existinguser"
    password = "securepass"
    authenticator.add_user(username, password)
    with pytest.raises(UsernameAlreadyExists):
        authenticator.add_user(username, password)


def test_add_user_password_too_short(authenticator):
    username = "newuser"
    password = "short"
    with pytest.raises(PasswordToShort):
        authenticator.add_user(username, password)


def test_login_success(authenticator):
    mock_user = MagicMock(spec=User)
    mock_user.check_password.return_value = True
    mock_user.is_logged_in = False
    authenticator.users['testuser'] = mock_user
    authenticator.login("testuser", "secure123")
    assert mock_user.is_logged_in == True, "User should be logged in after correct login credentials"


def test_login_invalid_username(authenticator):
    with pytest.raises(InvalidUsername):
        authenticator.login("nonexistentuser", "password")


def test_login_invalid_password(authenticator):
    with patch('auth_system.User') as MockUser:
        mock_user = MockUser.return_value
        mock_user.check_password.return_value = False

        with pytest.raises(InvalidPassword):
            authenticator.login("testuser", "wrongpassword")


def test_user_logged_in(authenticator):
    authenticator.login("testuser", "secure123")
    assert authenticator.is_logged_in("testuser") == True, "User should be logged in"


def test_user_not_logged_in(authenticator):
    assert authenticator.is_logged_in("testuser") == False, "User should not be logged in"


def test_user_does_not_exist(authenticator):
    assert authenticator.is_logged_in("nonexistentuser") == False, "User should not be logged in"


# Tests for Authorizer class
@pytest.fixture
def authorizer(authenticator):
    return Authorizer(authenticator)


def test_add_permission_success(authorizer):
    authorizer.add_permission("edit")
    assert "edit" in authorizer.permissions, "Permission should be added"


def test_add_permission_exists(authorizer):
    authorizer.add_permission("edit")
    with pytest.raises(PermissionError):
        authorizer.add_permission("edit")


def test_permit_user_success(authorizer):
    authorizer.add_permission("edit")
    authorizer.permit_user("edit", "testuser")
    assert "testuser" in authorizer.permissions["edit"], "User should have permission"


def test_permit_user_no_permission(authorizer):
    with pytest.raises(PermissionError):
        authorizer.permit_user("edit", "testuser")


def test_permit_user_invalid_user(authorizer):
    authorizer.add_permission("edit")
    with pytest.raises(InvalidUsername):
        authorizer.permit_user("edit", "unknownuser")


def test_check_permission_success(authorizer, authenticator):
    authorizer.add_permission("edit")
    authorizer.permit_user("edit", "testuser")
    authenticator.login("testuser", "secure123")
    assert authorizer.check_permission("edit", "testuser") == True, "User should have access"


def test_check_permission_not_logged_in(authorizer, authenticator):
    authorizer.add_permission("edit")
    authorizer.permit_user("edit", "testuser")
    with pytest.raises(NotLoggedInError):
        authorizer.check_permission("edit", "testuser")


def test_check_permission_no_permission(authorizer, authenticator):
    authorizer.add_permission("edit")
    authenticator.login("testuser", "secure123")
    with pytest.raises(NotPermittedError):
        authorizer.check_permission("edit", "testuser")


def test_check_permission_no_exist_permission(authorizer, authenticator):
    authenticator.login("testuser", "secure123")
    with pytest.raises(PermissionError):
        authorizer.check_permission("edit", "testuser")

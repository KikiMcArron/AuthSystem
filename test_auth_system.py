import pytest
import hashlib
from unittest.mock import MagicMock, patch, PropertyMock
from auth_system import User, Authenticator
from exceptions import UsernameAlreadyExists, PasswordToShort, InvalidUsername, InvalidPassword


# Tests for User class


@pytest.fixture
def user():
    username = 'testuser'
    password = 'secure123'
    return User(username, password)


def test_encrypt_pw(monkeypatch):
    class MockSHA256:
        def hexdigest(self):
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

    # Replace the existing user with the mock
    authenticator.users['testuser'] = mock_user

    authenticator.login("testuser", "secure123")

    # Directly check if is_logged_in was set to True
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

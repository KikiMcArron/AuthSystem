from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from auth_system import User


class AuthException(Exception):
    """
    Base class for exceptions in this module.

    Attributes:
        username (str): The username of the user who caused the exception.
        user (str): The user object who caused the exception.
    """
    def __init__(self, username: str, user: Optional['User'] = None) -> None:
        super().__init__(username, user)
        self.username = username
        self.user = user


class UsernameAlreadyExists(AuthException):
    """
    Exception raised when a username already exists in the system.
    """
    pass


class PasswordTooShort(AuthException):
    """
    Exception raised when a password is too short.
    """
    pass


class InvalidUsername(AuthException):
    """
    Exception raised when a username is invalid or does not exist in the system.
    """
    pass


class InvalidPassword(AuthException):
    """
    Exception raised when a password is invalid or does not match the stored password for a user.
    """
    pass


class NotLoggedInError(AuthException):
    """
    Exception raised when a user is not logged in but tries to perform an action that requires authentication.
    """
    pass


class NotPermittedError(AuthException):
    """
    Exception raised when a user tries to perform an action they do not have permission for.
    """
    pass

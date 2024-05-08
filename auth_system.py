import hashlib
from typing import Dict, Set
from exceptions import (PasswordTooShort, UsernameAlreadyExists, InvalidUsername, InvalidPassword, NotLoggedInError,
                        NotPermittedError)


class User:
    """
    Represents a user in the system with functionalities for password encryption and verification.

    Attributes:
        username (str): The username of the user.
        password (str): The encrypted password of the user.
        is_logged_in (bool): Flag indicating whether the user is currently logged in.

    Methods:
        _encrypt_pw: Encrypts a password using SHA-256 hashing.
        check_password: Checks if a provided password matches the stored encrypted password.
    """

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = self._encrypt_pw(password)
        self.is_logged_in = False

    def _encrypt_pw(self, password: str) -> str:
        hash_string = self.username + password
        encoded_hash_string = hash_string.encode('utf8')
        return hashlib.sha256(encoded_hash_string).hexdigest()

    def check_password(self, password: str) -> bool:
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password


class Authenticator:
    """
    Manages a collection of users and handles user authentication.

    Attributes:
        users: (Dict[str, User]) A dictionary of users with usernames as keys and User objects as values.

    Methods:
        add_user: Adds a new user to the collection.
        remove_user: Removes a user from the collection.
        login: Logs a user in by verifying their password.
        is_logged_in: Checks if a user is logged in.
    """
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}

    def add_user(self, username: str, password: str) -> None:
        if username in self.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        self.users[username] = User(username, password)

    def remove_user(self, username: str) -> None:
        if username not in self.users:
            raise InvalidUsername(username)
        del self.users[username]

    def login(self, username: str, password: str) -> bool:
        try:
            user = self.users[username]
        except KeyError:
            raise InvalidUsername(username)

        if not user.check_password(password):
            raise InvalidPassword(username, user)

        user.is_logged_in = True
        return True

    def is_logged_in(self, username: str) -> bool:
        if username in self.users:
            return self.users[username].is_logged_in
        return False


class Authorizer:
    """
    Manages permissions for users.

    Attributes:
        authenticator: An Authenticator object to manage user authentication.
        permissions (dict): A dictionary of permissions with permission names as keys and sets of usernames as values.

    Methods:
        add_permission: Adds a new permission to the collection.
        permit_user: Grants a user a specific permission.
        check_permission: Checks if a user has a specific permission.
    """
    def __init__(self, authenticator: Authenticator) -> None:
        self.authenticator = authenticator
        self.permissions: Dict[str, Set[str]] = {}

    def add_permission(self, perm_name: str) -> None:
        if perm_name in self.permissions:
            raise PermissionError('Permission already exists')
        self.permissions[perm_name] = set()

    def permit_user(self, perm_name: str, username: str) -> None:
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError('Permission does not exist')
        else:
            if username not in self.authenticator.users:
                raise InvalidUsername(username)
            perm_set.add(username)

    def check_permission(self, perm_name: str, username: str) -> bool:
        if not self.authenticator.is_logged_in(username):
            raise NotLoggedInError(username)
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError('Permission does not exist')
        else:
            if username not in perm_set:
                raise NotPermittedError(username)
            else:
                return True

from abc import ABC, abstractmethod
from auth_system import Authenticator, Authorizer


class Action(ABC):
    """
    Abstract base class for all actions in the system.

    Methods:
        execute: Abstract method to be implemented by subclasses. Executes the action.
    """

    @abstractmethod
    def execute(self) -> None:
        pass


class AddUser(Action):
    """
    Represents the action of adding a user to the system.

    Attributes:
        authenticator: An Authenticator object to manage user authentication.

    Methods:
        execute: Executes the action of adding a user.
    """

    def __init__(self, authenticator: Authenticator) -> None:
        self.authenticator = authenticator

    def execute(self) -> None:
        username = input('Enter the username you wish to add: ')
        password = input(f'Enter the password for user {username}: ')
        self.authenticator.add_user(username, password)
        print(f'User "{username}" added successfully.')


class RemoveUser(Action):
    """
    Represents the action of removing a user from the system.

    Attributes:
        authenticator: An Authenticator object to manage user authentication.

    Methods:
        execute: Executes the action of removing a user.
    """
    def __init__(self, authenticator: Authenticator) -> None:
        self.authenticator = authenticator

    def execute(self) -> None:
        username = input('Enter the username you wish to remove: ')
        self.authenticator.remove_user(username)
        print(f'User "{username}" removed successfully.')


class AddPermission(Action):
    """
    Represents the action of adding a permission to the system.

    Attributes:
        authorizer: An Authorizer object to manage user permissions.

    Methods:
        execute: Executes the action of adding a permission.
    """
    def __init__(self, authorizer: Authorizer) -> None:
        self.authorizer = authorizer

    def execute(self) -> None:
        permission = input('Enter the permission you wish to add: ')
        self.authorizer.add_permission(permission)
        print(f'Permission "{permission}" added successfully.')


class PermitUser(Action):
    """
    Represents the action of granting a user a specific permission.

    Attributes:
        authorizer: An Authorizer object to manage user permissions.

    Methods:
        execute: Executes the action of granting a user a permission.
    """
    def __init__(self, authorizer: Authorizer) -> None:
        self.authorizer = authorizer

    def execute(self) -> None:
        permission = input('Enter the permission you wish to add: ')
        username = input('Enter the username you wish to permit: ')
        self.authorizer.permit_user(permission, username)
        print(f'User "{username}" permitted for permission "{permission}".')


class Exit(Action):
    """
    Represents the action of exiting the system.

    Methods:
        execute: Executes the action of exiting the system.
    """
    def execute(self) -> None:
        raise SystemExit()

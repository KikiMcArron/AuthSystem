from abc import ABC, abstractmethod


class Action(ABC):
    @abstractmethod
    def execute(self):
        pass


class AddUser(Action):
    def __init__(self, authenticator):
        self.authenticator = authenticator

    def execute(self):
        username = input('Enter the username you wish to add: ')
        password = input(f'Enter the password for user {username}: ')
        self.authenticator.add_user(username, password)
        print(f'User "{username}" added successfully.')


class RemoveUser(Action):
    def __init__(self, authenticator):
        self.authenticator = authenticator

    def execute(self):
        username = input('Enter the username you wish to remove: ')
        self.authenticator.remove_user(username)
        print(f'User "{username}" removed successfully.')


class AddPermission(Action):
    def __init__(self, authorizer):
        self.authorizer = authorizer

    def execute(self):
        permission = input('Enter the permission you wish to add: ')
        self.authorizer.add_permission(permission)
        print(f'Permission "{permission}" added successfully.')


class PermitUser(Action):
    def __init__(self, authorizer):
        self.authorizer = authorizer

    def execute(self):
        permission = input('Enter the permission you wish to add: ')
        username = input('Enter the username you wish to permit: ')
        self.authorizer.permit_user(permission, username)
        print(f'User "{username}" permitted for permission "{permission}".')


class Exit(Action):
    def execute(self):
        raise SystemExit()
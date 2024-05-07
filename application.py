import re
from actions import AddUser, RemoveUser, AddPermission, PermitUser, Exit
from auth_system import Authenticator, Authorizer


class AuthManager:
    def __init__(self):
        self.authenticator = Authenticator()
        self.authorizer = Authorizer(self.authenticator)
        self.actions = [
            AddUser(self.authenticator),
            RemoveUser(self.authenticator),
            AddPermission(self.authorizer),
            PermitUser(self.authorizer),
            Exit()
        ]


class Menu:
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager

    def display_menu(self):
        print(f'Please select an option (1-{len(self.auth_manager.actions)}):')
        for index, action in enumerate(self.auth_manager.actions, start=1):
            action_name = self.format_action_name(action.__class__.__name__)
            print(f'{index}. {action_name}')

    @staticmethod
    def format_action_name(action_name):
        return re.sub(r'(?<!^)(?=[A-Z])', ' ', action_name).title()


class Application:
    def __init__(self, action_manager):
        self.action_manager = action_manager
        self.menu_display = Menu(self.action_manager)

    def run(self):
        try:
            while True:
                self.menu_display.display_menu()
                action = self.get_user_choice()
                if action:
                    action.execute()
        finally:
            print('Thank you for testing AuthSystem app')

    def get_user_choice(self):
        choice = input('Enter your choice: ')
        try:
            select_index = int(choice) - 1
            return self.action_manager.actions[select_index]
        except (ValueError, IndexError):
            print('Invalid choice. Please try again.')
            return None

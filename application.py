import re
from typing import Optional
from actions import Action, AddUser, RemoveUser, AddPermission, PermitUser, Exit
from auth_system import Authenticator, Authorizer


class AuthManager:
    """
    Manages authentication and authorization actions in the system.

    Attributes:
        authenticator (Authenticator): An Authenticator object to manage user authentication.
        authorizer (Authorizer): An Authorizer object to manage user permissions.
        actions (list): A list of Action objects representing the available actions in the system.
    """
    def __init__(self) -> None:
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
    """
    Displays a menu of available actions to the user.

    Attributes:
        auth_manager (AuthManager): An AuthManager object to manage authentication and authorization actions.

    Methods:
        display_menu: Prints the available actions to the console.
        format_action_name: Formats the name of an action for display.
    """
    def __init__(self, auth_manager: AuthManager) -> None:
        self.auth_manager = auth_manager

    def display_menu(self) -> None:
        print(f'Please select an option (1-{len(self.auth_manager.actions)}):')
        for index, action in enumerate(self.auth_manager.actions, start=1):
            action_name = self.format_action_name(action.__class__.__name__)
            print(f'{index}. {action_name}')

    @staticmethod
    def format_action_name(action_name: str) -> str:
        """
        Formats the name of an action for display.

        Converts camelCase or PascalCase action names into a more readable format
        suitable for display as menu items, by adding spaces before each capital letter
        (except the first) and capitalizing the first letter of each word.

        Args:
            action_name (str): The name of the action to format.

        Returns:
            str: The formatted action name.
        """
        return re.sub(r'(?<!^)(?=[A-Z])', ' ', action_name).title()


class Application:
    def __init__(self, action_manager: AuthManager) -> None:
        self.action_manager = action_manager
        self.menu_display = Menu(self.action_manager)

    def run(self) -> None:
        try:
            while True:
                self.menu_display.display_menu()
                action = self.get_user_choice()
                if action:
                    action.execute()
        finally:
            print('Thank you for testing AuthSystem app')

    def get_user_choice(self) -> Optional[Action]:
        choice = input('Enter your choice: ')
        try:
            select_index = int(choice) - 1
            return self.action_manager.actions[select_index]
        except (ValueError, IndexError):
            print('Invalid choice. Please try again.')
            return None

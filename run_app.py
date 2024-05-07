from application import Application, AuthManager


def main():
    auth_manager = AuthManager()
    app = Application(auth_manager)
    app.run()


if __name__ == '__main__':
    main()

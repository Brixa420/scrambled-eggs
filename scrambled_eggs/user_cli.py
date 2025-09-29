"""
Command-line interface for user management.
"""

import argparse
import getpass
import sys
from typing import List, Optional

from .user_management import UserManager


def main(args: Optional[List[str]] = None) -> int:
    """Run the user management CLI.

    Args:
        args: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(description="Scrambled Eggs User Management")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Create user command
    create_parser = subparsers.add_parser("create", help="Create a new user")
    create_parser.add_argument("username", help="Username")
    create_parser.add_argument("--admin", action="store_true", help="Make the user an admin")

    # List users command
    list_parser = subparsers.add_parser("list", help="List all users")

    # Delete user command
    delete_parser = subparsers.add_parser("delete", help="Delete a user")
    delete_parser.add_argument("username", help="Username to delete")
    delete_parser.add_argument("--admin-username", required=True, help="Admin username")

    # Reset password command
    reset_parser = subparsers.add_parser("reset-password", help="Reset a user's password")
    reset_parser.add_argument("username", help="Username to reset")
    reset_parser.add_argument("--admin-username", required=True, help="Admin username")

    # Parse arguments
    parsed_args = parser.parse_args(args)
    user_manager = UserManager()

    if parsed_args.command == "create":
        # Get password securely
        while True:
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password == confirm:
                break
            print("Passwords don't match. Try again.", file=sys.stderr)

        try:
            user = user_manager.create_user(
                username=parsed_args.username, password=password, is_admin=parsed_args.admin
            )
            print(f"User '{user.username}' created successfully!")
            if parsed_args.admin:
                print("  - This user has admin privileges")
            return 0
        except Exception as e:
            print(f"Error creating user: {e}", file=sys.stderr)
            return 1

    elif parsed_args.command == "list":
        users = user_manager.list_users()
        if not users:
            print("No users found.")
            return 0

        # Print user table
        print(f"{'Username':<20} {'Admin':<6} {'Active':<6} {'Last Login':<25} {'Created At'}")
        print("-" * 80)
        for user in users:
            last_login = user.get("last_login", "Never")
            if last_login and len(last_login) > 20:  # Truncate long timestamps
                last_login = last_login[:20]
            print(
                f"{user['username']:<20} "
                f"{'Yes' if user['is_admin'] else 'No':<6} "
                f"{'Yes' if user.get('is_active', True) else 'No':<6} "
                f"{last_login:<25} "
                f"{user['created_at']}"
            )
        return 0

    elif parsed_args.command == "delete":
        admin_password = getpass.getpass(f"Enter password for {parsed_args.admin_username}: ")
        if not user_manager.authenticate(parsed_args.admin_username, admin_password):
            print("Authentication failed.", file=sys.stderr)
            return 1

        if user_manager.delete_user(parsed_args.username, parsed_args.admin_username):
            print(f"User '{parsed_args.username}' deleted successfully!")
            return 0
        else:
            print(f"Failed to delete user '{parsed_args.username}'.", file=sys.stderr)
            return 1

    elif parsed_args.command == "reset-password":
        admin_password = getpass.getpass(f"Enter password for {parsed_args.admin_username}: ")
        if not user_manager.authenticate(parsed_args.admin_username, admin_password):
            print("Authentication failed.", file=sys.stderr)
            return 1

        while True:
            new_password = getpass.getpass("Enter new password: ")
            confirm = getpass.getpass("Confirm new password: ")
            if new_password == confirm:
                break
            print("Passwords don't match. Try again.", file=sys.stderr)

        if user_manager.reset_password(
            parsed_args.username, new_password, parsed_args.admin_username
        ):
            print(f"Password for '{parsed_args.username}' has been reset.")
            return 0
        else:
            print(f"Failed to reset password for '{parsed_args.username}'.", file=sys.stderr)
            return 1

    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())

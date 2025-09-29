import os
import secrets
import shutil
import string


def generate_random_key(length=64):
    """Generate a secure random key."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def setup_environment():
    # Check if .env already exists
    if os.path.exists(".env"):
        print("⚠️  .env file already exists. Creating a backup...")
        shutil.copy2(".env", ".env.backup" + str(int(time.time())))

    # Read the example file
    with open(".env.example", "r") as f:
        content = f.read()

    # Replace placeholders with generated values
    content = content.replace("generate_a_secure_random_key_here", generate_random_key())

    # Write to .env
    with open(".env", "w") as f:
        f.write(content)

    print("✅ .env file created successfully!")
    print("🔑 Generated secure keys for SECRET_KEY, ENCRYPTION_KEY, and JWT_SECRET_KEY")
    print("\n⚠️  IMPORTANT: Keep this file secure and never commit it to version control!")


if __name__ == "__main__":
    import time

    setup_environment()

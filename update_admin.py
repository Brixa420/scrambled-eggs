import getpass

from passlib.context import CryptContext

from app.db.base import SessionLocal
from app.models.user import User


def update_admin_password():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            print("❌ Admin user not found")
            return

        print("\n🔒 Admin Password Update")
        print("----------------------")

        while True:
            new_password = getpass.getpass("Enter new password: ")
            confirm_password = getpass.getpass("Confirm new password: ")

            if new_password != confirm_password:
                print("❌ Passwords do not match. Please try again.")
                continue

            if len(new_password) < 8:
                print("❌ Password must be at least 8 characters long.")
                continue

            # Update password
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            admin.hashed_password = pwd_context.hash(new_password)
            db.commit()
            print("\n✅ Admin password updated successfully!")
            break

    except Exception as e:
        print(f"❌ Error updating password: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    update_admin_password()

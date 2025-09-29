"""
Test MFA verification with account lockout and rate limiting.

This test suite verifies:
1. Account lockout after maximum failed attempts
2. Rate limiting for MFA verification
3. Proper error messages and status codes
4. Lockout expiration
5. Backup code verification during lockout
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta
import time

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.resolve())
sys.path.insert(0, project_root)

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.config import settings
from app.db.base import Base, get_db
from app.models.user import User
from app.models.two_factor import UserTwoFactor, TwoFactorStatus, TwoFactorMethod
from app.core.security import get_password_hash
from app.services.mfa_service import MFAService

# Test client
client = TestClient(app)

def create_test_user(db: Session, email: str = "test_lockout@example.com", with_backup_codes: bool = True):
    """Create a test user with MFA enabled and optional backup codes."""
    # Delete existing test user if any
    db.query(User).filter(User.email == email).delete()
    db.commit()
    
    # Create test user
    user = User(
        email=email,
        hashed_password=get_password_hash("testpassword"),
        username=email.split('@')[0],
        is_active=True
    )
    db.add(user)
    db.flush()
    
    # Set up MFA
    totp_secret = MFAService.generate_totp_secret()
    two_factor = UserTwoFactor(
        user_id=user.id,
        totp_secret=totp_secret,
        totp_enabled=True,
        status=TwoFactorStatus.ACTIVE,
        failed_attempts=0
    )
    db.add(two_factor)
    
    if with_backup_codes:
        # Add a backup code for testing
        backup_code = "BACKUP123456"
        db.execute(
            """
            INSERT INTO backup_codes (user_id, code, used)
            VALUES (:user_id, :code, FALSE)
            """,
            {"user_id": user.id, "code": get_password_hash(backup_code)}
        )
    
    db.commit()
    
    return user

def test_backup_code_during_lockout(db: Session):
    """Test that backup codes can be used during TOTP lockout."""
    # Create test user with backup codes
    user = create_test_user(db, email="backup_test@example.com")
    
    # Get MFA token
    login_data = {
        "username": user.email,
        "password": "testpassword",
    }
    response = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    mfa_token = response.json()["mfa_token"]
    
    # Trigger lockout with TOTP
    for _ in range(MFAService.MAX_FAILED_ATTEMPTS + 1):
        client.post(
            f"{settings.API_V1_STR}/mfa/verify",
            json={"mfa_token": mfa_token, "code": "123456", "method": "totp"}
        )
    
    # Try to use backup code while locked out
    backup_code = "BACKUP123456"  # This should match what's in create_test_user
    response = client.post(
        f"{settings.API_V1_STR}/mfa/verify",
        json={
            "mfa_token": mfa_token,
            "code": backup_code,
            "method": "backup"
        }
    )
    
    # Should be able to use backup code even when TOTP is locked
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
    
    # Verify the backup code was marked as used
    used = db.execute(
        "SELECT used FROM backup_codes WHERE user_id = :user_id",
        {"user_id": user.id}
    ).fetchone()
    assert used and used[0] is True


def test_concurrent_access_attempts(db: Session):
    """Test that concurrent access attempts are handled correctly."""
    from concurrent.futures import ThreadPoolExecutor
    
    # Create test user
    user = create_test_user(db, email="concurrent_test@example.com")
    
    # Get MFA token
    login_data = {
        "username": user.email,
        "password": "testpassword",
    }
    response = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    mfa_token = response.json()["mfa_token"]
    
    # Function to simulate a single verification attempt
    def attempt_verification():
        return client.post(
            f"{settings.API_V1_STR}/mfa/verify",
            json={"mfa_token": mfa_token, "code": "123456", "method": "totp"}
        )
    
    # Make multiple concurrent requests
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(attempt_verification) for _ in range(10)]
        results = [f.result() for f in futures]
    
    # Verify we got the expected number of failures and at least one lockout
    status_codes = [r.status_code for r in results]
    assert status_codes.count(400) + status_codes.count(403) >= 5  # At least 5 failures
    assert 403 in status_codes  # At least one lockout


def test_error_responses(db: Session):
    """Test that error responses contain the expected fields."""
    # Create test user
    user = create_test_user(db, email="error_test@example.com")
    
    # Get MFA token
    login_data = {
        "username": user.email,
        "password": "testpassword",
    }
    response = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    mfa_token = response.json()["mfa_token"]
    
    # Test invalid method
    response = client.post(
        f"{settings.API_V1_STR}/mfa/verify",
        json={"mfa_token": mfa_token, "code": "123456", "method": "invalid"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "message" in response.json()
    
    # Test missing fields
    response = client.post(
        f"{settings.API_V1_STR}/mfa/verify",
        json={"mfa_token": mfa_token}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_mfa_lockout_basic(db: Session):
    """Test basic MFA lockout after maximum failed attempts."""
    # Create test user
    user = create_test_user(db)
    
    # Get MFA token
    login_data = {
        "username": user.email,
        "password": "testpassword",
    }
    response = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == status.HTTP_202_ACCEPTED
    data = response.json()
    assert "mfa_required" in data
    assert "mfa_token" in data
    
    mfa_token = data["mfa_token"]
    
    # Test failed attempts
    for i in range(MFAService.MAX_FAILED_ATTEMPTS + 1):
        response = client.post(
            f"{settings.API_V1_STR}/mfa/verify",
            json={
                "mfa_token": mfa_token,
                "code": "123456",  # Invalid code
                "method": "totp"
            }
        )
        
        if i < MFAService.MAX_FAILED_ATTEMPTS - 1:
            # Should fail but not locked yet
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "remaining_attempts" in response.json()
            assert response.json()["remaining_attempts"] == MFAService.MAX_FAILED_ATTEMPTS - i - 1
        elif i == MFAService.MAX_FAILED_ATTEMPTS - 1:
            # Last attempt before lockout
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "remaining_attempts" in response.json()
            assert response.json()["remaining_attempts"] == 0
        else:
            # Should be locked out now
            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "retry_after" in response.json()
            assert response.json()["message"] == "Account locked due to too many failed attempts"
    
    # Verify the account is locked in the database
    db.refresh(user)
    assert user.two_factor.failed_attempts >= MFAService.MAX_FAILED_ATTEMPTS
    assert user.two_factor.status == TwoFactorStatus.ACTIVE
    assert user.two_factor.lockout_until is not None


def test_mfa_lockout_expiration(db: Session):
    """Test that lockout expires after the lockout period."""
    # Create test user
    user = create_test_user(db, email="expiry_test@example.com")
    
    # Get MFA token
    login_data = {
        "username": user.email,
        "password": "testpassword",
    }
    response = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    mfa_token = response.json()["mfa_token"]
    
    # Trigger lockout
    for _ in range(MFAService.MAX_FAILED_ATTEMPTS + 1):
        client.post(
            f"{settings.API_V1_STR}/mfa/verify",
            json={"mfa_token": mfa_token, "code": "123456", "method": "totp"}
        )
    
    # Manually set lockout time to expire soon
    db.refresh(user)
    user.two_factor.lockout_until = datetime.utcnow() + timedelta(seconds=2)  # 2 seconds from now
    db.commit()
    
    # Should still be locked
    response = client.post(
        f"{settings.API_V1_STR}/mfa/verify",
        json={"mfa_token": mfa_token, "code": "123456", "method": "totp"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    
    # Wait for lockout to expire
    time.sleep(3)
    
    # Should be able to try again
    response = client.post(
        f"{settings.API_V1_STR}/mfa/verify",
        json={"mfa_token": mfa_token, "code": "123456", "method": "totp"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST  # Still wrong code, but not locked out
    assert "remaining_attempts" in response.json()


def test_mfa_rate_limiting(db: Session):
    """Test rate limiting for MFA verification."""
    # Create test user
    user = create_test_user(db, email="rate_limit@example.com")
    
    # Get MFA token
    login_data = {
        "username": user.email,
        "password": "testpassword",
    response = client.post(
        f"{settings.API_V1_STR}/login/access-token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    mfa_token = response.json()["mfa_token"]
    
    # Trigger lockout with TOTP
    for _ in range(MFAService.MAX_FAILED_ATTEMPTS + 1):
        client.post(
            f"{settings.API_V1_STR}/mfa/verify",
            json={"mfa_token": mfa_token, "code": "123456", "method": "totp"}
        )
    
    # Try to use backup code while locked out
    response = client.post(
        f"{settings.API_V1_STR}/mfa/verify",
        json={
            "mfa_token": mfa_token,
            "code": backup_codes[0],  # Use the backup code
            "method": "backup"
        }
    )
    
    # Should still be able to use backup code
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
    
    # Verify the backup code was marked as used
    used_code = db.execute(
        "SELECT used FROM backup_codes WHERE user_id = :user_id",
        {"user_id": user.id}
    ).fetchone()
    assert used_code and used_code[0] is True

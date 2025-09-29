"""
Multi-Factor Authentication (MFA) utilities.
"""

import base64
from typing import Any, Dict, Optional, Tuple

import pyotp
import qrcode

from .config import get_config
from .utils import security_utils

# Initialize config
config = get_config()


class MFAError(Exception):
    """Raised when there's an error with MFA operations."""

    pass


class MFA:
    """Multi-Factor Authentication utilities."""

    @staticmethod
    def generate_secret() -> str:
        """
        Generate a new TOTP secret.

        Returns:
            A base32-encoded secret key
        """
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        """
        Get the provisioning URI for a TOTP secret.

        Args:
            secret: The base32-encoded secret key
            email: The user's email (used as an identifier)

        Returns:
            A provisioning URI that can be used to generate a QR code
        """
        return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=config.MFA_ISSUER)

    @staticmethod
    def generate_qr_code(uri: str) -> bytes:
        """
        Generate a QR code for the provisioning URI.

        Args:
            uri: The provisioning URI

        Returns:
            The QR code image as PNG bytes
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to bytes
        img_bytes = BytesIO()
        img.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        return img_bytes.getvalue()

    @staticmethod
    def verify_totp(secret: str, token: str, window: int = 1) -> bool:
        """
        Verify a TOTP token.

        Args:
            secret: The base32-encoded secret key
            token: The token to verify
            window: The verification window (in time steps, 30 seconds each)

        Returns:
            True if the token is valid, False otherwise
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)

    @staticmethod
    def generate_recovery_codes(count: int = 10) -> Tuple[list, str]:
        """
        Generate recovery codes for MFA.

        Args:
            count: The number of recovery codes to generate (default: 10)

        Returns:
            A tuple of (codes, hashed_codes) where codes is a list of plaintext
            recovery codes and hashed_codes is a single string of hashed codes
            separated by commas
        """
        import hashlib
        import secrets

        codes = []
        hashed_codes = []

        for _ in range(count):
            # Generate a random 12-character code with dashes for readability
            code = "-".join(
                [secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2)]
            ).upper()

            # Hash the code for secure storage
            hashed = hashlib.sha256(code.encode("utf-8")).hexdigest()

            codes.append(code)
            hashed_codes.append(hashed)

        # Return the plaintext codes and a single string of hashed codes
        return codes, ",".join(hashed_codes)

    @staticmethod
    def verify_recovery_code(hashed_codes: str, code: str) -> Tuple[bool, str]:
        """
        Verify a recovery code.

        Args:
            hashed_codes: A string of hashed recovery codes separated by commas
            code: The recovery code to verify

        Returns:
            A tuple of (is_valid, updated_hashed_codes) where is_valid is True
            if the code is valid, and updated_hashed_codes is the updated list
            of hashed codes with the used code removed
        """
        import hashlib

        if not hashed_codes or not code:
            return False, hashed_codes

        # Hash the provided code
        hashed_code = hashlib.sha256(code.strip().encode("utf-8")).hexdigest()

        # Split the hashed codes and check if the provided code is in the list
        codes = hashed_codes.split(",")

        try:
            # Remove the used code
            codes.remove(hashed_code)
            return True, ",".join(codes)
        except ValueError:
            return False, hashed_codes


# Create an instance for easy importing
mfa = MFA()

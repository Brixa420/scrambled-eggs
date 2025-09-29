"""
Monkey patches for the Scrambled Eggs library.
"""

import logging
from functools import wraps

logger = logging.getLogger(__name__)


def patch_breach_detector():
    """Patch the BreachDetector class to handle the threshold parameter."""
    try:
        from scrambled_eggs.breach_detection import BreachDetector

        # Save the original __init__
        original_init = BreachDetector.__init__

        # Create a wrapper that removes the threshold parameter
        @wraps(original_init)
        def patched_init(self, *args, **kwargs):
            if "threshold" in kwargs:
                logger.debug("Removing 'threshold' parameter from BreachDetector.__init__")
                del kwargs["threshold"]
            return original_init(self, *args, **kwargs)

        # Apply the patch
        BreachDetector.__init__ = patched_init
        logger.info("Successfully patched BreachDetector.__init__")
        return True
    except Exception as e:
        logger.error(f"Failed to patch BreachDetector: {e}")
        return False


def patch_key_derivation():
    """Patch the KeyDerivation class to add the derive_key method."""
    try:
        import hashlib
        import os

        from scrambled_eggs.security.key_derivation import KeyDerivation

        if not hasattr(KeyDerivation, "derive_key"):

            @classmethod
            def derive_key(
                cls,
                password: str,
                salt: bytes = None,
                key_length: int = 32,
                iterations: int = 100000,
                **kwargs,
            ) -> tuple[bytes, bytes]:
                """Derive a key from a password using PBKDF2-HMAC-SHA256."""
                if isinstance(password, str):
                    password = password.encode("utf-8")
                if salt is None:
                    salt = os.urandom(16)
                dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=key_length)
                return dk, salt

            KeyDerivation.derive_key = derive_key
            logger.info("Successfully patched KeyDerivation.derive_key")
            return True
        return True
    except Exception as e:
        logger.error(f"Failed to patch KeyDerivation: {e}")
        return False


def patch_memory_protector():
    """Patch the MemoryProtector class to add the secure_erase method."""
    try:
        from scrambled_eggs.security.memory_protection import MemoryProtector

        if not hasattr(MemoryProtector, "secure_erase"):

            @staticmethod
            def secure_erase(data):
                """Securely erase sensitive data from memory."""
                try:
                    if isinstance(data, (bytearray, bytes)):
                        # Overwrite with zeros
                        data_len = len(data)
                        if isinstance(data, bytearray):
                            data[:] = bytearray(data_len)
                        elif isinstance(data, bytes):
                            data = b"\x00" * data_len
                    return True
                except Exception as e:
                    logger.error(f"Error in secure_erase: {e}")
                    return False

            MemoryProtector.secure_erase = secure_erase
            logger.info("Successfully patched MemoryProtector.secure_erase")
            return True
        return True
    except Exception as e:
        logger.error(f"Failed to patch MemoryProtector: {e}")
        return False


def apply_all_patches():
    """Apply all available patches."""
    results = [patch_breach_detector(), patch_key_derivation(), patch_memory_protector()]
    return all(results)


# Apply patches when this module is imported
apply_all_patches()

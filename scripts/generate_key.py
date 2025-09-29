"""
Generate a secure encryption key for Scrambled Eggs.
"""

import base64
import json
import os
from pathlib import Path


def generate_key():
    """Generate a secure encryption key and save it to a file."""
    # Generate a random 32-byte (256-bit) key
    key = os.urandom(32)
    key_hex = key.hex()
    key_base64 = base64.urlsafe_b64encode(key).decode("utf-8")

    # Create a simple key file
    key_data = {
        "key": key_base64,
        "key_hex": key_hex,
        "key_length": 256,
        "created_at": "2025-09-27T00:00:00Z",  # Will be updated with actual time
    }

    # Save the key to a file
    key_dir = Path("data/keys")
    key_dir.mkdir(parents=True, exist_ok=True)

    key_file = key_dir / "encryption_key.json"
    with open(key_file, "w") as f:
        json.dump(key_data, f, indent=2)

    # Set restrictive permissions (Windows doesn't fully support this, but we try)
    try:
        os.chmod(key_file, 0o600)
    except:
        pass  # Ignore if we can't set permissions

    print(f"✅ Encryption key generated and saved to: {key_file}")
    print("\n=== IMPORTANT ===")
    print("Keep this key safe! If you lose it, you won't be able to decrypt your data.")
    print("\nKey (hex):", key_hex)
    print("Key (base64):", key_base64)
    print("\nAdd this to your .env file:")
    print(f"ENCRYPTION_KEY={key_base64}")


if __name__ == "__main__":
    generate_key()

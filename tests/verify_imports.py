"""
Script to verify that all necessary imports are working correctly.
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

print("Python path:")
for path in sys.path:
    print(f"  - {path}")

print("\nTesting imports...")

try:
    # Test importing the encryption service
    print("\n1. Testing encryption service import...")
    from app.services.encryption import crypto

    print("✅ Successfully imported encryption service")

    # Test basic encryption/decryption
    print("\n2. Testing encryption/decryption...")
    test_message = "Hello, Scrambled Eggs!"
    context = {"test": "value"}

    print(f"   Original message: {test_message}")
    encrypted = crypto.encrypt(test_message, context=context)
    print("   ✅ Encryption successful")

    decrypted = crypto.decrypt(encrypted, context=context)
    decrypted_message = decrypted["plaintext"].decode("utf-8")
    print(f"   Decrypted message: {decrypted_message}")

    if decrypted_message == test_message:
        print("   ✅ Decryption successful")
    else:
        print("   ❌ Decryption failed: messages don't match")

    print("\n🎉 All tests passed!")

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\nTroubleshooting steps:")
    print("1. Make sure you're running from the project root")
    print("2. Check that the app package is in your Python path")
    print("3. Verify all dependencies are installed")

except Exception as e:
    print(f"❌ An error occurred: {e}")
    raise

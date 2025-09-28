"""
Minimal test script for the Scrambled Eggs encryption service.
"""
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import the encryption service
try:
    from app.services.encryption import crypto
    print("✅ Successfully imported encryption service")
    
    # Test basic encryption/decryption
    test_message = "Hello, Scrambled Eggs!"
    print(f"\nTesting encryption with message: {test_message}")
    
    # Encrypt
    encrypted = crypto.encrypt(test_message)
    print("✅ Encryption successful")
    
    # Decrypt
    decrypted = crypto.decrypt(encrypted)
    decrypted_message = decrypted['plaintext'].decode('utf-8')
    print(f"✅ Decryption successful. Decrypted message: {decrypted_message}")
    
    # Verify
    if decrypted_message == test_message:
        print("✅ Test passed: Original and decrypted messages match!")
    else:
        print(f"❌ Test failed: Messages don't match. Expected '{test_message}', got '{decrypted_message}'")
    
except ImportError as e:
    print(f"❌ Failed to import encryption service: {e}")
    print(f"Python path: {sys.path}")
    raise

except Exception as e:
    print(f"❌ An error occurred: {e}")
    raise

"""
Scrambled Eggs - Encryption Setup

This script sets up the encryption system for the Scrambled Eggs application.
It creates a new encryption key and configures the system to use it.
"""
import os
import sys
import json
import logging
from pathlib import Path
from getpass import getpass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('encryption_setup.log')
    ]
)
logger = logging.getLogger(__name__)

def ensure_directories() -> Path:
    """Ensure all required directories exist."""
    # Create data directory
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True, mode=0o700)
    
    # Create keys directory
    keys_dir = data_dir / 'keys'
    keys_dir.mkdir(exist_ok=True, mode=0o700)
    
    # Create logs directory
    logs_dir = Path('logs')
    logs_dir.mkdir(exist_ok=True, mode=0o750)
    
    return data_dir

def generate_secure_key() -> bytes:
    """Generate a secure random encryption key."""
    import secrets
    return secrets.token_bytes(32)  # 256-bit key

def setup_encryption() -> bool:
    """Set up the encryption system with a new key."""
    try:
        print("\n=== Scrambled Eggs Encryption Setup ===\n")
        print("This will set up a new encryption key for your application.")
        print("\nIMPORTANT: The security of your encrypted data depends on this key.")
        print("Keep it safe and never share it with anyone!\n")
        
        # Ensure directories exist
        data_dir = ensure_directories()
        
        # Generate a new key
        key = generate_secure_key()
        key_hex = key.hex()
        key_base64 = base64.b64encode(key).decode('utf-8')
        
        # Create key metadata
        from datetime import datetime
        key_id = f"key_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        key_data = {
            'id': key_id,
            'created_at': datetime.utcnow().isoformat(),
            'key': key_base64,
            'key_hex': key_hex,
            'key_length': 256,  # bits
            'is_active': True,
            'usage': 'application_encryption',
            'rotation_policy': '90d',
            'version': 1
        }
        
        # Save the key to a secure file
        keys_dir = data_dir / 'keys'
        key_file = keys_dir / f"{key_id}.json"
        
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
        
        # Set restrictive permissions
        os.chmod(key_file, 0o600)
        
        # Create or update the configuration
        config_file = data_dir / 'encryption_config.json'
        config = {
            'version': 1,
            'current_key_id': key_id,
            'key_storage': str(keys_dir.absolute()),
            'key_rotation_days': 90,
            'key_history_size': 3,
            'created_at': datetime.utcnow().isoformat(),
            'encryption_algorithm': 'AES-256-GCM',
            'key_derivation': {
                'algorithm': 'PBKDF2-HMAC-SHA256',
                'iterations': 100000,
                'salt_length': 16
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Create a backup of the key (in a real app, this would be more secure)
        backup_file = data_dir / f"{key_id}.backup"
        with open(backup_file, 'w') as f:
            f.write("=== SCRAMBLED EGGS ENCRYPTION KEY BACKUP ===\n\n")
            f.write("WARNING: This file contains sensitive information!\n")
            f.write("Store it in a secure location and never commit it to version control.\n\n")
            f.write(f"Key ID: {key_id}\n")
            f.write(f"Created: {key_data['created_at']}\n")
            f.write("\nKEY (hex):\n")
            f.write(key_hex + "\n\n")
            f.write("KEY (base64):\n")
            f.write(key_base64 + "\n")
        
        # Set restrictive permissions on the backup
        os.chmod(backup_file, 0o600)
        
        # Create a simple test script
        test_script = data_dir / 'test_encryption.py'
        test_code = f""""
# Test encryption/decryption with the new key
# Run this script to verify that encryption is working correctly.

import os
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load the key
key_file = Path('data/keys/{key_id}.json')
with open(key_file) as f:
    key_data = json.load(f)

key = base64.b64decode(key_data['key'])

# Test data
test_message = b"Hello, Scrambled Eggs! This is a test message."
print(f"Original: {{test_message}}")

# Encrypt
iv = os.urandom(16)
cipher = Cipher(
    algorithms.AES(key),
    modes.GCM(iv),
    backend=default_backend()
)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(test_message) + encryptor.finalize()
tag = encryptor.tag

print(f"Encrypted: {{ciphertext.hex()}}")

# Decrypt
cipher = Cipher(
    algorithms.AES(key),
    modes.GCM(iv, tag),
    backend=default_backend()
)
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()

print(f"Decrypted: {{decrypted}}")

if decrypted == test_message:
    print("✅ Encryption test passed!")
else:
    print("❌ Encryption test failed!")
"""
        with open(test_script, 'w', encoding='utf-8') as f:
            f.write(test_code)
        
        # Make the test script executable
        os.chmod(test_script, 0o700)
        
        print("\n✅ Encryption system set up successfully!")
        print("\n=== IMPORTANT INFORMATION ===")
        print(f"Key ID: {key_id}")
        print(f"Key file: {key_file}")
        print(f"Backup file: {backup_file}")
        print("\n=== NEXT STEPS ===")
        print("1. Securely store the backup file in a safe location")
        print("2. Test the encryption system by running:")
        print(f"   python {test_script}")
        print("3. Add the following to your .env file:")
        print(f"   ENCRYPTION_KEY_ID={key_id}")
        print("   ENCRYPTION_KEY_PATH=data/keys")
        print("\n⚠️  WARNING: Keep your encryption key safe! If lost, encrypted data cannot be recovered.")
        
        return True
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Failed to set up encryption: {e}\n{error_details}")
        return False

if __name__ == "__main__":
    try:
        import base64
        if not setup_encryption():
            print("\n❌ Failed to set up encryption. Check the logs for details.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)

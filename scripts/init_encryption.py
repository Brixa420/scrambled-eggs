"""
Initialize encryption for Scrambled Eggs application.

This script sets up the necessary encryption keys and configuration
for the Scrambled Eggs application.
"""
import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(project_root / 'encryption_init.log')
    ]
)
logger = logging.getLogger(__name__)

def initialize_encryption():
    """Initialize the encryption system."""
    try:
        logger.info("Initializing encryption system...")
        
        # Create necessary directories
        data_dir = project_root / 'data'
        keys_dir = data_dir / 'keys'
        
        for directory in [data_dir, keys_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
        
        # Initialize the database
        from app.db.database import init_db
        init_db()
        logger.info("Database initialized")
        
        # Set up encryption keys
        from app.services.key_service import key_service
        from getpass import getpass
        
        # Get master key from environment or prompt
        master_key = os.environ.get('MASTER_ENCRYPTION_KEY')
        if not master_key:
            print("\n=== Encryption Key Setup ===")
            print("Enter a strong master encryption key (at least 32 characters):")
            master_key = getpass("Master key: ").strip()
            
            if len(master_key) < 32:
                logger.error("Master key must be at least 32 characters long")
                return False
        
        # Generate a new encryption key
        encrypted_key, key_id = key_service.create_key(master_key.encode())
        logger.info(f"Generated new encryption key: {key_id}")
        
        # Save the master key hash (in production, use a proper key management system)
        import hashlib
        master_key_hash = hashlib.sha256(master_key.encode()).hexdigest()
        
        config_path = data_dir / 'encryption_config.json'
        with open(config_path, 'w') as f:
            import json
            json.dump({
                'master_key_hash': master_key_hash,
                'current_key_id': key_id,
                'key_storage': str(keys_dir.absolute())
            }, f, indent=2)
        
        logger.info(f"Encryption configuration saved to {config_path}")
        logger.info("Encryption system initialized successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize encryption: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    print("=== Scrambled Eggs Encryption Initialization ===\n")
    
    if initialize_encryption():
        print("\n✅ Encryption system initialized successfully!")
        print("\nNext steps:")
        print("1. Securely store your master encryption key")
        print("2. Restart your application to use the new encryption settings")
        print("\n⚠️  WARNING: Keep your master key safe! If you lose it, you won't be able to decrypt your data!")
    else:
        print("\n❌ Failed to initialize encryption. Check the logs for details.")
        sys.exit(1)

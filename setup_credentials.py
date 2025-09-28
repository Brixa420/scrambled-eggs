#!/usr/bin/env python3
"""
Script to set up initial credentials for Scrambled Eggs.
"""
import os
import sys
import logging
import time
from pathlib import Path
from scrambled_eggs.key_management import KeyManager, User

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_credentials():
    """Set up the initial user credentials."""
    try:
        # Initialize key manager
        key_manager = KeyManager()
        
        # Check if users already exist
        if key_manager._users:
            logger.warning("Users already exist in the key manager. This will update existing users.")
            
        # Create/update the Luna user
        user = key_manager.create_user(
            user_id="Luna",
            password="UrielTheArchangel2025",
            attributes={
                "email": "luna@example.com",
                "role": "admin"
            }
        )
        
        # Save the changes
        key_manager._save_keys()
        
        logger.info("Successfully set up credentials:")
        logger.info(f"  - Username: Luna")
        logger.info(f"  - Master Password: UrielTheArchangel2025")
        logger.info("\nIMPORTANT: Please change the password after first login!")
        
    except Exception as e:
        logger.error(f"Failed to set up credentials: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(setup_credentials())

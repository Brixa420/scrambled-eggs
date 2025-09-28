"""
Hardware Security Module (HSM) Interface

This module provides a unified interface for interacting with various HSM implementations,
including cloud HSMs, smart cards, and hardware security tokens.
"""
import sys
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Type, TypeVar, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the project root to the Python path to support direct execution
project_root = str(Path(__file__).parent.parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def _import_module(module_name: str):
    """Helper to import a module with better error messages."""
    try:
        return __import__(module_name, fromlist=['*'])
    except ImportError as e:
        logger.error(f"Failed to import {module_name}: {e}")
        raise

# Import core types
try:
    from .types import HSMType, KeyType, KeyUsage, HSMKey, HSMInterface
except ImportError as e:
    logger.error("Failed to import HSM types. Make sure the package is properly installed.")
    raise

# Import compliance modules
try:
    from .compliance import (
        ComplianceManager,
        ComplianceModule,
        ComplianceRequirement,
        ComplianceStatus,
        FIPS140_3,
        CommonCriteria,
        SecurityAudit
    )
    
    # Import specific HSM implementations
    from .cloud import CloudHSMClient
    from .smartcard import SmartCardManager
    from .pkcs11 import PKCS11Interface
    from .tpm import TPMInterface
    
except ImportError as e:
    logger.error(f"Failed to import HSM modules: {e}")
    logger.info("Some HSM implementations may not be available.")
    # Set default values to None for optional imports
    ComplianceManager = ComplianceModule = ComplianceRequirement = None
    ComplianceStatus = FIPS140_3 = CommonCriteria = SecurityAudit = None
    CloudHSMClient = SmartCardManager = PKCS11Interface = TPMInterface = None

# Define __all__ to explicitly export public API
__all__ = [
    # Core classes
    'HSMInterface',
    'HSMKey',
    'HSMFactory',
    'KeyType',
    'KeyUsage',
    'HSMType',
    
    # Compliance
    'ComplianceManager',
    'ComplianceModule',
    'ComplianceRequirement',
    'ComplianceStatus',
    'FIPS140_3',
    'CommonCriteria',
    'SecurityAudit',
    
    # HSM Implementations
    'CloudHSMClient',
    'SmartCardManager',
    'PKCS11Interface',
    'TPMInterface'
]

class HSMFactory:
    """Factory for creating HSM instances."""
    
    @staticmethod
    def create_hsm(hsm_type: Union[str, HSMType], config: Dict[str, Any] = None) -> HSMInterface:
        """
        Create an HSM instance of the specified type.
        
        Args:
            hsm_type: Type of HSM to create
            config: Configuration for the HSM
            
        Returns:
            An instance of the specified HSM type
        """
        if isinstance(hsm_type, str):
            try:
                hsm_type = HSMType[hsm_type.upper()]
            except KeyError as e:
                raise ValueError(f"Unknown HSM type: {hsm_type}") from e
        
        if hsm_type == HSMType.CLOUD_KMS:
            return CloudHSMClient(config or {})
        elif hsm_type == HSMType.PKCS11:
            return PKCS11Interface(config or {})
        elif hsm_type == HSMType.TPM:
            return TPMInterface(config or {})
        elif hsm_type == HSMType.SMART_CARD:
            return SmartCardManager(config or {})
        else:
            raise ValueError(f"Unsupported HSM type: {hsm_type}")

import asyncio
import platform

# Console output utilities that work with Windows
class ConsoleOutput:
    CHECK = '[OK]' if platform.system() == 'Windows' else '✓'
    WARN = '[WARN]' if platform.system() == 'Windows' else '⚠️'
    FAIL = '[FAIL]' if platform.system() == 'Windows' else '❌'
    
    @classmethod
    def print_success(cls, message):
        print(f"  {cls.CHECK} {message}")
        
    @classmethod
    def print_warning(cls, message):
        print(f"  {cls.WARN} {message}")
        
    @classmethod
    def print_error(cls, message):
        print(f"  {cls.FAIL} {message}")

async def test_hsm_async():
    """Asynchronous test function for HSM functionality."""
    # Test configuration
    config = {
        'cloud': {
            'provider': 'aws_kms',
            'region': 'us-east-1'
        },
        'pkcs11': {
            'library': '/path/to/pkcs11.so',
            'slot': 0,
            'pin': '1234'
        },
        'tpm': {
            'device': '/dev/tpm0'
        },
        'smartcard': {
            'reader': 'SCM Microsystems Inc. SCR 3310 [CCID Interface] 00 00',
            'pin': '1234'
        }
    }
    
    # Test each HSM type
    for hsm_type in HSMType:
        try:
            print(f"\nTesting {hsm_type.name}...")
            hsm = HSMFactory.create_hsm(hsm_type, config.get(hsm_type.name.lower(), {}))
            
            # Initialize and connect
            try:
                if await hsm.initialize():
                    await hsm.connect()
                    
                    # Test key operations
                    key_id = f"test_key_{hsm_type.name.lower()}"
                    key = await hsm.create_key(
                        key_type=KeyType.AES,
                        key_size=256,
                        key_id=key_id,
                        label=f"Test Key {hsm_type.name}",
                        tags={"purpose": "testing"}
                    )
                    
                    if key:
                        ConsoleOutput.print_success(f"Created key: {key.key_id}")
                        
                        # Test encryption/decryption if supported
                        if hasattr(key, 'allowed_operations') and \
                           KeyUsage.ENCRYPT in key.allowed_operations and \
                           KeyUsage.DECRYPT in key.allowed_operations:
                            
                            plaintext = b"Test message for encryption"
                            try:
                                ciphertext = await hsm.encrypt(key_id, plaintext)
                                decrypted = await hsm.decrypt(key_id, ciphertext)
                                assert decrypted == plaintext, "Decryption failed"
                                ConsoleOutput.print_success("Encryption/decryption test passed")
                            except Exception as e:
                                ConsoleOutput.print_warning(f"Encryption/decryption test failed: {e}")
                        
                        # Clean up
                        try:
                            await hsm.delete_key(key_id)
                            ConsoleOutput.print_success("Cleaned up test key")
                        except Exception as e:
                            ConsoleOutput.print_warning(f"Failed to clean up key: {e}")
                    
                    await hsm.disconnect()
                    ConsoleOutput.print_success(f"{hsm_type.name} tests completed successfully")
                else:
                    ConsoleOutput.print_warning(f"Failed to initialize {hsm_type.name}")
                    
            except Exception as e:
                ConsoleOutput.print_error(f"Error during {hsm_type.name} test: {str(e)}")
                # Try to clean up if there was an error
                try:
                    if 'hsm' in locals():
                        await hsm.disconnect()
                except:
                    pass
                
        except Exception as e:
            ConsoleOutput.print_error(f"Failed to create {hsm_type.name} HSM: {str(e)}")

def test_hsm():
    """Synchronous wrapper for the async test function."""
    asyncio.run(test_hsm_async())

# Example usage
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("scrambled_eggs.hsm")
    
    try:
        # Run the test function
        test_hsm()
    except Exception as e:
        logger.error(f"Error running HSM test: {e}", exc_info=True)
        raise

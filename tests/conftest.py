"""
Test configuration and fixtures for the Enterprise HSM tests.
"""
import os
import sys
import asyncio
import pytest
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('test.log')
    ]
)

# Set up test logger
logger = logging.getLogger(__name__)

# Fixtures
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="module")
def test_config():
    """Return a test configuration dictionary."""
    return {
        'hsm': {
            'provider': 'aws_kms',
            'aws': {
                'region': 'us-west-2',
                'access_key_id': 'test-access-key',
                'secret_access_key': 'test-secret-key'
            }
        },
        'enterprise': {
            'integrations': {
                'active_directory': {
                    'type': 'active_directory',
                    'server': 'ldap://test-ad.example.com',
                    'domain': 'TEST',
                    'username': 'test-user',
                    'password': 'test-password',
                    'use_ssl': True
                },
                'siem': {
                    'type': 'elasticsearch',
                    'hosts': ['http://localhost:9200'],
                    'username': 'elastic',
                    'password': 'password',
                    'use_ssl': False
                }
            }
        },
        'cluster': {
            'sharding_strategy': 'hash',
            'load_balancing_strategy': 'round_robin',
            'redis_url': 'redis://localhost:6379/0',
            'replication_factor': 2,
            'auto_rebalance': True
        },
        'backup': {
            'provider': 'local',
            'location': '/tmp/hsm-backups',
            'retention_days': 7,
            'compression': True,
            'max_backups': 5,
            'schedule': '0 0 * * *',
            'rpo': 'daily',
            'rto': 'hourly'
        }
    }

@pytest.fixture(scope="module")
def mock_hsm_client():
    """Return a mock HSM client for testing."""
    class MockCloudHSMClient:
        def __init__(self, config=None):
            self.config = config or {}
            self.keys = {}
            self.connected = False
        
        async def connect(self):
            self.connected = True
            return True
        
        async def create_key(self, key_type, key_size=None, key_id=None, **kwargs):
            if not self.connected:
                raise RuntimeError("Not connected to HSM")
            
            key_id = key_id or f"key-{len(self.keys) + 1}"
            key = {
                'key_id': key_id,
                'key_type': key_type,
                'key_size': key_size,
                'created_at': '2023-01-01T00:00:00Z',
                'enabled': True,
                'description': kwargs.get('description', ''),
                'tags': kwargs.get('tags', {})
            }
            
            self.keys[key_id] = key
            return key
        
        async def encrypt(self, key_id, plaintext, **kwargs):
            if not self.connected:
                raise RuntimeError("Not connected to HSM")
            
            if key_id not in self.keys:
                raise ValueError(f"Key {key_id} not found")
            
            # Simple XOR encryption for testing
            key = self.keys[key_id]
            key_bytes = key['key_id'].encode()
            encrypted = bytearray()
            
            for i in range(len(plaintext)):
                encrypted.append(plaintext[i] ^ key_bytes[i % len(key_bytes)])
            
            return bytes(encrypted)
        
        async def decrypt(self, key_id, ciphertext, **kwargs):
            # Decryption is the same as encryption for XOR
            return await self.encrypt(key_id, ciphertext, **kwargs)
        
        async def close(self):
            self.connected = False
    
    return MockCloudHSMClient()

@pytest.fixture(scope="module")
def enterprise_hsm(test_config, mock_hsm_client):
    """Return an EnterpriseHSM instance with a mock HSM client."""
    from scrambled_eggs.hsm.enterprise_hsm import EnterpriseHSM
    
    # Create the enterprise HSM client
    hsm = EnterpriseHSM(test_config)
    
    # Replace the HSM client with our mock
    hsm._hsm_client = mock_hsm_client
    
    return hsm

# Plugin to add command line options
def pytest_addoption(parser):
    """Add custom command line options for pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests"
    )
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests"
    )

def pytest_configure(config):
    """Configure pytest based on command line options."""
    # Register custom markers
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow to run"
    )
    config.addinivalue_line(
        "markers",
        "integration: mark test as an integration test"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection based on command line options."""
    skip_slow = not config.getoption("--run-slow")
    skip_integration = not config.getoption("--integration")
    
    skip_marker = {
        "slow": skip_slow,
        "integration": skip_integration
    }
    
    for item in items:
        for marker in skip_marker:
            if marker in item.keywords and skip_marker[marker]:
                item.add_marker(pytest.mark.skip(reason=f"need --{marker} option to run"))

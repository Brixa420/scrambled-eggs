"""
Configuration for the Tor manager.
"""
import os
from pathlib import Path
from typing import Optional, Dict, Any

from app.config import DATA_DIR, CONFIG_DIR, LOG_DIR

# Default Tor configuration
DEFAULT_TOR_CONFIG = {
    # Network settings
    'control_port': 9051,  # Tor control port
    'socks_port': 9050,    # Tor SOCKS port
    
    # Paths
    'tor_data_dir': str(Path(DATA_DIR) / 'tor'),
    'tor_log_file': str(Path(LOG_DIR) / 'tor.log'),
    'tor_rc_file': str(Path(CONFIG_DIR) / 'torrc'),
    
    # Authentication
    'password': None,  # Set to None for cookie authentication
    'hashed_control_password': None,  # Will be generated if password is set
    
    # Circuit settings
    'circuit_timeout': 600,  # 10 minutes
    'max_circuit_dirtiness': 3600,  # 1 hour
    'max_circuits_per_purpose': 3,
    
    # Performance
    'num_circuits': 3,
    'socks_timeout': 30,  # seconds
    'control_timeout': 10,  # seconds
    
    # Metrics and monitoring
    'enable_metrics': True,
    'metrics_db_url': f'sqlite:///{Path(DATA_DIR) / "tor_metrics.db"}',
    'metrics_interval': 60,  # seconds
    
    # Web dashboard
    'enable_dashboard': True,
    'dashboard_host': '127.0.0.1',
    'dashboard_port': 8050,
    
    # Logging
    'log_level': 'INFO',
    'log_file': str(Path(LOG_DIR) / 'tor_manager.log'),
    
    # Advanced settings
    'use_bridges': False,
    'bridges': [],
    'exit_nodes': None,  # Comma-separated list of country codes
    'exclude_nodes': None,  # Comma-separated list of country codes
    'strict_nodes': False,
    'geoip_file': None,
    'geoip6_file': None,
}

def get_tor_config(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get the Tor configuration with overrides.
    
    Args:
        overrides: Dictionary of configuration overrides
        
    Returns:
        Dictionary with the final configuration
    """
    config = DEFAULT_TOR_CONFIG.copy()
    
    # Apply environment variable overrides
    for key in config.keys():
        env_key = f'SCRAMBLED_EGGS_TOR_{key.upper()}'
        if env_key in os.environ:
            # Convert string values to appropriate types
            value = os.environ[env_key]
            if isinstance(config[key], bool):
                value = value.lower() in ('true', '1', 'yes', 'y')
            elif isinstance(config[key], int):
                value = int(value)
            elif isinstance(config[key], float):
                value = float(value)
            config[key] = value
    
    # Apply direct overrides
    if overrides:
        config.update(overrides)
    
    # Ensure directories exist
    for dir_key in ['tor_data_dir', 'log_file', 'metrics_db_url']:
        if dir_key in config and config[dir_key]:
            path = Path(config[dir_key].replace('sqlite:///', ''))
            if dir_key == 'metrics_db_url':
                path = path.parent
            path.mkdir(parents=True, exist_ok=True)
    
    # Generate hashed password if needed
    if config['password'] and not config['hashed_control_password']:
        from hashlib import sha1
        import base64
        digest = sha1(config['password'].encode('utf-8')).digest()
        config['hashed_control_password'] = f"16:{base64.b64encode(digest).decode('utf-8')}"
    
    return config

def configure_logging(config: Dict[str, Any]) -> None:
    """Configure logging for the Tor manager.
    
    Args:
        config: Tor configuration dictionary
    """
    import logging
    from logging.handlers import RotatingFileHandler
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    logger = logging.getLogger('tor')
    logger.setLevel(config['log_level'].upper())
    
    # Add file handler
    file_handler = RotatingFileHandler(
        config['log_file'],
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

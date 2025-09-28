"""
Scrambled Eggs - A self-modifying encryption system for device protection
"""

__version__ = '1.0.0'
__author__ = 'Scrambled Eggs Team'
__license__ = 'MIT'

from .core import ScrambledEggs
from .file_handler import FileHandler
from .cli import main
from .service import SecurityService, run_as_service as run_service
from .tray_icon import ScrambledEggsTray, run_tray_app
from .adaptive_encryption import AdaptiveEncryption
from .antartica_routing import (
    AntarcticaRouter,
    get_antartica_router,
    set_antartica_routing,
    close_antartica_router
)

from .exceptions import (
    ScrambledEggsError,
    EncryptionError,
    DecryptionError,
    BreachDetected,
)
from .file_handler import encrypt_file, decrypt_file

__all__ = [
    'ScrambledEggs',
    'AdaptiveEncryption',
    'encrypt_file',
    'decrypt_file',
    'ScrambledEggsError',
    'EncryptionError',
    'DecryptionError',
    'BreachDetected',
    'AntarcticaRouter',
    'get_antartica_router',
    'set_antartica_routing',
    'close_antartica_router'
]

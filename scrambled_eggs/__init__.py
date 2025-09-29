"""
Scrambled Eggs - A self-modifying encryption system for device protection
"""

__version__ = "1.0.0"
__author__ = "Scrambled Eggs Team"
__license__ = "MIT"

from .adaptive_encryption import AdaptiveEncryption
from .antartica_routing import (
    AntarcticaRouter,
    close_antartica_router,
    get_antartica_router,
    set_antartica_routing,
)
from .cli import main
from .core import ScrambledEggs
from .exceptions import (
    BreachDetected,
    DecryptionError,
    EncryptionError,
    ScrambledEggsError,
)
from .file_handler import FileHandler, decrypt_file, encrypt_file
from .service import SecurityService
from .service import run_as_service as run_service
from .tray_icon import ScrambledEggsTray, run_tray_app

__all__ = [
    "ScrambledEggs",
    "AdaptiveEncryption",
    "encrypt_file",
    "decrypt_file",
    "ScrambledEggsError",
    "EncryptionError",
    "DecryptionError",
    "BreachDetected",
    "AntarcticaRouter",
    "get_antartica_router",
    "set_antartica_routing",
    "close_antartica_router",
]

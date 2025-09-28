"""
Crypto instance initialization.
This module is used to break circular imports by providing a way to access the crypto instance.
"""
from .scrambled_eggs_crypto import ScrambledEggsCrypto

# Create a single instance of ScrambledEggsCrypto
crypto = ScrambledEggsCrypto()

"""
Cryptographic utility functions for the Brixa blockchain.
"""
import hashlib
from typing import List, Union
import base58

def calculate_merkle_root(tx_hashes: List[str]) -> str:
    """
    Calculate the Merkle root from a list of transaction hashes.
    
    Args:
        tx_hashes: List of transaction hashes
        
    Returns:
        str: The Merkle root as a hexadecimal string
    """
    if not tx_hashes:
        return hashlib.sha256().hexdigest()
    
    # Convert all hashes to bytes
    hashes = [bytes.fromhex(h) for h in tx_hashes]
    
    while len(hashes) > 1:
        # If odd number of hashes, duplicate the last one
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
            
        new_hashes = []
        for i in range(0, len(hashes), 2):
            # Concatenate and hash pairs of hashes
            combined = hashes[i] + hashes[i+1]
            new_hash = hashlib.sha256(hashlib.sha256(combined).digest()).digest()
            new_hashes.append(new_hash)
            
        hashes = new_hashes
    
    return hashes[0].hex()

def hash160(data: bytes) -> bytes:
    """
    Calculate RIPEMD160(SHA256(data)).
    
    Args:
        data: Input data to hash
        
    Returns:
        bytes: The hash160 digest
    """
    sha256 = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256).digest()

def double_sha256(data: bytes) -> bytes:
    """
    Calculate SHA256(SHA256(data)).
    
    Args:
        data: Input data to hash
        
    Returns:
        bytes: The double SHA-256 digest
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def base58_encode(data: bytes) -> str:
    """
    Encode data in Base58.
    
    Args:
        data: Data to encode
        
    Returns:
        str: Base58 encoded string
    """
    return base58.b58encode(data).decode('utf-8')

def base58_decode(data: str) -> bytes:
    """
    Decode data from Base58.
    
    Args:
        data: Base58 encoded string
        
    Returns:
        bytes: Decoded data
    """
    return base58.b58decode(data)

def sign_message(private_key: bytes, message: bytes) -> bytes:
    """
    Sign a message with a private key.
    
    Args:
        private_key: Private key bytes
        message: Message to sign
        
    Returns:
        bytes: Signature
    """
    from ecdsa import SigningKey, SECP256k1
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    return sk.sign_deterministic(message, hashfunc=hashlib.sha256)

def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """
    Verify a signature.
    
    Args:
        public_key: Public key bytes
        signature: Signature to verify
        message: Original message
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
    try:
        vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
        return vk.verify(signature, message, hashfunc=hashlib.sha256)
    except (BadSignatureError, Exception):
        return False

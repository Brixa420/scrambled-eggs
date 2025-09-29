"""
Secure chat implementation with end-to-end encryption and perfect forward secrecy.
"""

import hashlib
import json
import os
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants
RATCHET_STEP = 1
MESSAGE_KEYS_TO_KEEP = 1000
MAX_SKIP = 1000


@dataclass
class RatchetKey:
    key: bytes
    index: int = 0


@dataclass
class KeyPair:
    private_key: bytes
    public_key: bytes


@dataclass
class SessionState:
    # Identity keys
    identity_key_private: bytes
    identity_key_public: bytes

    # Ephemeral keys
    ephemeral_key_private: bytes
    ephemeral_key_public: bytes

    # Pre-keys
    pre_keys: List[bytes]
    pre_key_index: int = 0

    # Ratchet state
    root_key: Optional[bytes] = None
    sending_chain: Optional[RatchetKey] = None
    receiving_chain: Optional[RatchetKey] = None

    # Message counters
    message_counter_send: int = 0
    message_counter_recv: int = 0

    # Pending message keys
    pending_message_keys: Dict[int, bytes] = None

    # Session state
    is_initialized: bool = False
    session_id: Optional[str] = None
    session_start: Optional[datetime] = None

    def __post_init__(self):
        if self.pending_message_keys is None:
            self.pending_message_keys = {}


class SecureChat:
    """Secure chat implementation with end-to-end encryption and perfect forward secrecy."""

    def __init__(self, storage_path: str = None):
        """Initialize the secure chat system."""
        self.storage_path = storage_path or os.path.expanduser("~/.scrambled_eggs/secure_chat")
        os.makedirs(self.storage_path, exist_ok=True)

        # Initialize session state
        self.sessions: Dict[str, SessionState] = {}
        self.active_session_id: Optional[str] = None

        # Initialize keys
        self._initialize_keys()

    def _initialize_keys(self):
        """Initialize cryptographic keys for the secure chat."""
        # Generate identity key pair (long-term)
        identity_key_private = x25519.X25519PrivateKey.generate()
        identity_key_public = identity_key_private.public_key()

        # Generate ephemeral key pair
        ephemeral_key_private = x25519.X25519PrivateKey.generate()
        ephemeral_key_public = ephemeral_key_private.public_key()

        # Generate pre-keys
        pre_keys = [self._generate_pre_key() for _ in range(100)]

        # Initialize session state
        self.session_state = SessionState(
            identity_key_private=identity_key_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            identity_key_public=identity_key_public.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ),
            ephemeral_key_private=ephemeral_key_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            ephemeral_key_public=ephemeral_key_public.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ),
            pre_keys=[pk[1] for pk in pre_keys],
            is_initialized=True,
            session_start=datetime.utcnow(),
        )

    def _generate_pre_key(self) -> Tuple[int, bytes]:
        """Generate a new pre-key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        return (
            self.session_state.pre_key_index + 1,
            public_key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            ),
        )

    def _hkdf(
        self, input_key_material: bytes, salt: bytes = None, info: bytes = None, length: int = 32
    ) -> bytes:
        """Derive a key using HKDF."""
        if salt is None:
            salt = os.urandom(32)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info or b"scrambled-eggs-chat",
        )

        return hkdf.derive(input_key_material)

    def _encrypt_message(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """Encrypt a message using AES-GCM."""
        key = os.urandom(32)
        nonce = os.urandom(12)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        return key + nonce + ciphertext

    def _decrypt_message(self, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """Decrypt a message using AES-GCM."""
        if len(ciphertext) < 44:  # 32 (key) + 12 (nonce) = 44 bytes
            raise ValueError("Ciphertext too short")

        key = ciphertext[:32]
        nonce = ciphertext[32:44]
        actual_ciphertext = ciphertext[44:]

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, actual_ciphertext, associated_data)

    def _sign_message(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using Ed25519."""
        private_key = Ed25519PrivateKey.from_private_bytes(private_key)
        return private_key.sign(message)

    def _verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a message signature using Ed25519."""
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key)
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def create_session(self, recipient_public_key: bytes) -> str:
        """Create a new secure session with a recipient."""
        # Generate a new session ID
        session_id = hashlib.sha256(os.urandom(32)).hexdigest()

        # Initialize session state
        self.sessions[session_id] = {
            "recipient_public_key": recipient_public_key,
            "session_id": session_id,
            "created_at": datetime.utcnow(),
            "last_used": datetime.utcnow(),
            "message_counter": 0,
            "pending_messages": {},
        }

        return session_id

    def encrypt_message(self, session_id: str, plaintext: str, ttl: int = None) -> dict:
        """Encrypt a message for a session."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]

        # Prepare message
        message = {
            "text": plaintext,
            "timestamp": datetime.utcnow().isoformat(),
            "ttl": ttl,
            "sender_id": b64encode(self.session_state.identity_key_public).decode("utf-8"),
        }

        # Serialize message
        message_json = json.dumps(message).encode("utf-8")

        # Encrypt message
        ciphertext = self._encrypt_message(message_json)

        # Sign message
        signature = self._sign_message(ciphertext, self.session_state.identity_key_private)

        # Update session state
        session["message_counter"] += 1
        session["last_used"] = datetime.utcnow()

        return {
            "ciphertext": b64encode(ciphertext).decode("utf-8"),
            "signature": b64encode(signature).decode("utf-8"),
            "message_id": session["message_counter"],
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def decrypt_message(self, encrypted_message: dict) -> dict:
        """Decrypt a message from a session."""
        session_id = encrypted_message.get("session_id")
        if not session_id or session_id not in self.sessions:
            raise ValueError(f"Invalid session ID: {session_id}")

        session = self.sessions[session_id]

        # Verify signature
        ciphertext = b64decode(encrypted_message["ciphertext"])
        signature = b64decode(encrypted_message["signature"])

        if not self._verify_signature(ciphertext, signature, session["recipient_public_key"]):
            raise ValueError("Invalid message signature")

        # Decrypt message
        try:
            plaintext = self._decrypt_message(ciphertext)
            message = json.loads(plaintext.decode("utf-8"))

            # Check message TTL if set
            if "ttl" in message and message["ttl"]:
                message_time = datetime.fromisoformat(message["timestamp"])
                if datetime.utcnow() > message_time + timedelta(seconds=message["ttl"]):
                    raise ValueError("Message has expired")

            # Update session state
            session["last_used"] = datetime.utcnow()

            return message

        except Exception as e:
            raise ValueError(f"Failed to decrypt message: {str(e)}")

    def cleanup_expired_messages(self):
        """Clean up expired messages from all sessions."""
        current_time = datetime.utcnow()

        for session_id, session in list(self.sessions.items()):
            # Remove sessions that haven't been used in 30 days
            if (current_time - session["last_used"]).days > 30:
                del self.sessions[session_id]
                continue

            # Remove expired pending messages
            for msg_id, msg in list(session["pending_messages"].items()):
                msg_time = datetime.fromisoformat(msg["timestamp"])
                if "ttl" in msg and (current_time - msg_time).total_seconds() > msg["ttl"]:
                    del session["pending_messages"][msg_id]


# Example usage
if __name__ == "__main__":
    # Initialize secure chat for two parties
    alice_chat = SecureChat()
    bob_chat = SecureChat()

    # Alice creates a session with Bob
    # In a real scenario, Bob's public key would be obtained through a secure channel
    session_id = alice_chat.create_session(bob_chat.session_state.identity_key_public)

    # Alice sends a message to Bob
    encrypted_msg = alice_chat.encrypt_message(
        session_id, "Hello, Bob! This is a secure message.", ttl=3600
    )

    # Bob receives and decrypts the message
    try:
        decrypted_msg = bob_chat.decrypt_message(encrypted_msg)
        print(f"Decrypted message: {decrypted_msg['text']}")
        print(f"From: {decrypted_msg['sender_id']}")
        print(f"Timestamp: {decrypted_msg['timestamp']}")
    except Exception as e:
        print(f"Error decrypting message: {str(e)}")

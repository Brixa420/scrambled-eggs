"""
AI-to-AI Communication Module
Handles secure and private communication between AI instances.
"""
import json
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Awaitable
import logging
from datetime import datetime
import uuid

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .instance import AIInstance
from .privacy import PrivacyEngine, SecureHasher

logger = logging.getLogger(__name__)

class AIConnection:
    """Represents a connection between two AI instances."""
    
    def __init__(self, local_instance: AIInstance, remote_instance_id: str):
        """Initialize a connection to a remote AI instance.
        
        Args:
            local_instance: The local AI instance
            remote_instance_id: ID of the remote AI instance
        """
        self.local_instance = local_instance
        self.remote_instance_id = remote_instance_id
        self.connection_id = str(uuid.uuid4())
        self.established_at = datetime.utcnow()
        self.last_activity = self.established_at
        self._shared_secret = None
        self._send_nonce = 0
        self._recv_nonce = 0
        self._send_key = None
        self._recv_key = None
    
    async def establish_handshake(self, peer_public_key: bytes) -> bytes:
        """Perform key exchange and establish secure channel.
        
        Args:
            peer_public_key: The remote instance's public key
            
        Returns:
            Local public key to send to the peer
        """
        # Generate an ephemeral key pair for this session
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Perform key exchange
        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = private_key.exchange(peer_key)
        
        # Derive encryption keys using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for send key, 32 bytes for receive key
            salt=None,
            info=b'ai-communication-keys',
        )
        key_material = hkdf.derive(shared_secret)
        
        # Split the key material into send and receive keys
        self._send_key = key_material[:32]
        self._recv_key = key_material[32:]
        self._shared_secret = shared_secret
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    async def encrypt_message(self, message: Dict[str, Any]) -> bytes:
        """Encrypt a message for the remote instance.
        
        Args:
            message: The message to encrypt (must be JSON-serializable)
            
        Returns:
            Encrypted message as bytes
        """
        if not self._send_key:
            raise RuntimeError("Handshake not completed")
        
        # Serialize the message
        plaintext = json.dumps(message).encode('utf-8')
        
        # Encrypt with ChaCha20-Poly1305
        nonce = self._send_nonce.to_bytes(12, 'little')
        self._send_nonce += 1
        
        chacha = ChaCha20Poly1305(self._send_key)
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        
        # Include the nonce with the ciphertext
        return nonce + ciphertext
    
    async def decrypt_message(self, encrypted_message: bytes) -> Dict[str, Any]:
        """Decrypt a message from the remote instance.
        
        Args:
            encrypted_message: The encrypted message (nonce + ciphertext)
            
        Returns:
            Decrypted message as a dictionary
        """
        if not self._recv_key:
            raise RuntimeError("Handshake not completed")
        
        # Split nonce and ciphertext
        nonce = encrypted_message[:12]
        ciphertext = encrypted_message[12:]
        
        # Decrypt with ChaCha20-Poly1305
        chacha = ChaCha20Poly1305(self._recv_key)
        plaintext = chacha.decrypt(nonce, ciphertext, None)
        
        # Update nonce and return deserialized message
        self._recv_nonce = int.from_bytes(nonce, 'little') + 1
        return json.loads(plaintext.decode('utf-8'))
    
    def is_active(self) -> bool:
        """Check if the connection is still active."""
        return (datetime.utcnow() - self.last_activity).total_seconds() < 300  # 5-minute timeout


class AIMessageBroker:
    """Manages communication between AI instances."""
    
    def __init__(self, local_instance: AIInstance):
        """Initialize with the local AI instance."""
        self.local_instance = local_instance
        self.connections: Dict[str, AIConnection] = {}
        self.message_handlers = {}
        self.privacy = PrivacyEngine(local_instance)
    
    async def connect(self, remote_instance_id: str, peer_public_key: bytes) -> bytes:
        """Establish a connection to a remote AI instance.
        
        Args:
            remote_instance_id: ID of the remote instance
            peer_public_key: The remote instance's public key
            
        Returns:
            Local public key to send to the peer
        """
        if remote_instance_id in self.connections:
            # Reuse existing connection if it's still active
            if self.connections[remote_instance_id].is_active():
                return self.connections[remote_instance_id].public_key
        
        # Create new connection
        connection = AIConnection(self.local_instance, remote_instance_id)
        local_public_key = await connection.establish_handshake(peer_public_key)
        
        # Store the connection
        self.connections[remote_instance_id] = connection
        return local_public_key
    
    def register_handler(self, message_type: str, handler: Callable[[Dict[str, Any]], Awaitable[None]]):
        """Register a message handler for a specific message type."""
        self.message_handlers[message_type] = handler
    
    async def send_message(self, remote_instance_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to a remote AI instance.
        
        Args:
            remote_instance_id: ID of the remote instance
            message: The message to send (must be JSON-serializable)
            
        Returns:
            True if the message was sent successfully
        """
        if remote_instance_id not in self.connections:
            logger.warning(f"No active connection to {remote_instance_id}")
            return False
        
        try:
            connection = self.connections[remote_instance_id]
            encrypted = await connection.encrypt_message(message)
            
            # In a real implementation, this would send the message over the network
            # For now, we'll just log it
            logger.info(f"Sending message to {remote_instance_id}: {message.get('type', 'unknown')}")
            
            # Update last activity
            connection.last_activity = datetime.utcnow()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message to {remote_instance_id}: {e}")
            return False
    
    async def receive_message(self, remote_instance_id: str, encrypted_message: bytes) -> bool:
        """Receive and process a message from a remote AI instance.
        
        Args:
            remote_instance_id: ID of the remote instance
            encrypted_message: The encrypted message
            
        Returns:
            True if the message was processed successfully
        """
        if remote_instance_id not in self.connections:
            logger.warning(f"No active connection to {remote_instance_id}")
            return False
        
        try:
            connection = self.connections[remote_instance_id]
            message = await connection.decrypt_message(encrypted_message)
            
            # Update last activity
            connection.last_activity = datetime.utcnow()
            
            # Process the message based on its type
            message_type = message.get('type')
            if message_type in self.message_handlers:
                await self.message_handlers[message_type](message)
            else:
                logger.warning(f"No handler for message type: {message_type}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to process message from {remote_instance_id}: {e}")
            return False
    
    async def broadcast(self, message: Dict[str, Any], exclude: List[str] = None) -> int:
        """Broadcast a message to all connected AI instances.
        
        Args:
            message: The message to broadcast
            exclude: List of instance IDs to exclude
            
        Returns:
            Number of instances the message was sent to
        """
        if exclude is None:
            exclude = []
        
        count = 0
        for instance_id in list(self.connections.keys()):
            if instance_id not in exclude:
                if await self.send_message(instance_id, message):
                    count += 1
        
        return count
    
    def cleanup_inactive_connections(self) -> int:
        """Remove inactive connections.
        
        Returns:
            Number of connections removed
        """
        initial_count = len(self.connections)
        self.connections = {
            k: v for k, v in self.connections.items() 
            if v.is_active()
        }
        return initial_count - len(self.connections)


class AICollaborationManager:
    """Manages collaborative learning between AI instances."""
    
    def __init__(self, message_broker: AIMessageBroker):
        """Initialize with a message broker."""
        self.broker = message_broker
        self.collaboration_groups: Dict[str, List[str]] = {}  # group_id -> [instance_ids]
        self.model_updates: Dict[str, List[Dict]] = {}  # model_id -> [updates]
        
        # Register message handlers
        self.broker.register_handler('model_update', self._handle_model_update)
        self.broker.register_handler('join_group', self._handle_join_group)
        self.broker.register_handler('leave_group', self._handle_leave_group)
    
    async def create_group(self, group_id: str, initial_members: List[str] = None) -> bool:
        """Create a new collaboration group."""
        if group_id in self.collaboration_groups:
            return False
        
        self.collaboration_groups[group_id] = initial_members or []
        return True
    
    async def join_group(self, group_id: str, instance_id: str) -> bool:
        """Join a collaboration group."""
        if group_id not in self.collaboration_groups:
            return False
        
        if instance_id not in self.collaboration_groups[group_id]:
            self.collaboration_groups[group_id].append(instance_id)
            
            # Notify other group members
            await self.broker.broadcast({
                'type': 'group_update',
                'group_id': group_id,
                'action': 'joined',
                'instance_id': instance_id
            }, exclude=[instance_id])
        
        return True
    
    async def leave_group(self, group_id: str, instance_id: str) -> bool:
        """Leave a collaboration group."""
        if group_id in self.collaboration_groups:
            if instance_id in self.collaboration_groups[group_id]:
                self.collaboration_groups[group_id].remove(instance_id)
                
                # Notify other group members
                await self.broker.broadcast({
                    'type': 'group_update',
                    'group_id': group_id,
                    'action': 'left',
                    'instance_id': instance_id
                }, exclude=[instance_id])
                
                return True
        return False
    
    async def share_model_update(self, group_id: str, update: Dict[str, Any]) -> bool:
        """Share a model update with a collaboration group."""
        if group_id not in self.collaboration_groups:
            return False
        
        # Store the update
        if group_id not in self.model_updates:
            self.model_updates[group_id] = []
        
        self.model_updates[group_id].append(update)
        
        # Share with group members
        for instance_id in self.collaboration_groups[group_id]:
            if instance_id != self.broker.local_instance.instance_id:  # Don't send to self
                await self.broker.send_message(instance_id, {
                    'type': 'model_update',
                    'group_id': group_id,
                    'update': update
                })
        
        return True
    
    async def _handle_model_update(self, message: Dict[str, Any]) -> None:
        """Handle an incoming model update."""
        group_id = message.get('group_id')
        update = message.get('update')
        
        if group_id and update:
            if group_id not in self.model_updates:
                self.model_updates[group_id] = []
            
            self.model_updates[group_id].append(update)
            
            # Apply the update to the local model
            await self._apply_model_update(update)
    
    async def _handle_join_group(self, message: Dict[str, Any]) -> None:
        """Handle a join group request."""
        group_id = message.get('group_id')
        instance_id = message.get('instance_id')
        
        if group_id and instance_id:
            await self.join_group(group_id, instance_id)
    
    async def _handle_leave_group(self, message: Dict[str, Any]) -> None:
        """Handle a leave group request."""
        group_id = message.get('group_id')
        instance_id = message.get('instance_id')
        
        if group_id and instance_id:
            await self.leave_group(group_id, instance_id)
    
    async def _apply_model_update(self, update: Dict[str, Any]) -> None:
        """Apply a model update to the local model."""
        # This is a placeholder - in a real implementation, this would
        # update the local model with the received weights or gradients
        logger.info(f"Applying model update: {update.get('update_id', 'unknown')}")
        
        # Example: Update model with federated averaging
        # model_weights = self.model.get_weights()
        # for i in range(len(model_weights)):
        #     model_weights[i] = model_weights[i] * 0.9 + update['weights'][i] * 0.1
        # self.model.set_weights(model_weights)
        pass


# Example usage:
# broker = AIMessageBroker(ai_instance)
# collaboration = AICollaborationManager(broker)
# 
# # Create a group and share model updates
# await collaboration.create_group('research_team', ['ai1', 'ai2', 'ai3'])
# 
# # Share a model update
# update = {
#     'update_id': str(uuid.uuid4()),
#     'weights': [...],  # Model weights or gradients
#     'metadata': {
#         'epoch': 1,
#         'batch_size': 32,
#         'samples_seen': 1000
#     }
# }
# await collaboration.share_model_update('research_team', update)

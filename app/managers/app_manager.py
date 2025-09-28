"""
Application manager that coordinates between different components.
"""
import logging
from typing import Optional, Dict, Any

from app.managers.contact_manager import ContactManager
from app.managers.message_manager import MessageManager
from app.managers.call_manager import CallManager
from app.managers.file_transfer_manager import FileTransferManager
from app.managers.group_manager import GroupManager
from app.network.p2p_manager import P2PManager
from app.security.crypto_engine import CryptoEngine
from app.security.self_modifying import SelfModifyingEncryption, SecurityLevel

class AppManager:
    """Manages the application state and coordinates between components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the application manager."""
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.running = False
        
        # Initialize security components
        self.crypto_engine = CryptoEngine()
        self.security_manager = SelfModifyingEncryption(
            initial_level=SecurityLevel.MEDIUM
        )
        
        # Initialize managers
        self.contact_manager = ContactManager()
        self.message_manager = MessageManager()
        self.call_manager = CallManager()
        self.file_transfer_manager = FileTransferManager()
        self.group_manager = GroupManager()
        
        # Initialize network
        self.p2p_manager = P2PManager(
            crypto_engine=self.crypto_engine,
            message_callback=self._handle_incoming_message,
            call_callback=self._handle_incoming_call,
            file_callback=self._handle_file_transfer
        )
        
        self.logger.info("Application manager initialized")
    
    def start(self) -> bool:
        """Start the application."""
        if self.running:
            self.logger.warning("Application is already running")
            return False
            
        try:
            # Start network components
            self.p2p_manager.start()
            
            self.running = True
            self.logger.info("Application started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start application: {str(e)}")
            self.stop()
            return False
    
    def stop(self) -> None:
        """Stop the application."""
        if not self.running:
            return
            
        try:
            # Stop network components
            self.p2p_manager.stop()
            
            # Save state
            self._save_state()
            
            self.running = False
            self.logger.info("Application stopped")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}")
    
    def _handle_incoming_message(self, message: Dict[str, Any]) -> None:
        """Handle incoming message from network."""
        try:
            # Verify message signature
            if not self.crypto_engine.verify_message(
                message['content'].encode(),
                message['signature'],
                message['sender_public_key']
            ):
                self.logger.warning(f"Invalid message signature from {message['sender_id']}")
                return
                
            # Process message based on type
            if message['type'] == 'text':
                self.message_manager.add_message(
                    message_id=message['message_id'],
                    sender_id=message['sender_id'],
                    recipient_id=message['recipient_id'],
                    content=message['content'],
                    message_type='text',
                    timestamp=message['timestamp']
                )
                
                # Notify UI
                self._notify_ui('new_message', {
                    'message': message,
                    'unread_count': self.message_manager.get_unread_count(message['recipient_id'])
                })
                
            elif message['type'] == 'file':
                # Handle file transfer
                self.file_transfer_manager.handle_incoming_file(message)
                
        except Exception as e:
            self.logger.error(f"Error handling incoming message: {str(e)}")
    
    def _handle_incoming_call(self, call_data: Dict[str, Any]) -> None:
        """Handle incoming call."""
        try:
            self.call_manager.handle_incoming_call(call_data)
        except Exception as e:
            self.logger.error(f"Error handling incoming call: {str(e)}")
    
    def _handle_file_transfer(self, file_data: Dict[str, Any]) -> None:
        """Handle incoming file transfer."""
        try:
            self.file_transfer_manager.handle_incoming_file(file_data)
        except Exception as e:
            self.logger.error(f"Error handling file transfer: {str(e)}")
    
    def _save_state(self) -> None:
        """Save application state."""
        try:
            # Save contacts, messages, etc.
            pass
        except Exception as e:
            self.logger.error(f"Error saving application state: {str(e)}")
    
    def _notify_ui(self, event_type: str, data: Dict[str, Any]) -> None:
        """Notify UI about an event."""
        # This would be connected to the UI update mechanism
        pass
    
    def send_message(self, recipient_id: str, content: str) -> bool:
        """Send a message to a contact."""
        try:
            # Encrypt message
            encrypted_content = self.crypto_engine.encrypt_message(
                content,
                recipient_public_key=self.contact_manager.get_public_key(recipient_id)
            )
            
            # Sign message
            signature = self.crypto_engine.sign_message(content)
            
            # Create message
            message = {
                'type': 'text',
                'message_id': self._generate_message_id(),
                'sender_id': self.user_id,
                'recipient_id': recipient_id,
                'content': encrypted_content,
                'timestamp': self._get_timestamp(),
                'signature': signature,
                'sender_public_key': self.crypto_engine.get_public_key()
            }
            
            # Send via P2P
            self.p2p_manager.send_message(recipient_id, message)
            
            # Store locally
            self.message_manager.add_message(
                message_id=message['message_id'],
                sender_id=message['sender_id'],
                recipient_id=message['recipient_id'],
                content=content,  # Store decrypted content locally
                message_type='text',
                timestamp=message['timestamp'],
                status='sent'
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send message: {str(e)}")
            return False
    
    def start_call(self, recipient_id: str, video_enabled: bool = False) -> bool:
        """Start a call with a contact."""
        return self.call_manager.start_call(recipient_id, video_enabled)
    
    def send_file(self, recipient_id: str, file_path: str) -> bool:
        """Send a file to a contact."""
        return self.file_transfer_manager.send_file(recipient_id, file_path)
    
    def create_group(self, name: str, members: list) -> str:
        """Create a new group chat."""
        return self.group_manager.create_group(name, members)
    
    @property
    def user_id(self) -> str:
        """Get the current user's ID."""
        # In a real app, this would come from the user's profile/account
        return self.config.get('user_id', 'local_user')
    
    def _generate_message_id(self) -> str:
        """Generate a unique message ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _get_timestamp(self) -> int:
        """Get current timestamp in milliseconds."""
        import time
        return int(time.time() * 1000)

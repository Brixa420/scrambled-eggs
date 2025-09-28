"""
Message Manager

Handles message-related operations including sending, receiving, and processing messages.
"""
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class MessageManager:
    """Manages message operations for the application."""
    
    def __init__(self):
        """Initialize the MessageManager."""
        self.messages: Dict[str, List[Dict[str, Any]]] = {}
        logger.info("MessageManager initialized")
    
    def send_message(self, recipient_id: str, message: str, **kwargs) -> bool:
        """
        Send a message to a recipient.
        
        Args:
            recipient_id: ID of the recipient
            message: The message content
            **kwargs: Additional message metadata
            
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        try:
            if recipient_id not in self.messages:
                self.messages[recipient_id] = []
                
            self.messages[recipient_id].append({
                'content': message,
                'timestamp': kwargs.get('timestamp'),
                'status': 'sent',
                **kwargs
            })
            logger.info(f"Message sent to {recipient_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False
    
    def get_messages(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all messages for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of message dictionaries
        """
        return self.messages.get(user_id, [])
    
    def mark_as_read(self, user_id: str, message_index: int) -> bool:
        """
        Mark a message as read.
        
        Args:
            user_id: ID of the user
            message_index: Index of the message to mark as read
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if user_id in self.messages and 0 <= message_index < len(self.messages[user_id]):
                self.messages[user_id][message_index]['status'] = 'read'
                return True
            return False
        except Exception as e:
            logger.error(f"Error marking message as read: {e}")
            return False

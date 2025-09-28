""
Message queue implementation for asynchronous message handling in the P2P network.
"""
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class QueuedMessage:
    """Represents a message in the queue with metadata."""
    message: Dict[str, Any]
    recipient_id: str
    priority: int = 1  # Higher number = higher priority
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_attempt: Optional[datetime] = None
    
    def should_retry(self) -> bool:
        """Determine if this message should be retried."""
        if self.retry_count >= self.max_retries:
            return False
            
        # Exponential backoff: 5s, 15s, 30s, etc.
        backoff = min(5 * (2 ** self.retry_count), 300)  # Max 5 minutes
        next_attempt = self.last_attempt + timedelta(seconds=backoff) if self.last_attempt else self.created_at
        return datetime.utcnow() >= next_attempt

class MessageQueue:
    """Asynchronous message queue for reliable message delivery."""
    
    def __init__(self, send_message_callback: Callable[[str, Dict[str, Any]], Awaitable[bool]]):
        """Initialize the message queue.
        
        Args:
            send_message_callback: Async function to actually send the message
        """
        self.queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.in_flight: Dict[str, QueuedMessage] = {}
        self.send_message = send_message_callback
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self._message_counter = 0
        
    async def start(self) -> None:
        """Start the message processing loop."""
        if self.running:
            return
            
        self.running = True
        self._task = asyncio.create_task(self._process_queue())
        logger.info("Message queue started")
        
    async def stop(self) -> None:
        """Stop the message processing loop."""
        if not self.running:
            return
            
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Message queue stopped")
        
    async def enqueue_message(
        self, 
        message: Dict[str, Any], 
        recipient_id: str, 
        priority: int = 1,
        max_retries: int = 3
    ) -> str:
        """Add a message to the queue.
        
        Args:
            message: The message to send
            recipient_id: ID of the recipient peer
            priority: Message priority (higher = higher priority)
            max_retries: Maximum number of delivery attempts
            
        Returns:
            str: A unique message ID
        """
        message_id = f"msg_{self._message_counter}"
        self._message_counter += 1
        
        queued = QueuedMessage(
            message=message,
            recipient_id=recipient_id,
            priority=priority,
            max_retries=max_retries
        )
        
        # Add to queue with priority (lower number = higher priority)
        await self.queue.put((-priority, message_id, queued))
        logger.debug(f"Enqueued message {message_id} for {recipient_id}")
        
        return message_id
        
    async def acknowledge_message(self, message_id: str) -> None:
        """Acknowledge successful delivery of a message.
        
        Args:
            message_id: ID of the message to acknowledge
        """
        if message_id in self.in_flight:
            del self.in_flight[message_id]
            logger.debug(f"Acknowledged message {message_id}")
            
    async def _process_queue(self) -> None:
        """Process messages from the queue and handle retries."""
        while self.running:
            try:
                # Check for messages that need retrying
                now = datetime.utcnow()
                retry_messages = []
                
                for msg_id, msg in list(self.in_flight.items()):
                    if msg.should_retry():
                        retry_messages.append((msg.priority, msg_id, msg))
                
                # Add retry messages back to the queue
                for priority, msg_id, msg in retry_messages:
                    await self.queue.put((priority, msg_id, msg))
                    del self.in_flight[msg_id]
                
                # Get the next message
                try:
                    priority, msg_id, queued_msg = await asyncio.wait_for(
                        self.queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                    
                # Update message state
                queued_msg.retry_count += 1
                queued_msg.last_attempt = datetime.utcnow()
                
                # Send the message
                try:
                    success = await self.send_message(
                        queued_msg.recipient_id,
                        queued_msg.message
                    )
                    
                    if success:
                        # If send was successful, wait for ack
                        self.in_flight[msg_id] = queued_msg
                        # Set a timeout for the ack
                        asyncio.create_task(self._wait_for_ack(msg_id))
                    else:
                        # Schedule for retry
                        if queued_msg.should_retry():
                            await self.queue.put((priority, msg_id, queued_msg))
                        else:
                            logger.warning(f"Failed to send message {msg_id} after {queued_msg.retry_count} attempts")
                            
                except Exception as e:
                    logger.error(f"Error sending message {msg_id}: {e}")
                    if queued_msg.should_retry():
                        await self.queue.put((priority, msg_id, queued_msg))
                    
            except Exception as e:
                logger.error(f"Error in message queue processing: {e}", exc_info=True)
                await asyncio.sleep(1)  # Prevent tight loop on errors
                
    async def _wait_for_ack(self, message_id: str, timeout: float = 30.0) -> None:
        """Wait for an acknowledgment for a message.
        
        Args:
            message_id: ID of the message to wait for
            timeout: Timeout in seconds
        """
        try:
            await asyncio.sleep(timeout)
            
            # If we get here, we timed out waiting for an ack
            if message_id in self.in_flight:
                msg = self.in_flight[message_id]
                del self.in_flight[message_id]
                
                if msg.should_retry():
                    logger.debug(f"Timeout waiting for ack for message {message_id}, retrying...")
                    await self.queue.put((msg.priority, message_id, msg))
                else:
                    logger.warning(f"Giving up on message {message_id} after {msg.retry_count} attempts")
                    
        except asyncio.CancelledError:
            # Task was cancelled, which is fine
            pass
        except Exception as e:
            logger.error(f"Error in ack waiter for {message_id}: {e}", exc_info=True)

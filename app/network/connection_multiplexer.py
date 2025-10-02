"""
Connection Multiplexer for P2P networking.

This module provides a ConnectionMultiplexer class that enables multiple logical
connections to share a single underlying transport connection, improving efficiency
and reducing connection overhead.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Optional, Set

from app.core.crypto import CryptoEngine

logger = logging.getLogger(__name__)

class MultiplexedMessageType(Enum):
    """Types of messages that can be sent over a multiplexed connection."""
    DATA = auto()
    OPEN = auto()
    CLOSE = auto()
    PING = auto()
    PONG = auto()
    ERROR = auto()

@dataclass
class MultiplexedMessage:
    """A message sent over a multiplexed connection."""
    channel_id: str
    message_type: MultiplexedMessageType
    data: bytes = b''
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        """Serialize the message to bytes."""
        return json.dumps({
            'channel_id': self.channel_id,
            'message_type': self.message_type.name,
            'data': self.data.hex(),
            'metadata': self.metadata,
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MultiplexedMessage':
        """Deserialize a message from bytes."""
        try:
            msg_dict = json.loads(data.decode())
            return cls(
                channel_id=msg_dict['channel_id'],
                message_type=MultiplexedMessageType[msg_dict['message_type']],
                data=bytes.fromhex(msg_dict['data']),
                metadata=msg_dict.get('metadata', {}),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Failed to deserialize message: {e}")
            raise ValueError("Invalid message format") from e

class ConnectionMultiplexer:
    """
    Manages multiple logical connections over a single transport connection.
    
    This class allows multiple logical channels to share a single WebRTC DataChannel,
    reducing the overhead of maintaining multiple WebRTC connections.
    """
    
    def __init__(
        self,
        send_message: Callable[[bytes], None],
        crypto_engine: Optional[CryptoEngine] = None,
        ping_interval: float = 30.0,
        max_channels: int = 100,
    ):
        """
        Initialize the connection multiplexer.
        
        Args:
            send_message: Function to send raw data over the transport
            crypto_engine: Optional crypto engine for message encryption
            ping_interval: Interval in seconds between ping messages (0 to disable)
            max_channels: Maximum number of channels that can be opened
        """
        self._send_message = send_message
        self._crypto_engine = crypto_engine or CryptoEngine()
        self._ping_interval = ping_interval
        self._max_channels = max_channels
        
        # Active channels and their handlers
        self._channels: Dict[str, asyncio.Queue] = {}
        self._channel_handlers: Dict[str, Callable[[bytes, Dict[str, Any]], None]] = {}
        self._channel_events: Dict[str, asyncio.Event] = {}
        
        # Connection state
        self._is_connected = asyncio.Event()
        self._is_closing = False
        self._ping_task: Optional[asyncio.Task] = None
        
        # Statistics
        self._bytes_sent = 0
        self._bytes_received = 0
        self._channels_opened = 0
        self._channels_closed = 0
        self._errors = 0
    
    async def start(self) -> None:
        """Start the connection multiplexer."""
        if self._ping_interval > 0 and not self._ping_task:
            self._ping_task = asyncio.create_task(self._ping_loop())
        self._is_connected.set()
    
    async def stop(self) -> None:
        """Stop the connection multiplexer and clean up resources."""
        self._is_closing = True
        
        if self._ping_task:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass
            self._ping_task = None
        
        # Close all channels
        for channel_id in list(self._channels.keys()):
            await self.close_channel(channel_id)
        
        self._is_connected.clear()
    
    async def _ping_loop(self) -> None:
        """Background task to send periodic ping messages."""
        while not self._is_closing:
            try:
                await asyncio.sleep(self._ping_interval)
                if not self._is_connected.is_set() or self._is_closing:
                    break
                await self._send_multiplexed_message(MultiplexedMessage(
                    channel_id="",
                    message_type=MultiplexedMessageType.PING,
                ))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ping loop: {e}")
                self._errors += 1
    
    async def _send_multiplexed_message(self, message: MultiplexedMessage) -> None:
        """Send a multiplexed message over the transport."""
        if not self._is_connected.is_set():
            raise ConnectionError("Not connected")
        
        try:
            # Encrypt the message if a crypto engine is available
            message_data = message.to_bytes()
            if self._crypto_engine:
                message_data = await self._crypto_engine.encrypt_message(
                    message_data,
                    additional_data=message.channel_id.encode(),
                )
            
            # Send the message
            self._send_message(message_data)
            self._bytes_sent += len(message_data)
            
        except Exception as e:
            logger.error(f"Failed to send multiplexed message: {e}")
            self._errors += 1
            raise
    
    async def open_channel(
        self,
        channel_id: str,
        message_handler: Callable[[bytes, Dict[str, Any]], None],
    ) -> bool:
        """
        Open a new logical channel.
        
        Args:
            channel_id: Unique identifier for the channel
            message_handler: Callback to handle incoming messages on this channel
            
        Returns:
            bool: True if the channel was opened, False otherwise
        """
        if channel_id in self._channels:
            logger.warning(f"Channel {channel_id} already exists")
            return False
            
        if len(self._channels) >= self._max_channels:
            logger.error(f"Maximum number of channels ({self._max_channels}) reached")
            return False
        
        self._channels[channel_id] = asyncio.Queue()
        self._channel_handlers[channel_id] = message_handler
        self._channel_events[channel_id] = asyncio.Event()
        self._channels_opened += 1
        
        # Notify the remote end
        await self._send_multiplexed_message(MultiplexedMessage(
            channel_id=channel_id,
            message_type=MultiplexedMessageType.OPEN,
        ))
        
        return True
    
    async def close_channel(self, channel_id: str) -> None:
        """Close a logical channel."""
        if channel_id not in self._channels:
            return
        
        # Notify the remote end
        try:
            await self._send_multiplexed_message(MultiplexedMessage(
                channel_id=channel_id,
                message_type=MultiplexedMessageType.CLOSE,
            ))
        except Exception as e:
            logger.warning(f"Error sending close message for channel {channel_id}: {e}")
        
        # Clean up local resources
        self._channels.pop(channel_id, None)
        self._channel_handlers.pop(channel_id, None)
        event = self._channel_events.pop(channel_id, None)
        if event:
            event.set()
        
        self._channels_closed += 1
    
    async def send_data(
        self,
        channel_id: str,
        data: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Send data over a logical channel.
        
        Args:
            channel_id: The channel to send the data on
            data: The data to send
            metadata: Optional metadata to include with the message
            
        Returns:
            bool: True if the data was sent, False otherwise
        """
        if channel_id not in self._channels:
            logger.error(f"Channel {channel_id} does not exist")
            return False
        
        try:
            await self._send_multiplexed_message(MultiplexedMessage(
                channel_id=channel_id,
                message_type=MultiplexedMessageType.DATA,
                data=data,
                metadata=metadata or {},
            ))
            return True
        except Exception as e:
            logger.error(f"Failed to send data on channel {channel_id}: {e}")
            self._errors += 1
            return False
    
    async def handle_message(self, data: bytes) -> None:
        """
        Handle an incoming message from the transport.
        
        This method should be called whenever data is received on the underlying
        transport connection.
        """
        try:
            # Decrypt the message if a crypto engine is available
            if self._crypto_engine:
                try:
                    # The channel ID is not known yet, so we can't provide additional_data
                    data = await self._crypto_engine.decrypt_message(data)
                except Exception as e:
                    logger.error(f"Failed to decrypt message: {e}")
                    self._errors += 1
                    return
            
            # Parse the message
            try:
                message = MultiplexedMessage.from_bytes(data)
                self._bytes_received += len(data)
            except ValueError as e:
                logger.error(f"Invalid message format: {e}")
                self._errors += 1
                return
            
            # Handle the message based on its type
            if message.message_type == MultiplexedMessageType.DATA:
                await self._handle_data_message(message)
            elif message.message_type == MultiplexedMessageType.OPEN:
                await self._handle_open_message(message)
            elif message.message_type == MultiplexedMessageType.CLOSE:
                await self._handle_close_message(message)
            elif message.message_type == MultiplexedMessageType.PING:
                await self._handle_ping_message(message)
            elif message.message_type == MultiplexedMessageType.PONG:
                await self._handle_pong_message(message)
            elif message.message_type == MultiplexedMessageType.ERROR:
                await self._handle_error_message(message)
            else:
                logger.warning(f"Unknown message type: {message.message_type}")
                self._errors += 1
                
        except Exception as e:
            logger.error(f"Error handling message: {e}", exc_info=True)
            self._errors += 1
    
    async def _handle_data_message(self, message: MultiplexedMessage) -> None:
        """Handle a data message."""
        # Print debug information
        print(f"\n=== _handle_data_message ===")
        print(f"Channel ID: {message.channel_id}")
        print(f"Available channels: {list(self._channels.keys())}")
        print(f"Available handlers: {list(self._channel_handlers.keys())}")
        
        if message.channel_id not in self._channels:
            print(f"ERROR: Channel {message.channel_id} not found in _channels")
            logger.warning(f"Received data for unknown channel: {message.channel_id}")
            return
        
        # Get the message handler for this channel
        handler = self._channel_handlers.get(message.channel_id)
        if not handler:
            print(f"ERROR: No handler found for channel {message.channel_id}")
            logger.warning(f"No handler for channel: {message.channel_id}")
            return
        
        # Call the handler with the message data and metadata
        try:
            print(f"Calling handler for channel {message.channel_id}")
            print(f"Data: {message.data}")
            print(f"Metadata: {message.metadata}")
            handler(message.data, message.metadata)
            print("Handler called successfully")
        except Exception as e:
            print(f"EXCEPTION in handler: {e}")
            logger.error(f"Error in channel {message.channel_id} handler: {e}", exc_info=True)
            self._errors += 1
        print("=== _handle_data_message completed ===\n")
    
    async def _handle_open_message(self, message: MultiplexedMessage) -> None:
        """Handle a channel open message."""
        if message.channel_id in self._channels:
            logger.warning(f"Received OPEN for existing channel: {message.channel_id}")
            return
        
        # If we have a default channel handler, use it to create the channel
        if hasattr(self, '_default_channel_handler'):
            await self.open_channel(
                message.channel_id,
                self._default_channel_handler,
            )
        else:
            logger.warning(f"Received OPEN for unknown channel with no default handler: {message.channel_id}")
    
    async def _handle_close_message(self, message: MultiplexedMessage) -> None:
        """Handle a channel close message."""
        if message.channel_id not in self._channels:
            return
        
        # Clean up the channel
        self._channels.pop(message.channel_id, None)
        self._channel_handlers.pop(message.channel_id, None)
        event = self._channel_events.pop(message.channel_id, None)
        if event:
            event.set()
        
        self._channels_closed += 1
    
    async def _handle_ping_message(self, message: MultiplexedMessage) -> None:
        """Handle a ping message."""
        # Respond with a pong
        await self._send_multiplexed_message(MultiplexedMessage(
            channel_id="",
            message_type=MultiplexedMessageType.PONG,
        ))
    
    async def _handle_pong_message(self, message: MultiplexedMessage) -> None:
        """Handle a pong message."""
        # Update last seen time for the connection
        pass
    
    async def _handle_error_message(self, message: MultiplexedMessage) -> None:
        """Handle an error message."""
        logger.error(f"Received error for channel {message.channel_id}: {message.data.decode(errors='replace')}")
        self._errors += 1
    
    # Properties for monitoring
    @property
    def is_connected(self) -> bool:
        """Return whether the multiplexer is connected."""
        return self._is_connected.is_set()
    
    @property
    def active_channels(self) -> Set[str]:
        """Return the set of active channel IDs."""
        return set(self._channels.keys())
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'bytes_sent': self._bytes_sent,
            'bytes_received': self._bytes_received,
            'channels_opened': self._channels_opened,
            'channels_closed': self._channels_closed,
            'active_channels': len(self._channels),
            'errors': self._errors,
        }

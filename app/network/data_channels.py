"""
Enhanced WebRTC DataChannels implementation for P2P communication.

This module provides a robust implementation of WebRTC DataChannels with support for:
- Multiple channel types (reliable, unreliable, file transfer, etc.)
- Connection multiplexing using ConnectionMultiplexer
- Automatic reconnection
- Message fragmentation and reassembly
- Flow control
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union, cast

from aiortc import RTCDataChannel, RTCPeerConnection, RTCSessionDescription

from ..core.crypto import CryptoEngine
from .connection_multiplexer import ConnectionMultiplexer, MultiplexedMessage, MultiplexedMessageType

logger = logging.getLogger(__name__)


class ChannelType(Enum):
    """Types of data channels."""
    RELIABLE = auto()  # Reliable, ordered delivery
    UNRELIABLE = auto()  # Unreliable, unordered delivery
    FILE_TRANSFER = auto()  # Optimized for file transfers
    STREAMING = auto()  # Optimized for streaming data
    CONTROL = auto()  # Control messages (highest priority)


@dataclass
class ChannelConfig:
    """Configuration for a data channel."""
    channel_type: ChannelType
    ordered: bool = True
    max_retransmits: Optional[int] = None
    max_packet_life_time: Optional[int] = None
    protocol: str = ""
    negotiated: bool = False
    id: Optional[int] = None
    priority: str = "normal"  # 'very-low', 'low', 'medium', 'high'


@dataclass
class Message:
    """A message sent over a data channel."""
    data: Union[bytes, str]
    channel_type: ChannelType
    is_binary: bool = False
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataChannelManager:
    """
    Manages WebRTC DataChannels with enhanced features.
    
    This implementation uses a single underlying WebRTC DataChannel with the ConnectionMultiplexer
    to efficiently handle multiple logical channels over a single transport connection.
    """

    def __init__(
        self,
        peer_id: str,
        crypto_engine: CryptoEngine,
        on_message: Callable[[str, Message], None],
        on_channel_open: Optional[Callable[[str, ChannelType], None]] = None,
        on_channel_close: Optional[Callable[[str, ChannelType], None]] = None,
    ):
        """Initialize the DataChannelManager.

        Args:
            peer_id: ID of the remote peer
            crypto_engine: CryptoEngine instance for encryption
            on_message: Callback for received messages
            on_channel_open: Callback when a channel is opened
            on_channel_close: Callback when a channel is closed
        """
        self.peer_id = peer_id
        self.crypto = crypto_engine
        self.on_message = on_message
        self.on_channel_open = on_channel_open
        self.on_channel_close = on_channel_close

        # WebRTC peer connection
        self.pc = RTCPeerConnection()
        self.pc.on("connectionstatechange", self._on_connection_state_change)
        self.pc.on("iceconnectionstatechange", self._on_ice_connection_state_change)

        # Single data channel for all traffic (multiplexed)
        self._data_channel: Optional[RTCDataChannel] = None
        self._multiplexer: Optional[ConnectionMultiplexer] = None
        self._channels: Dict[str, ChannelType] = {}  # channel_id -> ChannelType
        
        # Track connection state
        self._is_connected = False
        self._connection_attempts = 0
        self._max_connection_attempts = 5
        self._reconnect_delay = 1.0  # seconds, will increase with backoff
        
        # Track channel state
        self._channel_events: Dict[str, asyncio.Event] = {}
        self._pending_messages: Dict[str, List[Message]] = {}

    async def connect(self, offer_sdp: str) -> str:
        """Process an offer and return an answer SDP.

        Args:
            offer_sdp: SDP offer from the remote peer

        Returns:
            str: SDP answer to send back to the peer
        """
        try:
            # Set remote description
            await self.pc.setRemoteDescription(
                RTCSessionDescription(sdp=offer_sdp, type="offer")
            )

            # Create the data channel if we're the offerer
            if not self._data_channel:
                self._setup_data_channel()

            # Create answer
            answer = await self.pc.createAnswer()
            await self.pc.setLocalDescription(answer)

            return answer.sdp

        except Exception as e:
            logger.error(f"Failed to process offer: {e}")
            raise

    def _setup_data_channel(self) -> None:
        """Set up the underlying WebRTC data channel and multiplexer."""
        if self._data_channel is not None:
            return
            
        # Create a single reliable data channel for all traffic
        self._data_channel = self.pc.createDataChannel(
            label="multiplexed",
            ordered=True,
            protocol="multiplexed",
        )
        
        # Set up the multiplexer
        self._multiplexer = ConnectionMultiplexer(
            send_message=self._send_data_channel_message,
            crypto_engine=self.crypto,
            ping_interval=30.0,  # 30 seconds between pings
        )
        
        # Set up data channel event handlers
        self._data_channel.on("open", self._on_data_channel_open)
        self._data_channel.on("close", self._on_data_channel_close)
        self._data_channel.on("message", self._on_data_channel_message)
        
        # Start the multiplexer
        asyncio.create_task(self._multiplexer.start())
    
    async def create_channel(
        self, 
        channel_type: ChannelType, 
        config: Optional[ChannelConfig] = None
    ) -> str:
        """Create a new logical channel.

        Args:
            channel_type: Type of channel to create
            config: Optional channel configuration (not used in multiplexed mode)

        Returns:
            str: The ID of the created channel
        """
        if self._multiplexer is None:
            self._setup_data_channel()
            
        # Generate a unique channel ID
        channel_id = f"{channel_type.name.lower()}-{int(time.time() * 1000)}"
        
        # Create an event to track when the channel is ready
        self._channel_events[channel_id] = asyncio.Event()
        self._pending_messages[channel_id] = []
        
        # Store the channel type
        self._channels[channel_id] = channel_type
        
        # If we're the initiator, open the channel in the multiplexer
        if self._multiplexer and self._data_channel and self._data_channel.readyState == "open":
            try:
                await self._multiplexer.open_channel(
                    channel_id=channel_id,
                    message_handler=lambda data, metadata: self._on_multiplexed_message(channel_id, data, metadata),
                )
                logger.debug(f"Opened logical channel {channel_id} for {channel_type.name}")
            except Exception as e:
                logger.error(f"Failed to open logical channel {channel_id}: {e}")
                del self._channels[channel_id]
                del self._channel_events[channel_id]
                del self._pending_messages[channel_id]
                raise
        
        return channel_id

    def _get_channel_config(self, channel_type: ChannelType) -> Dict[str, Any]:
        """Get configuration for a channel type."""
        if channel_type == ChannelType.RELIABLE:
            return {
                "ordered": True,
                "max_retransmits": None,
                "max_packet_life_time": None,
                "priority": "high",
            }
        elif channel_type == ChannelType.UNRELIABLE:
            return {
                "ordered": False,
                "max_retransmits": 0,  # No retransmits for unreliable
                "max_packet_life_time": 1000,  # 1 second
                "priority": "low",
            }
        elif channel_type == ChannelType.FILE_TRANSFER:
            return {
                "ordered": True,
                "max_retransmits": None,
                "max_packet_life_time": None,
                "priority": "high",
            }
        elif channel_type == ChannelType.STREAMING:
            return {
                "ordered": False,
                "max_retransmits": 0,
                "max_packet_life_time": 1000,  # 1 second
                "priority": "medium",
            }
        else:  # CONTROL
            return {
                "ordered": True,
                "max_retransmits": 3,  # Few retries for control messages
                "max_packet_life_time": 5000,  # 5 seconds
                "priority": "very-high",
            }

    async def send_message(
        self,
        data: Union[bytes, str],
        channel_type: ChannelType = ChannelType.RELIABLE,
        is_binary: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
        channel_id: Optional[str] = None,
    ) -> bool:
        """Send a message over the specified channel type.

        Args:
            data: Data to send (bytes or string)
            channel_type: Type of channel to use (ignored if channel_id is provided)
            is_binary: Whether the data is binary
            metadata: Additional metadata to include with the message
            channel_id: Specific channel ID to use (creates one if not provided)

        Returns:
            bool: True if the message was sent successfully
        """
        if metadata is None:
            metadata = {}
        
        # Create a message object
        message = Message(
            data=data,
            channel_type=channel_type,
            is_binary=is_binary,
            metadata=metadata,
        )
        
        # If no channel_id is provided, create a new channel
        if channel_id is None:
            try:
                channel_id = await self.create_channel(channel_type)
            except Exception as e:
                logger.error(f"Failed to create channel for message: {e}")
                return False
        
        # If the channel doesn't exist, fail
        if channel_id not in self._channels:
            logger.error(f"Channel {channel_id} does not exist")
            return False
            
        # Get the actual channel type
        actual_channel_type = self._channels[channel_id]
        
        # If the multiplexer isn't ready yet, queue the message
        if self._multiplexer is None or not self._multiplexer.is_connected:
            self._pending_messages[channel_id].append(message)
            return True
            
        try:
            # Convert the data to bytes if it's a string
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Add metadata
            msg_metadata = {
                "channel_type": actual_channel_type.name,
                "is_binary": is_binary,
                "timestamp": time.time(),
                **metadata,
            }
            
            # Send the message through the multiplexer
            await self._multiplexer.send_data(
                channel_id=channel_id,
                data=data_bytes,
                metadata=msg_metadata,
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message on channel {channel_id}: {e}")
            return False

    async def close(self) -> None:
        """Close all channels and the peer connection."""
        # Close the multiplexer if it exists
        if self._multiplexer:
            await self._multiplexer.stop()
            self._multiplexer = None
        
        # Close the data channel if it exists
        if self._data_channel:
            self._data_channel.close()
            self._data_channel = None
        
        # Close the peer connection
        if self.pc:
            await self.pc.close()
        
        # Clear all state
        self._channels.clear()
        self._channel_events.clear()
        self._pending_messages.clear()
        self._is_connected = False

    # Event handlers
    def _on_data_channel_open(self) -> None:
        """Handle the data channel opening."""
        logger.info(f"Data channel opened with {self.peer_id}")
        self._is_connected = True
        self._connection_attempts = 0
        
        # Notify any waiting operations
        for event in self._channel_events.values():
            event.set()
    
    def _on_data_channel_close(self) -> None:
        """Handle the data channel closing."""
        logger.info(f"Data channel closed with {self.peer_id}")
        self._is_connected = False
        self._handle_disconnection()
    
    def _on_data_channel_message(self, message: Union[bytes, str]) -> None:
        """Handle an incoming message on the data channel."""
        if self._multiplexer:
            # Pass the message to the multiplexer
            if isinstance(message, str):
                message = message.encode('utf-8')
            asyncio.create_task(self._multiplexer.handle_message(message))
    
    async def _on_multiplexed_message(self, channel_id: str, data: bytes, metadata: Dict[str, Any]) -> None:
        """Handle a message from the multiplexer."""
        try:
            # Get the channel type from metadata or channel ID
            channel_type_name = metadata.get('channel_type', '').upper()
            try:
                channel_type = ChannelType[channel_type_name]
            except KeyError:
                # Try to determine from channel ID if not in metadata
                channel_type = self._channels.get(channel_id, ChannelType.RELIABLE)
            
            # Determine if the data is binary
            is_binary = metadata.get('is_binary', False)
            
            # Create a message object
            message = Message(
                data=data,
                channel_type=channel_type,
                is_binary=is_binary,
                metadata=metadata,
            )
            
            # Pass to the message handler
            self.on_message(self.peer_id, message)
            
        except Exception as e:
            logger.error(f"Error handling multiplexed message: {e}")
    
    def _send_data_channel_message(self, data: bytes) -> None:
        """Send raw data over the data channel."""
        if self._data_channel and self._data_channel.readyState == "open":
            self._data_channel.send(data)
    
    def _on_connection_state_change(self) -> None:
        """Handle connection state changes."""
        logger.info(f"Connection state changed to {self.pc.connectionState}")
        
        if self.pc.connectionState == "connected":
            self._is_connected = True
            self._connection_attempts = 0
            
            # Set up the data channel if we're the offerer
            if not self._data_channel and self.pc.localDescription:
                self._setup_data_channel()
                
        elif self.pc.connectionState == "disconnected":
            self._is_connected = False
            self._handle_disconnection()
    
    def _on_ice_connection_state_change(self) -> None:
        """Handle ICE connection state changes."""
        logger.info(f"ICE connection state changed to {self.pc.iceConnectionState}")
    
    def _handle_disconnection(self) -> None:
        """Handle a disconnection event."""
        if self._connection_attempts < self._max_connection_attempts:
            delay = min(self._reconnect_delay * (2 ** self._connection_attempts), 30)
            logger.info(f"Attempting to reconnect in {delay} seconds...")
            
            self._connection_attempts += 1
            asyncio.create_task(self._reconnect_after_delay(delay))
        else:
            logger.error("Max reconnection attempts reached. Giving up.")
    
    async def _reconnect_after_delay(self, delay: float) -> None:
        """Attempt to reconnect after a delay."""
        await asyncio.sleep(delay)
        # TODO: Implement reconnection logic

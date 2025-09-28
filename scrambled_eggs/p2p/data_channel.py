"""
Data Channel
-----------
Handles WebRTC data channels for P2P communication.
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Union

from aiortc import RTCDataChannel


class DataChannelEvent(Enum):
    """Events that can occur on a data channel."""
    OPEN = auto()
    CLOSED = auto()
    MESSAGE = auto()
    ERROR = auto()


@dataclass
class DataChannelMessage:
    """A message sent over a data channel."""
    event: DataChannelEvent
    data: Any = None
    error: Optional[Exception] = None


class DataChannel:
    """Wrapper around RTCDataChannel with a simpler interface."""
    
    def __init__(self, rtc_channel: RTCDataChannel, label: str = ""):
        """Initialize the data channel.
        
        Args:
            rtc_channel: The underlying RTCDataChannel
            label: Optional label for the channel
        """
        self._channel = rtc_channel
        self.label = label or rtc_channel.label
        self._message_handlers: List[Callable[[Any], None]] = []
        self._event_handlers: Dict[DataChannelEvent, List[Callable[[DataChannelMessage], None]]] = {
            event: [] for event in DataChannelEvent
        }
        
        # Set up event handlers
        self._channel.on("open", self._on_open)
        self._channel.on("close", self._on_close)
        self._channel.on("message", self._on_message)
        self._channel.on("error", self._on_error)
    
    def on_message(self, handler: Callable[[Any], None]) -> None:
        """Register a message handler.
        
        Args:
            handler: Function to call when a message is received
        """
        self._message_handlers.append(handler)
    
    def on_event(self, event: DataChannelEvent, handler: Callable[[DataChannelMessage], None]) -> None:
        """Register an event handler.
        
        Args:
            event: Event to listen for
            handler: Function to call when the event occurs
        """
        self._event_handlers[event].append(handler)
    
    async def send(self, data: Union[str, bytes, dict]) -> None:
        """Send data over the data channel.
        
        Args:
            data: Data to send (can be str, bytes, or dict)
        """
        if isinstance(data, dict):
            data = json.dumps(data)
        
        if isinstance(data, str):
            await self._channel.send(data)
        elif isinstance(data, (bytes, bytearray)):
            await self._channel.send(data)
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    async def close(self) -> None:
        """Close the data channel."""
        self._channel.close()
    
    def _on_open(self) -> None:
        """Handle the open event."""
        logging.info(f"Data channel '{self.label}' opened")
        self._trigger_event(DataChannelEvent.OPEN)
    
    def _on_close(self) -> None:
        """Handle the close event."""
        logging.info(f"Data channel '{self.label}' closed")
        self._trigger_event(DataChannelEvent.CLOSED)
    
    def _on_message(self, message: Union[str, bytes]) -> None:
        """Handle an incoming message."""
        try:
            # Try to parse JSON if it's a string
            if isinstance(message, str):
                try:
                    message = json.loads(message)
                except json.JSONDecodeError:
                    pass  # Not JSON, keep as string
            
            # Call message handlers
            for handler in self._message_handlers:
                try:
                    handler(message)
                except Exception as e:
                    logging.error(f"Error in message handler: {e}")
            
            # Trigger message event
            self._trigger_event(DataChannelEvent.MESSAGE, data=message)
        except Exception as e:
            logging.error(f"Error processing message: {e}")
            self._trigger_event(DataChannelEvent.ERROR, error=e)
    
    def _on_error(self, error: Exception) -> None:
        """Handle an error."""
        logging.error(f"Data channel error: {error}")
        self._trigger_event(DataChannelEvent.ERROR, error=error)
    
    def _trigger_event(self, event: DataChannelEvent, **kwargs) -> None:
        """Trigger an event."""
        message = DataChannelMessage(event=event, **kwargs)
        for handler in self._event_handlers[event]:
            try:
                handler(message)
            except Exception as e:
                logging.error(f"Error in event handler: {e}")
    
    @property
    def ready_state(self) -> str:
        """Get the current state of the data channel."""
        return self._channel.readyState
    
    @property
    def is_open(self) -> bool:
        """Check if the data channel is open."""
        return self._channel.readyState == "open"
    
    @property
    def is_closed(self) -> bool:
        """Check if the data channel is closed."""
        return self._channel.readyState == "closed"

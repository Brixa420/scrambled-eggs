"""
Signaling Client for WebRTC
--------------------------
Handles the signaling server communication for WebRTC peer connections.
"""

import asyncio
import json
import logging
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

import aiohttp
from aiohttp import ClientWebSocketResponse, WSMsgType


class SignalingMessageType(Enum):
    """Types of signaling messages."""

    OFFER = "offer"
    ANSWER = "answer"
    CANDIDATE = "candidate"
    ERROR = "error"
    WELCOME = "welcome"
    PEERS = "peers"
    BYE = "bye"


class SignalingMessage:
    """Represents a signaling message."""

    def __init__(self, message_type: SignalingMessageType, **kwargs):
        """Initialize a signaling message.

        Args:
            message_type: Type of the message
            **kwargs: Additional message data
        """
        self.type = message_type
        self.data = kwargs

    def to_json(self) -> str:
        """Convert the message to JSON."""
        return json.dumps({"type": self.type.value, "data": self.data})

    @classmethod
    def from_json(cls, json_str: str) -> "SignalingMessage":
        """Create a message from JSON."""
        try:
            data = json.loads(json_str)
            return cls(message_type=SignalingMessageType(data["type"]), **data.get("data", {}))
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return cls(
                message_type=SignalingMessageType.ERROR, error=f"Invalid message format: {str(e)}"
            )


class SignalingClient:
    """Client for WebRTC signaling server."""

    def __init__(self, url: str, on_message: Callable[[SignalingMessage], None]):
        """Initialize the signaling client.

        Args:
            url: WebSocket URL of the signaling server
            on_message: Callback for incoming messages
        """
        self.url = url
        self.on_message = on_message
        self.ws: Optional[ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.connected = asyncio.Event()
        self._reconnect_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Connect to the signaling server."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()

        while True:
            try:
                async with self.session.ws_connect(self.url) as ws:
                    self.ws = ws
                    self.connected.set()
                    await self._listen()
            except (aiohttp.ClientError, asyncio.CancelledError) as e:
                logging.error(f"WebSocket connection error: {e}")
                self.connected.clear()

                # Wait before reconnecting
                await asyncio.sleep(5)

            if self._reconnect_task is None:
                break

    async def _listen(self) -> None:
        """Listen for incoming messages."""
        if self.ws is None:
            return

        async for msg in self.ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    message = SignalingMessage.from_json(msg.data)
                    self.on_message(message)
                except Exception as e:
                    logging.error(f"Error processing message: {e}")
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
                break

    async def send(self, message: Union[SignalingMessage, str, dict]) -> None:
        """Send a message to the signaling server.

        Args:
            message: Message to send (can be SignalingMessage, dict, or JSON string)
        """
        if self.ws is None or self.ws.closed:
            raise ConnectionError("Not connected to signaling server")

        if isinstance(message, SignalingMessage):
            message = message.to_json()
        elif isinstance(message, dict):
            message = json.dumps(message)

        await self.ws.send_str(message)

    async def close(self) -> None:
        """Close the connection to the signaling server."""
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None

        if self.ws is not None and not self.ws.closed:
            await self.ws.close()

        if self.session is not None and not self.session.closed:
            await self.session.close()

        self.connected.clear()

    def start_reconnect_loop(self) -> None:
        """Start the reconnection loop in the background."""
        if self._reconnect_task is None:
            self._reconnect_task = asyncio.create_task(self.connect())

    def stop_reconnect_loop(self) -> None:
        """Stop the reconnection loop."""
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None

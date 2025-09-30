import asyncio
import json
import logging
from typing import Dict, Callable, Any, Optional, List
import websockets
from enum import Enum, auto
import uuid

class NetworkEventType(Enum):
    CONNECT = auto()
    DISCONNECT = auto()
    MESSAGE = auto()
    PLAYER_JOINED = auto()
    PLAYER_LEFT = auto()
    GAME_STATE_UPDATE = auto()
    INPUT_UPDATE = auto()

class NetworkManager:
    def __init__(self, server_url: str = None):
        self.server_url = server_url or "ws://localhost:8765"
        self.websocket = None
        self.connected = False
        self.client_id = str(uuid.uuid4())
        self.message_handlers: Dict[NetworkEventType, List[Callable]] = {
            event_type: [] for event_type in NetworkEventType
        }
        self.message_queue = asyncio.Queue()
        self.receive_task = None
        self.process_task = None
        self.logger = self._setup_logging()

    def _setup_logging(self):
        logger = logging.getLogger("NetworkManager")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        
        return logger

    async def connect(self):
        """Establish a WebSocket connection to the game server."""
        try:
            self.websocket = await websockets.connect(self.server_url)
            self.connected = True
            self.logger.info(f"Connected to server at {self.server_url}")
            
            # Start the receive and process tasks
            self.receive_task = asyncio.create_task(self._receive_messages())
            self.process_task = asyncio.create_task(self._process_messages())
            
            # Notify of successful connection
            await self._trigger_event(NetworkEventType.CONNECT, {"client_id": self.client_id})
            
        except Exception as e:
            self.logger.error(f"Failed to connect to server: {e}")
            self.connected = False
            raise

    async def disconnect(self):
        """Close the WebSocket connection."""
        if self.connected and self.websocket:
            # Cancel tasks
            if self.receive_task:
                self.receive_task.cancel()
            if self.process_task:
                self.process_task.cancel()
            
            # Close the connection
            await self.websocket.close()
            self.connected = False
            self.logger.info("Disconnected from server")
            
            # Notify of disconnection
            await self._trigger_event(NetworkEventType.DISCONNECT, {})

    async def _receive_messages(self):
        """Continuously receive messages from the server."""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    await self.message_queue.put(data)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to decode message: {e}")
        except websockets.exceptions.ConnectionClosed:
            self.connected = False
            self.logger.warning("Connection to server closed")
            await self._trigger_event(NetworkEventType.DISCONNECT, {})

    async def _process_messages(self):
        """Process received messages from the queue."""
        while True:
            try:
                message = await self.message_queue.get()
                event_type = NetworkEventType[message.get('type')]
                data = message.get('data', {})
                await self._trigger_event(event_type, data)
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")

    async def send(self, event_type: NetworkEventType, data: Dict[str, Any] = None):
        """Send a message to the server."""
        if not self.connected or not self.websocket:
            self.logger.warning("Cannot send message: Not connected to server")
            return
            
        try:
            message = {
                'type': event_type.name,
                'client_id': self.client_id,
                'data': data or {}
            }
            await self.websocket.send(json.dumps(message))
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            self.connected = False
            await self._trigger_event(NetworkEventType.DISCONNECT, {})

    def add_event_handler(self, event_type: NetworkEventType, handler: Callable):
        """Register a handler for a specific event type."""
        if handler not in self.message_handlers[event_type]:
            self.message_handlers[event_type].append(handler)

    def remove_event_handler(self, event_type: NetworkEventType, handler: Callable):
        """Remove a handler for a specific event type."""
        if handler in self.message_handlers[event_type]:
            self.message_handlers[event_type].remove(handler)

    async def _trigger_event(self, event_type: NetworkEventType, data: Dict[str, Any]):
        """Trigger all handlers for an event type."""
        for handler in self.message_handlers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                self.logger.error(f"Error in {event_type.name} handler: {e}")

    async def update_player_state(self, state: Dict[str, Any]):
        """Send player state update to the server."""
        await self.send(NetworkEventType.INPUT_UPDATE, {"state": state})

    async def request_game_state(self):
        """Request the current game state from the server."""
        await self.send(NetworkEventType.GAME_STATE_UPDATE, {})

# Example usage
async def example_usage():
    network = NetworkManager("ws://localhost:8765")
    
    # Add event handlers
    def on_connect(data):
        print(f"Connected with ID: {data.get('client_id')}")
    
    def on_player_joined(data):
        print(f"Player joined: {data.get('player_id')}")
    
    network.add_event_handler(NetworkEventType.CONNECT, on_connect)
    network.add_event_handler(NetworkEventType.PLAYER_JOINED, on_player_joined)
    
    try:
        # Connect to the server
        await network.connect()
        
        # Send some updates
        await network.update_player_state({
            'position': {'x': 10, 'y': 20},
            'velocity': {'x': 1, 'y': 0},
            'animation': 'walking'
        })
        
        # Keep the connection alive
        while True:
            await asyncio.sleep(1)
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await network.disconnect()

if __name__ == "__main__":
    asyncio.run(example_usage())

"""
Signaling Server
---------------
Handles the signaling between WebRTC peers for establishing P2P connections.
"""

import asyncio
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Models
class ConnectionRequest(BaseModel):
    """Model for connection requests."""

    client_id: str
    client_name: str
    public_key: str


class Message(BaseModel):
    """Model for signaling messages."""

    from_id: str
    to_id: str
    type: str
    content: Optional[Any] = None


# Connection manager
class ConnectionManager:
    """Manages active WebSocket connections and client information."""

    def __init__(self):
        """Initialize the connection manager."""
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_info: Dict[str, dict] = {}  # client_id -> {name, public_key, last_seen, online}
        self.rooms: Dict[str, Set[str]] = {}  # room_id -> set of client_ids

    async def connect(self, client_id: str, websocket: WebSocket):
        """Register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket

        # Update client info if it exists
        if client_id in self.client_info:
            self.client_info[client_id]["online"] = True
            logger.info(f"Client reconnected: {client_id}")
        else:
            logger.warning(f"New client connected without registration: {client_id}")

    def disconnect(self, client_id: str):
        """Handle client disconnection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]

            # Update client info if it exists
            if client_id in self.client_info:
                self.client_info[client_id]["online"] = False

            logger.info(f"Client disconnected: {client_id}")

        # Remove client from all rooms
        for room_id, clients in list(self.rooms.items()):
            if client_id in clients:
                clients.remove(client_id)

                # Notify other clients in the room
                self._notify_room_members(
                    room_id, {"type": "peer-left", "peer_id": client_id}, exclude=client_id
                )

                # Remove empty rooms
                if not clients:
                    del self.rooms[room_id]

    async def register_client(self, client_id: str, client_name: str, public_key: str):
        """Register a new client with the signaling server."""
        self.client_info[client_id] = {
            "name": client_name,
            "public_key": public_key,
            "online": client_id in self.active_connections,
            "last_seen": asyncio.get_event_loop().time(),
        }
        logger.info(f"Registered client: {client_id} ({client_name})")

    async def get_available_clients(self, exclude_id: str = None) -> List[dict]:
        """Get a list of all available clients."""
        return [{"id": cid, **info} for cid, info in self.client_info.items() if cid != exclude_id]

    async def join_room(self, client_id: str, room_id: str):
        """Add a client to a room."""
        if room_id not in self.rooms:
            self.rooms[room_id] = set()

        self.rooms[room_id].add(client_id)

        # Notify other clients in the room
        await self._notify_room_members(
            room_id,
            {
                "type": "peer-joined",
                "peer_id": client_id,
                "peer_info": self.client_info.get(client_id, {}),
            },
            exclude=client_id,
        )

        # Send list of peers already in the room to the new client
        peers = [
            {"id": pid, **self.client_info.get(pid, {})}
            for pid in self.rooms[room_id]
            if pid != client_id
        ]

        if client_id in self.active_connections:
            await self.send_message(
                client_id, {"type": "room-info", "room_id": room_id, "peers": peers}
            )

    async def leave_room(self, client_id: str, room_id: str):
        """Remove a client from a room."""
        if room_id in self.rooms and client_id in self.rooms[room_id]:
            self.rooms[room_id].remove(client_id)

            # Notify other clients in the room
            await self._notify_room_members(
                room_id, {"type": "peer-left", "peer_id": client_id}, exclude=client_id
            )

            # Remove empty rooms
            if not self.rooms[room_id]:
                del self.rooms[room_id]

    async def send_message(self, client_id: str, message: dict):
        """Send a message to a specific client."""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_text(json.dumps(message))
                return True
            except Exception as e:
                logger.error(f"Failed to send message to {client_id}: {e}")
                return False
        return False

    async def broadcast(self, message: dict, room_id: str, exclude: str = None):
        """Broadcast a message to all clients in a room."""
        if room_id not in self.rooms:
            return

        for client_id in list(self.rooms[room_id]):
            if client_id != exclude and client_id in self.active_connections:
                try:
                    await self.active_connections[client_id].send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to broadcast to {client_id}: {e}")

    async def _notify_room_members(self, room_id: str, message: dict, exclude: str = None):
        """Notify all members of a room about an event."""
        if room_id not in self.rooms:
            return

        for client_id in list(self.rooms[room_id]):
            if client_id != exclude:
                await self.send_message(client_id, message)


# Initialize FastAPI app
app = FastAPI(title="Scrambled Eggs Signaling Server")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize connection manager
manager = ConnectionManager()


# WebSocket endpoint
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for signaling."""
    # Register the connection
    await manager.connect(client_id, websocket)

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                await _handle_client_message(client_id, message)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from {client_id}")
            except Exception as e:
                logger.error(f"Error handling message from {client_id}: {e}")

    except WebSocketDisconnect:
        logger.info(f"Client disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}")
    finally:
        # Clean up on disconnect
        manager.disconnect(client_id)


# HTTP endpoints
@app.post("/register/")
async def register_client(request: ConnectionRequest):
    """Register a new client with the signaling server."""
    await manager.register_client(
        client_id=request.client_id, client_name=request.client_name, public_key=request.public_key
    )
    return {"status": "registered", "client_id": request.client_id}


@app.get("/clients/")
async def list_clients(exclude: str = None):
    """Get a list of all available clients."""
    clients = await manager.get_available_clients(exclude_id=exclude)
    return {"clients": clients}


# Message handling
async def _handle_client_message(sender_id: str, message: dict):
    """Handle incoming messages from clients."""
    msg_type = message.get("type")

    if msg_type == "join-room":
        # Client wants to join a room
        room_id = message.get("room_id")
        if room_id:
            await manager.join_room(sender_id, room_id)

    elif msg_type == "leave-room":
        # Client wants to leave a room
        room_id = message.get("room_id")
        if room_id:
            await manager.leave_room(sender_id, room_id)

    elif msg_type in ["offer", "answer", "ice-candidate", "message"]:
        # Forward signaling messages to the recipient
        recipient_id = message.get("to")
        if not recipient_id:
            logger.warning(f"No recipient specified in {msg_type} from {sender_id}")
            return

        # Add sender information to the message
        message["from"] = sender_id

        # Forward the message
        await manager.send_message(recipient_id, message)

    else:
        logger.warning(f"Unknown message type from {sender_id}: {msg_type}")


# Run the server
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "scrambled_eggs.signaling.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )

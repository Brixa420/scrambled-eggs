"""
Signaling server for peer discovery and session establishment.
"""
import asyncio
import json
import logging
import uuid
import time
from typing import Dict, List, Optional, Set, Tuple, Callable, Awaitable, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.models.contact import Contact, ContactStatus
from app.crypto.encryption_manager import EncryptionManager, KeyPair

logger = logging.getLogger(__name__)

# Type aliases
PeerID = str
ClientID = str

class ConnectionManager:
    """Manages WebSocket connections and peer discovery."""
    
    def __init__(self):
        """Initialize the connection manager."""
        self.active_connections: Dict[ClientID, WebSocket] = {}
        self.peer_registry: Dict[ClientID, PeerInfo] = {}
        self.pending_offers: Dict[str, Dict] = {}
        self.pending_answers: Dict[str, Dict] = {}
        self.ice_candidates: Dict[str, List[Dict]] = {}
        self.encryption = EncryptionManager()
        
        # Generate a server key pair for message signing
        self.server_key_pair = KeyPair.generate_ecc()
    
    async def connect(self, websocket: WebSocket, client_id: ClientID):
        """Register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"Client connected: {client_id}")
    
    def disconnect(self, client_id: ClientID):
        """Remove a WebSocket connection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        # Remove from peer registry
        if client_id in self.peer_registry:
            del self.peer_registry[client_id]
        
        # Clean up pending offers and answers
        for offer_id in list(self.pending_offers.keys()):
            if self.pending_offers[offer_id]["from"] == client_id or \
               self.pending_offers[offer_id]["to"] == client_id:
                del self.pending_offers[offer_id]
        
        for answer_id in list(self.pending_answers.keys()):
            if self.pending_answers[answer_id]["from"] == client_id or \
               self.pending_answers[answer_id]["to"] == client_id:
                del self.pending_answers[answer_id]
        
        # Clean up ICE candidates
        for peer_id in list(self.ice_candidates.keys()):
            if peer_id == client_id:
                del self.ice_candidates[peer_id]
            else:
                self.ice_candidates[peer_id] = [
                    c for c in self.ice_candidates[peer_id]
                    if c["from"] != client_id and c["to"] != client_id
                ]
        
        logger.info(f"Client disconnected: {client_id}")
    
    async def register_peer(self, client_id: ClientID, peer_info: 'PeerInfo'):
        """Register a peer with the signaling server."""
        self.peer_registry[client_id] = peer_info
        logger.info(f"Peer registered: {client_id} ({peer_info.username})")
    
    async def get_peers(self, exclude_client_id: Optional[ClientID] = None) -> List['PeerInfo']:
        """Get a list of all registered peers, optionally excluding one."""
        return [
            peer_info for client_id, peer_info in self.peer_registry.items()
            if client_id != exclude_client_id
        ]
    
    async def get_peer(self, client_id: ClientID) -> Optional['PeerInfo']:
        """Get information about a specific peer."""
        return self.peer_registry.get(client_id)
    
    async def send_message(self, client_id: ClientID, message: Dict):
        """Send a message to a specific client."""
        if client_id not in self.active_connections:
            logger.warning(f"Attempted to send message to disconnected client: {client_id}")
            return False
        
        try:
            await self.active_connections[client_id].send_json(message)
            return True
        except Exception as e:
            logger.error(f"Error sending message to {client_id}: {e}")
            return False
    
    async def broadcast(self, message: Dict, exclude: Optional[ClientID] = None):
        """Send a message to all connected clients, optionally excluding one."""
        for client_id, connection in list(self.active_connections.items()):
            if client_id != exclude:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id}: {e}")
    
    # WebRTC Signaling Methods
    
    async def handle_offer(self, from_client: ClientID, to_client: ClientID, offer: Dict):
        """Handle a WebRTC offer from one peer to another."""
        if to_client not in self.peer_registry:
            logger.warning(f"Offer to unknown client: {to_client}")
            return False
        
        # Store the offer
        offer_id = str(uuid.uuid4())
        self.pending_offers[offer_id] = {
            "id": offer_id,
            "from": from_client,
            "to": to_client,
            "offer": offer,
            "timestamp": time.time()
        }
        
        # Forward the offer to the target peer
        await self.send_message(to_client, {
            "type": "offer",
            "from": from_client,
            "offer": offer,
            "offer_id": offer_id
        })
        
        return True
    
    async def handle_answer(self, from_client: ClientID, to_client: ClientID, answer: Dict, offer_id: str):
        """Handle a WebRTC answer from a peer."""
        if to_client not in self.peer_registry:
            logger.warning(f"Answer to unknown client: {to_client}")
            return False
        
        # Store the answer
        answer_id = str(uuid.uuid4())
        self.pending_answers[answer_id] = {
            "id": answer_id,
            "from": from_client,
            "to": to_client,
            "answer": answer,
            "offer_id": offer_id,
            "timestamp": time.time()
        }
        
        # Forward the answer to the original offerer
        await self.send_message(to_client, {
            "type": "answer",
            "from": from_client,
            "answer": answer,
            "answer_id": answer_id,
            "offer_id": offer_id
        })
        
        return True
    
    async def handle_ice_candidate(self, from_client: ClientID, to_client: ClientID, candidate: Dict):
        """Handle an ICE candidate from a peer."""
        if to_client not in self.peer_registry:
            logger.warning(f"ICE candidate to unknown client: {to_client}")
            return False
        
        # Store the ICE candidate
        if to_client not in self.ice_candidates:
            self.ice_candidates[to_client] = []
        
        self.ice_candidates[to_client].append({
            "from": from_client,
            "candidate": candidate,
            "timestamp": time.time()
        })
        
        # Forward the ICE candidate to the target peer
        await self.send_message(to_client, {
            "type": "ice-candidate",
            "from": from_client,
            "candidate": candidate
        })
        
        return True
    
    async def get_ice_candidates(self, client_id: ClientID) -> List[Dict]:
        """Get all pending ICE candidates for a client."""
        candidates = self.ice_candidates.get(client_id, [])
        if client_id in self.ice_candidates:
            del self.ice_candidates[client_id]
        return candidates


class PeerInfo(BaseModel):
    """Information about a peer in the network."""
    client_id: str = Field(..., description="Unique identifier for the client")
    username: str = Field(..., description="Display name of the peer")
    public_key: str = Field(..., description="Base64-encoded public key for encryption")
    signature_public_key: str = Field(..., description="Base64-encoded public key for signatures")
    status: ContactStatus = Field(default=ContactStatus.ONLINE, description="Current status of the peer")
    last_seen: float = Field(default_factory=time.time, description="Timestamp of last activity")
    ip_address: Optional[str] = Field(None, description="IP address of the peer")
    port: Optional[int] = Field(None, description="Port number for direct connections")
    capabilities: List[str] = Field(default_factory=list, description="List of supported features")
    
    class Config:
        json_encoders = {
            ContactStatus: lambda v: v.value,
        }


class SignalingServer:
    """WebSocket-based signaling server for WebRTC peer connections."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        """Initialize the signaling server."""
        self.host = host
        self.port = port
        self.app = FastAPI()
        self.manager = ConnectionManager()
        
        # Set up CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Set up WebSocket endpoint
        @self.app.websocket("/ws/{client_id}")
        async def websocket_endpoint(websocket: WebSocket, client_id: str):
            await self.handle_connection(websocket, client_id)
        
        # Set up HTTP endpoints
        @self.app.get("/peers")
        async def get_peers():
            return await self.manager.get_peers()
        
        @self.app.get("/peers/{client_id}")
        async def get_peer(client_id: str):
            peer = await self.manager.get_peer(client_id)
            if peer is None:
                raise HTTPException(status_code=404, detail="Peer not found")
            return peer
        
        @self.app.get("/public-key")
        async def get_public_key():
            return {
                "public_key": self.manager.server_key_pair.get_public_key().decode('utf-8')
            }
    
    async def handle_connection(self, websocket: WebSocket, client_id: str):
        """Handle a new WebSocket connection."""
        await self.manager.connect(websocket, client_id)
        
        try:
            while True:
                # Wait for incoming messages
                data = await websocket.receive_text()
                
                try:
                    message = json.loads(data)
                    await self.handle_message(client_id, message)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON received from {client_id}")
                    await websocket.send_json({
                        "type": "error",
                        "message": "Invalid JSON"
                    })
                except Exception as e:
                    logger.error(f"Error handling message from {client_id}: {e}")
                    await websocket.send_json({
                        "type": "error",
                        "message": str(e)
                    })
                    
        except WebSocketDisconnect:
            logger.info(f"Client disconnected: {client_id}")
        except Exception as e:
            logger.error(f"WebSocket error for {client_id}: {e}")
        finally:
            self.manager.disconnect(client_id)
    
    async def handle_message(self, client_id: str, message: Dict):
        """Handle an incoming WebSocket message."""
        msg_type = message.get("type")
        
        if msg_type == "register":
            # Register a new peer
            peer_info = PeerInfo(
                client_id=client_id,
                username=message["username"],
                public_key=message["public_key"],
                signature_public_key=message.get("signature_public_key", ""),
                status=ContactStatus.ONLINE,
                capabilities=message.get("capabilities", []),
                ip_address=message.get("ip_address"),
                port=message.get("port")
            )
            await self.manager.register_peer(client_id, peer_info)
            
            # Send confirmation
            await self.manager.send_message(client_id, {
                "type": "registered",
                "client_id": client_id,
                "peers": [
                    peer.dict(exclude={"ip_address", "port"})
                    for peer in await self.manager.get_peers(exclude_client_id=client_id)
                ]
            })
            
            # Notify other peers about the new peer
            await self.manager.broadcast({
                "type": "peer-connected",
                "peer": peer_info.dict(exclude={"ip_address", "port"})
            }, exclude=client_id)
        
        elif msg_type == "offer":
            # Handle WebRTC offer
            to_client = message["to"]
            offer = message["offer"]
            await self.manager.handle_offer(client_id, to_client, offer)
        
        elif msg_type == "answer":
            # Handle WebRTC answer
            to_client = message["to"]
            answer = message["answer"]
            offer_id = message["offer_id"]
            await self.manager.handle_answer(client_id, to_client, answer, offer_id)
        
        elif msg_type == "ice-candidate":
            # Handle ICE candidate
            to_client = message["to"]
            candidate = message["candidate"]
            await self.manager.handle_ice_candidate(client_id, to_client, candidate)
        
        elif msg_type == "ping":
            # Handle ping (keep-alive)
            await self.manager.send_message(client_id, {"type": "pong"})
        
        elif msg_type == "get-peers":
            # Return list of peers
            peers = await self.manager.get_peers(exclude_client_id=client_id)
            await self.manager.send_message(client_id, {
                "type": "peers",
                "peers": [peer.dict(exclude={"ip_address", "port"}) for peer in peers]
            })
        
        elif msg_type == "update-status":
            # Update peer status
            if client_id in self.manager.peer_registry:
                self.manager.peer_registry[client_id].status = ContactStatus(message["status"])
                self.manager.peer_registry[client_id].last_seen = time.time()
                
                # Notify other peers about the status change
                await self.manager.broadcast({
                    "type": "peer-updated",
                    "client_id": client_id,
                    "status": message["status"]
                }, exclude=client_id)
        
        else:
            logger.warning(f"Unknown message type from {client_id}: {msg_type}")
            await self.manager.send_message(client_id, {
                "type": "error",
                "message": f"Unknown message type: {msg_type}"
            })
    
    async def start(self):
        """Start the signaling server."""
        import uvicorn
        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info",
            ws_ping_interval=30,
            ws_ping_timeout=60,
            timeout_keep_alive=5,
        )
        server = uvicorn.Server(config)
        await server.serve()
    
    @classmethod
    def create_and_run(cls, host: str = "0.0.0.0", port: int = 8765):
        """Create and run the signaling server."""
        server = cls(host=host, port=port)
        return asyncio.create_task(server.start())


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create and run the signaling server
    server = SignalingServer()
    print(f"Starting signaling server on ws://0.0.0.0:8765")
    
    try:
        import asyncio
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down signaling server...")

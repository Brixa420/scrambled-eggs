"""
Secure WebRTC signaling server with authentication and rate limiting.
Handles signaling between WebRTC peers for establishing direct connections.
"""
import asyncio
import json
import logging
import time
import hmac
import hashlib
import os
from typing import Dict, Set, Optional, Any, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

from aiohttp import web
import aiohttp_cors

logger = logging.getLogger(__name__)

@dataclass
class RateLimiter:
    """Simple rate limiter for WebSocket connections."""
    max_requests: int
    time_window: int  # in seconds
    
    def __post_init__(self):
        self.requests: Dict[str, List[float]] = {}
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if a client is allowed to make a request."""
        now = time.time()
        
        # Remove old timestamps
        if client_id in self.requests:
            self.requests[client_id] = [
                t for t in self.requests[client_id]
                if now - t < self.time_window
            ]
        
        # Add current request
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        # Check rate limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        self.requests[client_id].append(now)
        return True

class WebRTCSignalingServer:
    """Secure WebRTC signaling server with authentication and rate limiting."""
    
    def __init__(
        self, 
        host: str = '0.0.0.0', 
        port: int = 8080,
        secret_key: Optional[str] = None,
        rate_limit: int = 100,  # requests per minute
        max_message_size: int = 16 * 1024,  # 16KB
        auth_required: bool = True
    ):
        """Initialize the signaling server with security features.
        
        Args:
            host: Host to bind the server to
            port: Port to listen on
            secret_key: Secret key for token generation/validation
            rate_limit: Maximum requests per minute per client
            max_message_size: Maximum message size in bytes
            auth_required: Whether authentication is required
        """
        self.host = host
        self.port = port
        self.secret_key = secret_key or os.urandom(32).hex()
        self.max_message_size = max_message_size
        self.auth_required = auth_required
        
        # Rate limiting
        self.rate_limiter = RateLimiter(
            max_requests=rate_limit,
            time_window=60  # 1 minute
        )
        
        # WebSocket connections and rooms
        self.sockets: Dict[str, web.WebSocketResponse] = {}
        self.rooms: Dict[str, Set[str]] = {}
        self.peer_info: Dict[str, Dict[str, Any]] = {}  # Additional peer info
        
        # Set up the web application
        self.app = web.Application(client_max_size=max_message_size)
        self.setup_routes()
    
    def setup_routes(self) -> None:
        """Set up WebSocket routes and CORS configuration."""
        # Configure CORS with secure defaults
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                max_age=3600,  # 1 hour
            )
        })
        
        # Add WebSocket route
        resource = cors.add(self.app.router.add_resource('/ws'))
        cors.add(resource.add_route('GET', self.websocket_handler))
        
        # Add API endpoints
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/auth', self.handle_auth)
        
        # Add error middleware
        self.app.middlewares.append(self.error_middleware)
    
    @web.middleware
    async def error_middleware(self, request, handler):
        """Global error handling middleware."""
        try:
            return await handler(request)
        except web.HTTPException as ex:
            return web.json_response(
                {'error': ex.reason},
                status=ex.status
            )
        except Exception as e:
            logger.exception("Unexpected error")
            return web.json_response(
                {'error': 'Internal server error'},
                status=500
            )
    
    def generate_auth_token(self, peer_id: str, room_id: str) -> str:
        """Generate an authentication token for a peer."""
        timestamp = str(int(time.time()))
        message = f"{peer_id}:{room_id}:{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{message}:{signature}"
    
    def verify_auth_token(self, token: str) -> Tuple[bool, str, str]:
        """Verify an authentication token and return (is_valid, peer_id, room_id)."""
        try:
            parts = token.split(':')
            if len(parts) != 4:
                return False, "", ""
                
            peer_id, room_id, timestamp, signature = parts
            
            # Check if token is expired (5 minutes)
            if int(time.time()) - int(timestamp) > 300:
                return False, "", ""
            
            # Verify signature
            message = f"{peer_id}:{room_id}:{timestamp}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False, "", ""
                
            return True, peer_id, room_id
        except Exception:
            return False, "", ""
    
    async def handle_auth(self, request: web.Request) -> web.Response:
        """Handle authentication requests."""
        peer_id = request.query.get('peer_id')
        room_id = request.query.get('room_id', 'default')
        
        if not peer_id:
            raise web.HTTPBadRequest(reason="Peer ID is required")
        
        # In a real application, verify the user's identity here
        # For this example, we'll just generate a token for any peer_id
        
        token = self.generate_auth_token(peer_id, room_id)
        return web.json_response({
            'token': token,
            'peer_id': peer_id,
            'room_id': room_id,
            'expires_in': 300  # 5 minutes
        })
    
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint with server status."""
        return web.json_response({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat(),
            'peers_connected': len(self.sockets),
            'active_rooms': len(self.rooms),
            'auth_required': self.auth_required
        })
    
    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connections with authentication and rate limiting."""
        # Check rate limiting by client IP
        client_ip = request.remote or 'unknown'
        if not self.rate_limiter.is_allowed(f"ws_connect_{client_ip}"):
            raise web.HTTPTooManyRequests(
                reason="Rate limit exceeded. Please try again later."
            )
        
        ws = web.WebSocketResponse(max_msg_size=self.max_message_size)
        await ws.prepare(request)
        
        # Get query parameters
        peer_id = request.query.get('peer_id')
        room_id = request.query.get('room_id', 'default')
        auth_token = request.query.get('token')
        
        # Validate authentication if required
        if self.auth_required:
            if not auth_token:
                await ws.close(code=4003, message='Authentication required')
                return ws
                
            is_valid, token_peer_id, token_room_id = self.verify_auth_token(auth_token)
            if not is_valid or token_peer_id != peer_id or token_room_id != room_id:
                await ws.close(code=4001, message='Invalid authentication token')
                return ws
        
        if not peer_id:
            await ws.close(code=4000, message='peer_id is required')
            return ws
        
        # Check if peer ID is already in use
        if peer_id in self.sockets:
            await ws.close(code=4002, message='Peer ID already in use')
            return ws
        
        logger.info(f"New WebSocket connection: peer_id={peer_id}, room_id={room_id}")
        
        # Register the peer
        self.sockets[peer_id] = ws
        self.peer_info[peer_id] = {
            'ip': client_ip,
            'user_agent': request.headers.get('User-Agent', ''),
            'connected_at': time.time(),
            'last_active': time.time()
        }
        
        # Add peer to room
        if room_id not in self.rooms:
            self.rooms[room_id] = set()
        self.rooms[room_id].add(peer_id)
        
        try:
            # Notify other peers in the room
            await self.notify_peers(peer_id, room_id, {
                'type': 'peer-joined',
                'peer_id': peer_id,
                'timestamp': time.time()
            })
            
            # Send list of peers already in the room
            peers = [p for p in self.rooms[room_id] if p != peer_id]
            await self.send_to_peer(peer_id, {
                'type': 'peers',
                'peers': peers,
                'timestamp': time.time()
            })
            
            # Handle incoming messages
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    # Update last active time
                    self.peer_info[peer_id]['last_active'] = time.time()
                    
                    # Check message size
                    if len(msg.data) > self.max_message_size:
                        logger.warning(f"Message too large from {peer_id}")
                        continue
                    
                    try:
                        data = json.loads(msg.data)
                        await self.handle_message(peer_id, room_id, data)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON message from {peer_id}")
                    except Exception as e:
                        logger.error(f"Error handling message: {e}", exc_info=True)
                elif msg.type == web.WSMsgType.ERROR:
                    logger.error(f"WebSocket error from {peer_id}: {ws.exception()}")
                    break
                
        except asyncio.CancelledError:
            logger.info(f"Connection cancelled for {peer_id}")
        except Exception as e:
            logger.error(f"Error in WebSocket handler for {peer_id}: {e}")
        finally:
            # Clean up on disconnect
            await self.handle_disconnect(peer_id, room_id)
        
        return ws
    
    async def handle_message(self, peer_id: str, room_id: str, data: Dict[str, Any]) -> None:
        """Handle incoming WebSocket messages with validation and rate limiting."""
        msg_type = data.get('type')
        target_peer_id = data.get('target_peer_id')
        
        # Validate message type
        if not msg_type or not isinstance(msg_type, str):
            logger.warning(f"Invalid message type from {peer_id}")
            return
        
        # Validate target peer for direct messages
        if msg_type in ['offer', 'answer', 'candidate']:
            if not target_peer_id or not isinstance(target_peer_id, str):
                logger.warning(f"Invalid target peer from {peer_id}")
                return
                
            if target_peer_id not in self.sockets:
                logger.warning(f"Target peer not found: {target_peer_id}")
                return
            
            # Rate limit signaling messages
            rate_limit_key = f"{peer_id}_{msg_type}"
            if not self.rate_limiter.is_allowed(rate_limit_key):
                logger.warning(f"Rate limit exceeded for {peer_id} ({msg_type})")
                return
        
        # Forward the message to the target peer
        if msg_type in ['offer', 'answer', 'candidate'] and target_peer_id in self.sockets:
            await self.send_to_peer(target_peer_id, {
                **data,
                'sender_id': peer_id,
                'timestamp': time.time()
            })
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    async def handle_disconnect(self, peer_id: str, room_id: str) -> None:
        """Handle peer disconnection with cleanup."""
        logger.info(f"Peer disconnected: {peer_id}")
        
        # Remove peer from room
        if room_id in self.rooms and peer_id in self.rooms[room_id]:
            self.rooms[room_id].remove(peer_id)
            
            # Notify other peers
            if room_id in self.rooms:  # Check if room still exists
                await self.notify_peers(peer_id, room_id, {
                    'type': 'peer-left',
                    'peer_id': peer_id,
                    'timestamp': time.time()
                })
            
            # Clean up empty rooms
            if not self.rooms[room_id]:
                del self.rooms[room_id]
        
        # Remove WebSocket connection and peer info
        if peer_id in self.sockets:
            try:
                await self.sockets[peer_id].close()
            except Exception as e:
                logger.error(f"Error closing WebSocket for {peer_id}: {e}")
            finally:
                del self.sockets[peer_id]
        
        if peer_id in self.peer_info:
            del self.peer_info[peer_id]
    
    async def send_to_peer(self, peer_id: str, data: Dict[str, Any]) -> None:
        """Send a message to a specific peer with error handling."""
        if peer_id in self.sockets:
            try:
                await self.sockets[peer_id].send_json(data)
                return
            except Exception as e:
                logger.error(f"Error sending message to {peer_id}: {e}")
                # Clean up broken connection
                if peer_id in self.sockets:
                    await self.handle_disconnect(peer_id, self.peer_info[peer_id].get('room_id', 'unknown'))
        
        logger.warning(f"Could not send message to {peer_id}: Peer not connected")
    
    async def notify_peers(self, sender_id: str, room_id: str, data: Dict[str, Any]) -> None:
        """Notify all peers in a room except the sender with error handling."""
        if room_id not in self.rooms:
            return
            
        disconnected_peers = []
        
        for peer_id in self.rooms[room_id]:
            if peer_id != sender_id:
                try:
                    await self.send_to_peer(peer_id, data)
                except Exception as e:
                    logger.error(f"Error notifying peer {peer_id}: {e}")
                    disconnected_peers.append(peer_id)
        
        # Clean up disconnected peers
        for peer_id in disconnected_peers:
            if peer_id in self.peer_info:
                peer_room = self.peer_info[peer_id].get('room_id')
                if peer_room:
                    await self.handle_disconnect(peer_id, peer_room)
    
    async def start(self) -> None:
        """Start the signaling server with graceful shutdown handling."""
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Start the server
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info(f"Secure signaling server started on {self.host}:{self.port}")
        
        try:
            # Keep the server running
            while True:
                await asyncio.sleep(3600)  # Sleep for 1 hour
        except asyncio.CancelledError:
            logger.info("Shutdown signal received")
        finally:
            await self.stop()
    
    async def stop(self) -> None:
        """Stop the signaling server and clean up resources."""
        logger.info("Shutting down signaling server...")
        
        # Close all WebSocket connections
        for peer_id in list(self.sockets.keys()):
            if peer_id in self.peer_info:
                room_id = self.peer_info[peer_id].get('room_id', 'unknown')
                await self.handle_disconnect(peer_id, room_id)
            else:
                if peer_id in self.sockets:
                    try:
                        await self.sockets[peer_id].close()
                    except Exception as e:
                        logger.error(f"Error closing WebSocket for {peer_id}: {e}")
        
        # Clear all data structures
        self.sockets.clear()
        self.rooms.clear()
        self.peer_info.clear()
        
        logger.info("Signaling server stopped")

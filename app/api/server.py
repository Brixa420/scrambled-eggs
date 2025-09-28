"""
Flask server for Scrambled Eggs API and WebSocket communication.
"""
import os
import json
import logging
import asyncio
from functools import wraps
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable, Awaitable

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet

from app.core.config import get_config
from app.core.contact_manager import ContactManager, generate_contact_id, generate_key_pair
from app.core.file_transfer import FileTransferManager
from app.crypto.scrambled_eggs_encryption import ScrambledEggsEncryption
from app.network.tor_integration import TorManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='../../frontend/build', static_url_path='')
CORS(app)

# Configure SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=True,
    engineio_logger=True,
    ping_timeout=30,
    ping_interval=25,
    max_http_buffer_size=100 * 1024 * 1024  # 100MB
)

# Initialize managers
config = get_config()
contact_manager = ContactManager()
file_transfer_manager = FileTransferManager()
encryption = ScrambledEggsEncryption()
tor_manager = TorManager()

# Store active connections and user sessions
active_connections: Dict[str, Dict[str, Any]] = {}

# Authentication decorator
def authenticated_only(f: Callable) -> Callable:
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not request.sid or request.sid not in active_connections:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped

# SocketIO event handlers
@socketio.on('connect')
def handle_connect() -> None:
    """Handle new WebSocket connection."""
    logger.info(f"Client connected: {request.sid}")
    emit('connection_response', {'data': 'Connected to Scrambled Eggs'})

@socketio.on('disconnect')
def handle_disconnect() -> None:
    """Handle client disconnection."""
    logger.info(f"Client disconnected: {request.sid}")
    
    # Clean up user session
    if request.sid in active_connections:
        user_id = active_connections[request.sid].get('user_id')
        if user_id:
            logger.info(f"User {user_id} disconnected")
            # Notify contacts about offline status
            emit('user_status', {
                'user_id': user_id,
                'status': 'offline',
                'last_seen': datetime.now(timezone.utc).isoformat()
            }, broadcast=True, skip_sid=request.sid)
        
        # Remove from active connections
        del active_connections[request.sid]

@socketio.on('authenticate')
def handle_authentication(data: Dict[str, Any]) -> None:
    """Handle user authentication."""
    try:
        user_id = data.get('user_id')
        public_key = data.get('public_key')
        
        if not user_id or not public_key:
            emit('authentication_failed', {'error': 'Missing user_id or public_key'})
            return
        
        # Store connection info
        active_connections[request.sid] = {
            'user_id': user_id,
            'public_key': public_key,
            'last_seen': datetime.now(timezone.utc),
            'status': 'online'
        }
        
        logger.info(f"User {user_id} authenticated with SID {request.sid}")
        
        # Join user's room for private messages
        join_room(f"user_{user_id}")
        
        # Notify user of successful authentication
        emit('authentication_success', {
            'user_id': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        # Notify contacts about online status
        emit('user_status', {
            'user_id': user_id,
            'status': 'online',
            'last_seen': datetime.now(timezone.utc).isoformat()
        }, broadcast=True, skip_sid=request.sid)
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        emit('authentication_failed', {'error': str(e)})

@socketio.on('send_message')
@authenticated_only
def handle_send_message(data: Dict[str, Any]) -> None:
    """Handle sending a message to another user."""
    try:
        sender_id = active_connections[request.sid]['user_id']
        recipient_id = data.get('recipient_id')
        encrypted_content = data.get('encrypted_content')
        message_id = data.get('message_id')
        
        if not all([recipient_id, encrypted_content, message_id]):
            emit('message_error', {
                'message_id': message_id,
                'error': 'Missing required fields'
            })
            return
        
        # Get recipient's connection
        recipient_sid = None
        for sid, conn in active_connections.items():
            if conn.get('user_id') == recipient_id:
                recipient_sid = sid
                break
        
        # If recipient is online, forward the message
        if recipient_sid:
            emit('receive_message', {
                'message_id': message_id,
                'sender_id': sender_id,
                'encrypted_content': encrypted_content,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, room=f"user_{recipient_id}")
        
        # Acknowledge message delivery
        emit('message_delivered', {
            'message_id': message_id,
            'recipient_id': recipient_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        logger.info(f"Message {message_id} delivered from {sender_id} to {recipient_id}")
        
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        emit('message_error', {
            'message_id': data.get('message_id', 'unknown'),
            'error': str(e)
        })

@socketio.on('start_file_transfer')
@authenticated_only
def handle_start_file_transfer(data: Dict[str, Any]) -> None:
    """Initiate a file transfer."""
    try:
        sender_id = active_connections[request.sid]['user_id']
        recipient_id = data.get('recipient_id')
        file_metadata = data.get('file_metadata')
        
        if not all([recipient_id, file_metadata]):
            emit('file_transfer_error', {
                'transfer_id': data.get('transfer_id'),
                'error': 'Missing required fields'
            })
            return
        
        # Notify recipient about incoming file transfer
        emit('incoming_file_transfer', {
            'transfer_id': data.get('transfer_id'),
            'sender_id': sender_id,
            'file_metadata': file_metadata,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=f"user_{recipient_id}")
        
        # Acknowledge transfer initiation
        emit('file_transfer_started', {
            'transfer_id': data.get('transfer_id'),
            'recipient_id': recipient_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error starting file transfer: {e}")
        emit('file_transfer_error', {
            'transfer_id': data.get('transfer_id', 'unknown'),
            'error': str(e)
        })

# REST API endpoints
@app.route('/api/health')
def health_check() -> Response:
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/contacts', methods=['GET'])
@authenticated_only
def get_contacts() -> Response:
    """Get user's contacts."""
    try:
        user_id = active_connections[request.sid]['user_id']
        contacts = contact_manager.get_contacts()
        return jsonify({
            'status': 'success',
            'contacts': [contact.to_dict() for contact in contacts]
        })
    except Exception as e:
        logger.error(f"Error getting contacts: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/messages/<recipient_id>', methods=['GET'])
@authenticated_only
def get_messages(recipient_id: str) -> Response:
    """Get messages with a specific contact."""
    try:
        user_id = active_connections[request.sid]['user_id']
        # In a real app, you would fetch messages from the database
        # For now, return an empty list
        return jsonify({
            'status': 'success',
            'messages': []
        })
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

# Serve React app
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path: str) -> Response:
    """Serve the React app."""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

def run_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
    """Run the Flask server."""
    # Start Tor if enabled
    if config.network.enable_tor:
        try:
            tor_manager.start()
            logger.info(f"Tor service started on port {tor_manager.socks_port}")
        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
    
    # Start the SocketIO server
    logger.info(f"Starting Scrambled Eggs server on {host}:{port}")
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=debug,
        log_output=debug
    )

if __name__ == '__main__':
    run_server(debug=True)

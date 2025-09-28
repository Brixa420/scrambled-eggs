"""
WebRTC signaling server for P2P connections.
"""
import json
import logging
from flask import request, jsonify
from flask_socketio import emit, join_room, leave_room
from ..extensions import socketio

# Store active peer connections
active_peers = {}

def init_signaling(socketio):
    """Initialize WebSocket event handlers for signaling."""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle new WebSocket connection."""
        logging.info(f"Client connected: {request.sid}")
        emit('connection_success', {'sid': request.sid})

    @socketio.on('join')
    def handle_join(data):
        """Handle peer joining a room."""
        room = data.get('room')
        user_id = data.get('user_id')
        if not room or not user_id:
            return
            
        join_room(room)
        active_peers[request.sid] = {
            'room': room,
            'user_id': user_id,
            'sid': request.sid
        }
        logging.info(f"User {user_id} joined room {room}")
        emit('user_joined', {'user_id': user_id}, room=room, include_self=False)

    @socketio.on('offer')
    def handle_offer(data):
        """Handle WebRTC offer."""
        to = data.get('to')
        offer = data.get('offer')
        if not to or not offer:
            return
            
        sender = active_peers.get(request.sid, {})
        emit('offer', {
            'from': sender.get('user_id'),
            'offer': offer
        }, room=to)

    @socketio.on('answer')
    def handle_answer(data):
        """Handle WebRTC answer."""
        to = data.get('to')
        answer = data.get('answer')
        if not to or not answer:
            return
            
        sender = active_peers.get(request.sid, {})
        emit('answer', {
            'from': sender.get('user_id'),
            'answer': answer
        }, room=to)

    @socketio.on('ice_candidate')
    def handle_ice_candidate(data):
        """Handle ICE candidate exchange."""
        to = data.get('to')
        candidate = data.get('candidate')
        if not to or not candidate:
            return
            
        emit('ice_candidate', {
            'candidate': candidate
        }, room=to)

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection."""
        peer = active_peers.pop(request.sid, None)
        if peer:
            room = peer.get('room')
            user_id = peer.get('user_id')
            if room and user_id:
                leave_room(room)
                emit('user_left', {'user_id': user_id}, room=room)
                logging.info(f"User {user_id} left room {room}")

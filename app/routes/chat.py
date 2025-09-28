"""
Chat functionality routes.
"""
from flask import render_template, jsonify, request, current_app
from flask_login import login_required, current_user
from ..models.message import Message
from . import main
from datetime import datetime

@main.route('/chat')
@login_required
def chat():
    """Render the chat interface."""
    return render_template('chat/index.html')

@main.route('/api/messages', methods=['GET'])
@login_required
def get_messages():
    """Get recent messages."""
    limit = min(int(request.args.get('limit', 50)), 100)
    messages = Message.query.order_by(Message.timestamp.desc()).limit(limit).all()
    return jsonify([{
        'id': msg.id,
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat(),
        'user': {
            'id': msg.user_id,
            'username': msg.author.username
        }
    } for msg in messages])

@main.route('/api/messages', methods=['POST'])
@login_required
def send_message():
    """Send a new message."""
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({'error': 'Message content is required'}), 400
    
    message = Message(
        content=data['content'],
        user_id=current_user.id,
        timestamp=datetime.utcnow()
    )
    
    db.session.add(message)
    db.session.commit()
    
    # Emit the new message to all connected clients
    socketio.emit('new_message', {
        'id': message.id,
        'content': message.content,
        'timestamp': message.timestamp.isoformat(),
        'user': {
            'id': current_user.id,
            'username': current_user.username
        }
    })
    
    return jsonify({'status': 'success', 'message_id': message.id}), 201

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection."""
    if current_user.is_authenticated:
        current_app.logger.info(f'User {current_user.username} connected to chat')
        socketio.emit('user_connected', {'user_id': current_user.id, 'username': current_user.username})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    if current_user.is_authenticated:
        current_app.logger.info(f'User {current_user.username} disconnected from chat')
        socketio.emit('user_disconnected', {'user_id': current_user.id, 'username': current_user.username})

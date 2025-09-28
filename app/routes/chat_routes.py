"""
Chat routes for the Scrambled Eggs application.
"""
from flask import Blueprint, render_template, request, jsonify, session, current_app
from flask_socketio import emit, join_room, leave_room
from ..extensions import socketio
from ..services.chat_service import ChatService

# Create blueprint
chat_bp = Blueprint('chat', __name__, url_prefix='/chat')

# Initialize chat service
chat_service = ChatService()

# Dictionary to store active users and their rooms
active_users = {}

@chat_bp.route('/')
def chat():
    """Render the chat interface."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    return render_template('chat.html', user_id=session['user_id'])

@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection."""
    if 'user_id' not in session:
        return False
    
    user_id = session['user_id']
    active_users[request.sid] = user_id
    emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    emit('status', {'message': f'Connected as {user_id}'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    if request.sid in active_users:
        user_id = active_users.pop(request.sid)
        emit('user_left', {'user_id': user_id}, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    """Handle joining a chat room."""
    room = data.get('room')
    if not room:
        return
    
    join_room(room)
    emit('room_joined', {'room': room})

@socketio.on('leave_room')
def handle_leave_room(data):
    """Handle leaving a chat room."""
    room = data.get('room')
    if not room:
        return
    
    leave_room(room)
    emit('room_left', {'room': room})

@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending a chat message."""
    room = data.get('room')
    message = data.get('message')
    
    if not all([room, message]):
        return
    
    if request.sid not in active_users:
        return
    
    user_id = active_users[request.sid]
    
    # Encrypt the message before sending
    try:
        encrypted_message = current_app.encryption_manager.encrypt_message(message)
        
        # Store the message (you can implement this in ChatService)
        chat_service.store_message(room, user_id, message, encrypted_message)
        
        # Broadcast the message to the room
        emit('new_message', {
            'user_id': user_id,
            'message': message,
            'encrypted_message': encrypted_message,
            'timestamp': datetime.utcnow().isoformat()
        }, room=room)
    except Exception as e:
        current_app.logger.error(f"Error sending message: {str(e)}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator."""
    room = data.get('room')
    is_typing = data.get('is_typing', False)
    
    if not room or request.sid not in active_users:
        return
    
    user_id = active_users[request.sid]
    emit('user_typing', {
        'user_id': user_id,
        'is_typing': is_typing
    }, room=room, include_self=False)

# Register the blueprint with the app
def init_chat_routes(app):
    """Initialize chat routes with the Flask app."""
    app.register_blueprint(chat_bp)
    
    # Register socketio events
    socketio.on_event('connect', handle_connect)
    socketio.on_event('disconnect', handle_disconnect)
    socketio.on_event('join_room', handle_join_room)
    socketio.on_event('leave_room', handle_leave_room)
    socketio.on_event('send_message', handle_send_message)
    socketio.on_event('typing', handle_typing)
    
    return app

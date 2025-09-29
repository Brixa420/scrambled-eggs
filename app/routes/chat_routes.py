"""
Chat routes for the Scrambled Eggs application.
"""

import logging
from typing import Any, Dict

from flask import Blueprint, render_template, request, session
from flask_socketio import emit, join_room, leave_room

from ..extensions import socketio
from ..services.chat_service import ChatService
from ..services.llm_service import LLMService

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
chat_bp = Blueprint("chat", __name__, url_prefix="/chat")

# Initialize services
chat_service = ChatService()
llm_service = LLMService()

# Dictionary to store active users and their rooms
active_users = {}

# In-memory store for tracking message processing status
processing_messages: Dict[str, bool] = {}


@chat_bp.route("/")
def chat():
    """Render the chat interface."""
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    return render_template("chat.html", user_id=session["user_id"])


@socketio.on("connect")
def handle_connect():
    """Handle new WebSocket connection."""
    try:
        if "user_id" not in session:
            logger.warning("Unauthenticated connection attempt")
            return False

        user_id = session["user_id"]
        active_users[request.sid] = user_id

        # Notify everyone about the updated user list
        emit("user_list", {"users": list(active_users.values())}, broadcast=True)

        # Send connection status to the connected user
        emit("status", {"type": "success", "message": f"Connected as {user_id}"})

        logger.info(f"User {user_id} connected with SID {request.sid}")
        return True

    except Exception as e:
        logger.error(f"Error in handle_connect: {str(e)}", exc_info=True)
        emit("status", {"type": "error", "message": "Failed to establish connection"})
        return False


@socketio.on("disconnect")
def handle_disconnect():
    """Handle client disconnection."""
    try:
        if request.sid in active_users:
            user_id = active_users.pop(request.sid)
            emit(
                "user_left",
                {"user_id": user_id, "timestamp": datetime.utcnow().isoformat()},
                broadcast=True,
            )
            logger.info(f"User {user_id} disconnected")
    except Exception as e:
        logger.error(f"Error in handle_disconnect: {str(e)}", exc_info=True)


@socketio.on("join_room")
def handle_join_room(data):
    """Handle joining a chat room."""
    room = data.get("room")
    if not room:
        return

    join_room(room)
    emit("room_joined", {"room": room})


@socketio.on("leave_room")
def handle_leave_room(data):
    """Handle leaving a chat room."""
    room = data.get("room")
    if not room:
        return

    leave_room(room)
    emit("room_left", {"room": room})


@socketio.on("send_message")
def handle_send_message(data: Dict[str, Any]) -> None:
    """
    Handle sending a chat message with LLM response generation.

    Args:
        data: Dictionary containing:
            - content: The message content
            - room_id: Optional room ID
            - requires_llm: Whether to generate an LLM response
    """
    message_id = data.get("message_id")
    if not message_id:
        emit("error", {"message": "Message ID is required"})
        return

    try:
        user_id = session.get("user_id")
        if not user_id:
            emit("error", {"message": "Authentication required"}, room=request.sid)
            return

        content = data.get("content", "").strip()
        if not content:
            emit("error", {"message": "Message content cannot be empty"}, room=request.sid)
            return

        # Mark message as processing
        processing_messages[message_id] = True
        emit(
            "message_status",
            {
                "message_id": message_id,
                "status": "processing",
                "timestamp": datetime.utcnow().isoformat(),
            },
            room=request.sid,
        )

        # Save the user's message
        try:
            message = chat_service.send_message(
                user_id=user_id, content=content, room_id=data.get("room_id"), message_type="user"
            )

            # Broadcast the user's message
            emit(
                "new_message",
                {
                    "id": message.id,
                    "user_id": user_id,
                    "content": message.content,
                    "timestamp": message.timestamp.isoformat(),
                    "room_id": message.room_id,
                    "status": "delivered",
                },
                room=data.get("room_id", ""),
                broadcast=True,
            )

            # If LLM response is requested
            if data.get("requires_llm", False):
                # Get conversation history for context
                history = chat_service.get_conversation_history(
                    user_id=user_id,
                    room_id=data.get("room_id"),
                    limit=5,  # Last 5 messages for context
                )

                # Generate LLM response in a background task
                @socketio.start_background_task
                def generate_llm_response():
                    try:
                        # Mark as processing LLM response
                        emit(
                            "message_status",
                            {
                                "message_id": f"llm_{message_id}",
                                "status": "processing",
                                "timestamp": datetime.utcnow().isoformat(),
                            },
                            room=request.sid,
                        )

                        # Prepare the prompt with conversation history
                        context = "\n".join(
                            [
                                f"{'User' if msg.user_id == user_id else 'Assistant'}: {msg.content}"
                                for msg in history
                            ]
                        )

                        prompt = f"""Previous conversation:
{context}

User: {content}
Assistant:"""

                        # Generate response from LLM
                        llm_response = llm_service.generate_response(
                            prompt=prompt,
                            system_prompt="You are a helpful AI assistant. Keep your responses concise and relevant.",
                            temperature=0.7,
                            max_tokens=500,
                        )

                        # Save LLM response
                        llm_message = chat_service.send_message(
                            user_id="llm",  # Special user ID for AI responses
                            content=llm_response,
                            room_id=data.get("room_id"),
                            message_type="ai",
                        )

                        # Broadcast LLM response
                        emit(
                            "new_message",
                            {
                                "id": llm_message.id,
                                "user_id": "llm",
                                "content": llm_response,
                                "timestamp": llm_message.timestamp.isoformat(),
                                "room_id": llm_message.room_id,
                                "status": "delivered",
                            },
                            room=data.get("room_id", ""),
                            broadcast=True,
                        )

                    except Exception as e:
                        logger.error(f"Error generating LLM response: {str(e)}", exc_info=True)
                        emit(
                            "error",
                            {"message": "Failed to generate AI response", "details": str(e)},
                            room=request.sid,
                        )
                    finally:
                        # Clean up
                        if message_id in processing_messages:
                            del processing_messages[message_id]

                # Start the background task
                generate_llm_response()

        except Exception as e:
            logger.error(f"Error processing message: {str(e)}", exc_info=True)
            emit(
                "message_status",
                {
                    "message_id": message_id,
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                },
                room=request.sid,
            )

    except Exception as e:
        logger.error(f"Unexpected error in handle_send_message: {str(e)}", exc_info=True)
        emit(
            "error",
            {"message": "An unexpected error occurred", "details": str(e)},
            room=request.sid,
        )
    finally:
        # Clean up if not already done
        if message_id in processing_messages:
            del processing_messages[message_id]


@socketio.on("typing")
def handle_typing(data):
    """Handle typing indicator."""
    try:
        room = data.get("room")
        is_typing = data.get("is_typing", False)

        if not room or request.sid not in active_users:
            return

        user_id = active_users[request.sid]
        emit(
            "user_typing",
            {
                "user_id": user_id,
                "is_typing": is_typing,
                "room": room,
                "timestamp": datetime.utcnow().isoformat(),
            },
            room=room,
            skip_sid=request.sid,
        )

    except Exception as e:
        logger.error(f"Error in handle_typing: {str(e)}", exc_info=True)


# Register the blueprint with the app
def init_chat_routes(app):
    """Initialize chat routes with the Flask app."""
    app.register_blueprint(chat_bp)

    # Register socketio events
    socketio.on_event("connect", handle_connect)
    socketio.on_event("disconnect", handle_disconnect)
    socketio.on_event("join_room", handle_join_room)
    socketio.on_event("leave_room", handle_leave_room)
    socketio.on_event("send_message", handle_send_message)
    socketio.on_event("typing", handle_typing)

    return app

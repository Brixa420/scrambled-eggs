"""
LLM Chat API endpoints for the Scrambled Eggs application.
"""

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ..db.base import SessionLocal
from ..models.conversation import Conversation, Message
from ..models.user import User
from ..services.llm_service import LLMService

# Create blueprint
llm_bp = Blueprint("llm", __name__, url_prefix="/api/llm")

# Initialize services
llm_service = LLMService()

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"],
)


def get_user_conversation(user_id, conversation_id=None):
    """Get or create a conversation for the user."""
    db = SessionLocal()
    try:
        if conversation_id:
            conversation = (
                db.query(Conversation)
                .filter(Conversation.id == conversation_id, Conversation.user_id == user_id)
                .first()
            )
            if not conversation:
                return None, "Conversation not found"
            return conversation, None

        # Create new conversation if none exists
        conversation = Conversation(user_id=user_id)
        db.add(conversation)
        db.commit()
        return conversation, None

    except Exception as e:
        db.rollback()
        return None, str(e)
    finally:
        db.close()


def save_message(conversation_id, role, content):
    """Save a message to the conversation."""
    db = SessionLocal()
    try:
        message = Message(conversation_id=conversation_id, role=role, content=content)
        db.add(message)
        db.commit()
        return message, None
    except Exception as e:
        db.rollback()
        return None, str(e)
    finally:
        db.close()


@llm_bp.route("/conversations", methods=["GET"])
@jwt_required()
@limiter.limit("30 per minute")
def list_conversations():
    """List all conversations for the current user."""
    user_id = get_jwt_identity()
    db = SessionLocal()
    try:
        conversations = (
            db.query(Conversation)
            .filter(Conversation.user_id == user_id)
            .order_by(Conversation.updated_at.desc())
            .all()
        )

        return jsonify(
            [
                {
                    "id": conv.id,
                    "title": conv.title or f"Conversation {conv.id}",
                    "created_at": conv.created_at.isoformat(),
                    "updated_at": conv.updated_at.isoformat(),
                }
                for conv in conversations
            ]
        )

    except Exception as e:
        current_app.logger.error(f"Error listing conversations: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@llm_bp.route("/chat", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
def chat():
    """
    Handle chat messages with the LLM.
    Expected JSON payload:
    {
        "message": "Your message here",
        "conversation_id": "optional-conversation-id",
        "temperature": 0.7,
        "max_tokens": 500
    }
    """
    data = request.get_json()
    message = data.get("message")
    conversation_id = data.get("conversation_id")

    if not message:
        return jsonify({"error": "Message is required"}), 400

    user_id = get_jwt_identity()
    db = SessionLocal()

    try:
        # Get or create conversation
        conversation, error = get_user_conversation(user_id, conversation_id)
        if error:
            return jsonify({"error": error}), 404

        # Get user context
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Save user message
        user_message, error = save_message(conversation.id, "user", message)
        if error:
            return jsonify({"error": error}), 500

        # Get conversation history
        messages = (
            db.query(Message)
            .filter(Message.conversation_id == conversation.id)
            .order_by(Message.created_at.asc())
            .all()
        )

        # Format messages for the LLM
        chat_history = [{"role": msg.role, "content": msg.content} for msg in messages]

        # Generate response
        response = llm_service.generate_response(
            messages=chat_history,
            temperature=float(data.get("temperature", 0.7)),
            max_tokens=int(data.get("max_tokens", 500)),
        )

        # Save AI response
        ai_message, error = save_message(conversation.id, "assistant", response)
        if error:
            current_app.logger.error(f"Error saving AI message: {error}")

        # Update conversation timestamp
        conversation.updated_at = datetime.utcnow()
        db.commit()

        return jsonify(
            {
                "response": response,
                "conversation_id": str(conversation.id),
                "message_id": str(ai_message.id) if ai_message else None,
            }
        )

    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Error in LLM chat: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@llm_bp.route("/conversations/<conversation_id>", methods=["GET"])
@jwt_required()
@limiter.limit("30 per minute")
def get_conversation(conversation_id):
    """Get a specific conversation with its messages."""
    user_id = get_jwt_identity()
    db = SessionLocal()

    try:
        # Verify conversation belongs to user
        conversation = (
            db.query(Conversation)
            .filter(Conversation.id == conversation_id, Conversation.user_id == user_id)
            .first()
        )

        if not conversation:
            return jsonify({"error": "Conversation not found"}), 404

        # Get messages
        messages = (
            db.query(Message)
            .filter(Message.conversation_id == conversation_id)
            .order_by(Message.created_at.asc())
            .all()
        )

        return jsonify(
            {
                "id": str(conversation.id),
                "title": conversation.title or f"Conversation {conversation.id}",
                "created_at": conversation.created_at.isoformat(),
                "updated_at": conversation.updated_at.isoformat(),
                "messages": [
                    {
                        "id": str(msg.id),
                        "role": msg.role,
                        "content": msg.content,
                        "created_at": msg.created_at.isoformat(),
                    }
                    for msg in messages
                ],
            }
        )

    except Exception as e:
        current_app.logger.error(f"Error getting conversation: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


def init_llm_routes(app):
    """Initialize LLM routes with the Flask app."""
    app.register_blueprint(llm_bp)

""
Message-related API endpoints.
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from uuid import UUID
from datetime import datetime
from ..models.message import Message, MessageStatus
from ..models.message_models import MessageEdit, MessageReaction, MessageMention
from ..extensions import db
from ..utils.decorators import validate_uuid, handle_errors

bp = Blueprint('messages', __name__, url_prefix='/api/messages')

@bp.route('/<message_id>', methods=['GET'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors

def get_message(message_id):
    """Get a specific message by ID."""
    current_user_id = UUID(get_jwt_identity())
    message = Message.query.get_or_404(message_id)
    
    # Check permissions
    if str(current_user_id) not in [str(message.sender_id), str(message.recipient_id)]:
        return jsonify({"error": "Not authorized to view this message"}), 403
    
    return jsonify(message.to_dict())

@bp.route('/<message_id>/edit', methods=['PUT'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors

def edit_message(message_id):
    """Edit a message."""
    current_user_id = UUID(get_jwt_identity())
    data = request.get_json()
    
    if not data or 'content' not in data:
        return jsonify({"error": "Missing content"}), 400
    
    message = Message.query.get_or_404(message_id)
    
    # Check permissions - only sender can edit
    if str(message.sender_id) != str(current_user_id):
        return jsonify({"error": "Not authorized to edit this message"}), 403
    
    # Prevent editing after a certain time (e.g., 15 minutes)
    if (datetime.utcnow() - message.created_at).total_seconds() > 900:  # 15 minutes
        return jsonify({"error": "Message can only be edited within 15 minutes"}), 400
    
    # Update message
    message.edit(
        new_content=data['content'],
        edited_by=current_user_id,
        reason=data.get('reason')
    )
    
    db.session.commit()
    return jsonify(message.to_dict())

@bp.route('/<message_id>', methods=['DELETE'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors

def delete_message(message_id):
    """Delete a message."""
    current_user_id = UUID(get_jwt_identity())
    message = Message.query.get_or_404(message_id)
    
    # Check permissions - only sender can delete
    if str(message.sender_id) != str(current_user_id):
        return jsonify({"error": "Not authorized to delete this message"}), 403
    
    message.delete_message(deleted_by=current_user_id)
    db.session.commit()
    
    return jsonify({"status": "Message deleted"}), 200

@bp.route('/<message_id>/react', methods=['POST'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors

def react_to_message(message_id):
    """Add or update a reaction to a message."""
    current_user_id = UUID(get_jwt_identity())
    data = request.get_json()
    
    if not data or 'reaction' not in data:
        return jsonify({"error": "Missing reaction"}), 400
    
    message = Message.query.get_or_404(message_id)
    
    # Check if user is part of the conversation
    if str(current_user_id) not in [str(message.sender_id), str(message.recipient_id)]:
        return jsonify({"error": "Not authorized to react to this message"}), 403
    
    # Toggle reaction
    emoji = data['reaction']
    if message.reactions and emoji in message.reactions and str(current_user_id) in message.reactions[emoji]:
        message.remove_reaction(current_user_id, emoji)
    else:
        message.add_reaction(current_user_id, emoji)
    
    db.session.commit()
    return jsonify({"reactions": message.reactions or {}})

@bp.route('/<message_id>/mentions', methods=['GET'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors

def get_message_mentions(message_id):
    """Get all mentions in a message."""
    current_user_id = UUID(get_jwt_identity())
    message = Message.query.get_or_404(message_id)
    
    # Check permissions
    if str(current_user_id) not in [str(message.sender_id), str(message.recipient_id)]:
        return jsonify({"error": "Not authorized to view mentions"}), 403
    
    mentions = [m.to_dict() for m in message.message_mentions.all()]
    return jsonify({"mentions": mentions})

@bp.route('/<message_id>/edits', methods=['GET'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors

def get_message_edits(message_id):
    """Get edit history of a message."""
    current_user_id = UUID(get_jwt_identity())
    message = Message.query.get_or_404(message_id)
    
    # Check permissions
    if str(current_user_id) not in [str(message.sender_id), str(message.recipient_id)]:
        return jsonify({"error": "Not authorized to view edit history"}), 403
    
    edits = [e.to_dict() for e in message.edits.order_by(MessageEdit.edited_at.desc()).all()]
    return jsonify({"edits": edits})

@bp.route('/search', methods=['GET'])
@jwt_required()
@handle_errors

def search_messages():
    """Search messages in conversations."""
    current_user_id = UUID(get_jwt_identity())
    query = request.args.get('q')
    conversation_id = request.args.get('conversation_id')
    
    if not query:
        return jsonify({"error": "Search query is required"}), 400
    
    # Build base query
    q = Message.query.filter(
        (Message.sender_id == current_user_id) | (Message.recipient_id == current_user_id),
        Message.deleted == False,
        Message.content.ilike(f'%{query}%')
    )
    
    # Filter by conversation if specified
    if conversation_id:
        q = q.filter(Message.conversation_id == conversation_id)
    
    # Order by most recent first
    messages = q.order_by(Message.created_at.desc()).limit(50).all()
    
    return jsonify({
        "results": [msg.to_dict() for msg in messages],
        "query": query,
        "count": len(messages)
    })

"""
Message-related API endpoints.
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models.user import User
from ..models.conversation import Conversation, ConversationMember
from ..models.message_models import MessageMention, MentionType
from ..services.notification_service import NotificationService
from ..extensions import db
import re
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
    """
    Edit a message with version history and permission checks.
    
    Request body should include:
    - content: New message content (required)
    - reason: Optional reason for the edit
    - force: Set to true to bypass cooldown (admin only)
    """
    current_user_id = UUID(get_jwt_identity())
    data = request.get_json() or {}
    
    # Validate request
    if 'content' not in data:
        return jsonify({"error": "Missing content"}), 400
    
    # Get message and check permissions
    message = Message.query.get_or_404(message_id)
    current_user = User.query.get(current_user_id)
    
    # Check edit permissions
    if not message.can_edit(current_user_id, is_admin=getattr(current_user, 'is_admin', False)):
        return jsonify({"error": "Not authorized to edit this message"}), 403
    
    # For non-admins, check edit cooldown unless force is true
    if not getattr(current_user, 'is_admin', False) and not data.get('force'):
        edit_cooldown = 900  # 15 minutes in seconds
        time_since_creation = (datetime.utcnow() - message.created_at).total_seconds()
        
        if time_since_creation > edit_cooldown and message.edit_count > 0:
            return jsonify({
                "error": "Message can only be edited within 15 minutes of creation",
                "code": "edit_cooldown"
            }), 400
    
    try:
        # Update message with edit history
        edit = message.edit(
            new_content=data['content'],
            edited_by=current_user_id,
            reason=data.get('reason')
        )
        
        # Handle mentions
        if 'content' in data:
            # Delete existing mentions
            MessageMention.query.filter_by(message_id=message_id).delete()
            # Create new mentions
            create_mentions(message_id, data['content'], current_user_id)
        
        if not edit:
            return jsonify({"error": "Failed to update message"}), 400
        
        db.session.commit()
        
        # Notify participants of the edit
        notification_service = NotificationService()
        notification_service.notify_message_edited(
            message_id=message.id,
            conversation_id=message.conversation_id,
            editor_id=current_user_id,
            previous_content=edit.previous_content
        )
        
        return jsonify({
            "message": "Message updated successfully",
            "data": message.to_dict(include_edit_history=True)
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error editing message: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to update message"}), 500

@bp.route('/<message_id>', methods=['DELETE'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors
def delete_message(message_id):
    """
    Delete a message (soft delete by default).
    
    Query parameters:
    - hard: Set to true to permanently delete (admin only)
    - reason: Optional reason for deletion
    """
    current_user_id = UUID(get_jwt_identity())
    message = Message.query.get_or_404(message_id)
    
    # Check if already deleted
    if message.is_deleted:
        return jsonify({"message": "Message already deleted"}), 200
    
    # Check permissions
    current_user = User.query.get(current_user_id)
    is_admin = getattr(current_user, 'is_admin', False)
    
    if not message.can_delete(current_user_id, is_admin=is_admin):
        return jsonify({"error": "Not authorized to delete this message"}), 403
    
    # Get deletion parameters
    hard_delete = request.args.get('hard', '').lower() == 'true'
    reason = request.args.get('reason')
    
    try:
        # Delete the message
        success = message.delete_message(
            deleted_by=current_user_id,
            reason=reason,
            hard_delete=hard_delete and is_admin  # Only allow hard delete for admins
        )
        
        if not success:
            return jsonify({"error": "Failed to delete message"}), 400
        
        if hard_delete and is_admin:
            db.session.commit()
            return jsonify({"message": "Message permanently deleted"}), 200
        
        # For soft deletes, notify participants
        notification_service = NotificationService()
        notification_service.notify_message_deleted(
            message_id=message.id,
            conversation_id=message.conversation_id,
            deleted_by=current_user_id,
            reason=reason
        )
        
        db.session.commit()
        return jsonify({
            "message": "Message deleted",
            "data": message.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting message: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to delete message"}), 500

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

def extract_mentions(text):
    """Extract @mentions from message text."""
    return [{'username': m[1:]} for m in re.findall(r'@(\w+)', text)]

def create_mentions(message_id, text, mentioner_id):
    """Create mention records for a message."""
    mentions = []
    for mention in extract_mentions(text):
        user = User.query.filter_by(username=mention['username']).first()
        if user:
            mention = MessageMention(
                message_id=message_id,
                mentioned_id=user.id,
                mentioner_id=mentioner_id,
                mention_type=MentionType.USER
            )
            db.session.add(mention)
            mentions.append(mention)
    return mentions

@bp.route('/<conversation_id>/mentions/suggest', methods=['GET'])
@jwt_required()
@validate_uuid('conversation_id')
@handle_errors
def get_mention_suggestions(conversation_id):
    """Get user suggestions for @mentions in a conversation."""
    current_user_id = UUID(get_jwt_identity())
    query = request.args.get('q', '').lower()
    
    # Get conversation members
    members = ConversationMember.query.filter_by(
        conversation_id=conversation_id
    ).join(User).filter(
        User.username.ilike(f'%{query}%'),
        User.id != current_user_id  # Don't suggest the current user
    ).limit(10).all()
    
    return jsonify([{
        'id': str(member.user.id),
        'username': member.user.username,
        'avatar': member.user.avatar_url or ''
    } for member in members])

@bp.route('/<message_id>/edits', methods=['GET'])
@jwt_required()
@validate_uuid('message_id')
@handle_errors
def get_message_edits(message_id):
    """
    Get edit history for a message with pagination and filtering.
    
    Query parameters:
    - limit: Number of edits to return (default: 10, max: 50)
    - offset: Number of edits to skip (default: 0)
    - sort: Sort order ('asc' or 'desc', default: 'desc')
    """
    current_user_id = UUID(get_jwt_identity())
    message = Message.query.get_or_404(message_id)
    
    # Check permissions - only participants can view edit history
    conversation = Conversation.query.get(message.conversation_id)
    is_participant = ConversationMember.query.filter_by(
        conversation_id=message.conversation_id,
        user_id=current_user_id
    ).first() is not None
    
    if not is_participant:
        return jsonify({"error": "Not authorized to view edit history"}), 403
    
    # Get pagination parameters
    try:
        limit = min(int(request.args.get('limit', 10)), 50)  # Max 50 per page
        offset = max(int(request.args.get('offset', 0)), 0)
        sort_order = request.args.get('sort', 'desc').lower()
        
        if sort_order not in ('asc', 'desc'):
            sort_order = 'desc'
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid pagination parameters"}), 400
    
    # Get and return paginated edit history
    query = message.edit_history
    if sort_order == 'desc':
        query = query.order_by(MessageEdit.edited_at.desc())
    else:
        query = query.order_by(MessageEdit.edited_at.asc())
    
    total_edits = query.count()
    edits = query.offset(offset).limit(limit).all()
    
    return jsonify({
        "edits": [edit.to_dict() for edit in edits],
        "pagination": {
            "total": total_edits,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(edits)) < total_edits
        }
    })

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
        Message.is_deleted == False,
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

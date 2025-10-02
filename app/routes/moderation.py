from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from datetime import datetime, timedelta
from sqlalchemy import or_
from app import db
from app.models.forum import (
    User, Post, Comment, Report, AuditLog, Role, UserSession,
    ContentViolation, UserWarning, UserSuspension, UserBan
)
from app.models.auth import Permission
from app.services.moderation_service import ModerationService
from app.core.decorators import permission_required

bp = Blueprint('moderation', __name__, url_prefix='/api/moderation')

def get_current_user():
    """Get the current user from JWT token"""
    user_id = get_jwt_identity()
    return User.query.get(user_id)

# Report endpoints
@bp.route('/reports', methods=['POST'])
@jwt_required()
def create_report():
    """Create a new report"""
    current_user = get_current_user()
    data = request.get_json()
    
    required_fields = ['report_type', 'reason', 'target_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if target exists
    if data['report_type'] == 'post':
        target = Post.query.get(data['target_id'])
    elif data['report_type'] == 'comment':
        target = Comment.query.get(data['target_id'])
    elif data['report_type'] == 'user':
        target = User.query.get(data['target_id'])
    else:
        return jsonify({'error': 'Invalid report type'}), 400
    
    if not target:
        return jsonify({'error': 'Target not found'}), 404
    
    # Create report
    report = Report(
        reporter_id=current_user.id,
        reported_user_id=target.user_id if hasattr(target, 'user_id') else target.id,
        report_type=data['report_type'],
        target_id=data['target_id'],
        reason=data['reason'],
        details=data.get('details'),
        status='pending'
    )
    
    db.session.add(report)
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='report_created',
        details={
            'report_id': report.id,
            'report_type': report.report_type,
            'target_id': report.target_id,
            'reason': report.reason
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    # TODO: Notify moderators
    
    return jsonify({
        'id': report.id,
        'status': report.status,
        'created_at': report.created_at.isoformat()
    }), 201

@bp.route('/reports', methods=['GET'])
@jwt_required()
@permission_required(Permission.VIEW_MODERATION_QUEUE)
def get_reports():
    """Get all reports (for moderators)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status', 'pending')
    
    query = Report.query
    
    if status:
        query = query.filter(Report.status == status)
    
    pagination = query.order_by(Report.created_at.desc())\
                     .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'reports': [{
            'id': report.id,
            'report_type': report.report_type,
            'reason': report.reason,
            'status': report.status,
            'created_at': report.created_at.isoformat(),
            'reporter': report.reporter.username,
            'reported_user': report.reported_user.username if report.reported_user else None
        } for report in pagination.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    })

# Moderation actions
@bp.route('/warn/<int:user_id>', methods=['POST'])
@jwt_required()
@permission_required(Permission.MODERATE_USERS)
def warn_user(user_id):
    """Warn a user for violating rules"""
    current_user = get_current_user()
    data = request.get_json()
    
    user = User.query.get_or_404(user_id)
    
    # Create warning
    warning = UserWarning(
        user_id=user.id,
        issued_by=current_user.id,
        reason=data.get('reason', 'No reason provided'),
        violation_type=data.get('violation_type', 'other'),
        content_id=data.get('content_id'),
        content_type=data.get('content_type')
    )
    
    db.session.add(warning)
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='user_warned',
        details={
            'user_id': user.id,
            'warning_id': warning.id,
            'reason': warning.reason
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    # TODO: Notify user
    
    return jsonify({
        'id': warning.id,
        'user_id': user.id,
        'reason': warning.reason,
        'created_at': warning.created_at.isoformat()
    }), 201

@bp.route('/suspend/<int:user_id>', methods=['POST'])
@jwt_required()
@permission_required(Permission.MODERATE_USERS)
def suspend_user(user_id):
    """Suspend a user's account"""
    current_user = get_current_user()
    data = request.get_json()
    
    user = User.query.get_or_404(user_id)
    
    # Calculate suspension duration
    previous_suspensions = UserSuspension.query.filter_by(user_id=user.id).count()
    days = 1  # Default
    
    if previous_suspensions == 0:
        days = 1
    elif previous_suspensions == 1:
        days = 7
    elif previous_suspensions >= 2:
        days = 30
    
    expires_at = datetime.utcnow() + timedelta(days=days)
    
    # Create suspension
    suspension = UserSuspension(
        user_id=user.id,
        issued_by=current_user.id,
        reason=data.get('reason', 'No reason provided'),
        expires_at=expires_at,
        violation_ids=data.get('violation_ids', [])
    )
    
    # Invalidate user's active sessions
    UserSession.query.filter_by(user_id=user.id, is_active=True).update({
        'is_active': False,
        'expires_at': datetime.utcnow()
    })
    
    db.session.add(suspension)
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='user_suspended',
        details={
            'user_id': user.id,
            'suspension_id': suspension.id,
            'reason': suspension.reason,
            'expires_at': suspension.expires_at.isoformat()
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    # TODO: Notify user
    
    return jsonify({
        'id': suspension.id,
        'user_id': user.id,
        'reason': suspension.reason,
        'expires_at': suspension.expires_at.isoformat(),
        'days': days
    }), 201

@bp.route('/ban/<int:user_id>', methods=['POST'])
@jwt_required()
@permission_required(Permission.MODERATE_USERS)
def ban_user(user_id):
    """Ban a user's account"""
    current_user = get_current_user()
    data = request.get_json()
    
    user = User.query.get_or_404(user_id)
    
    # Check if user is already banned
    existing_ban = UserBan.query.filter_by(user_id=user.id, is_active=True).first()
    if existing_ban:
        return jsonify({'error': 'User is already banned'}), 400
    
    # Count previous bans
    previous_bans = UserBan.query.filter_by(user_id=user.id).count()
    
    # Create ban
    ban = UserBan(
        user_id=user.id,
        issued_by=current_user.id,
        reason=data.get('reason', 'No reason provided'),
        is_permanent=data.get('permanent', True),
        expires_at=None if data.get('permanent') else 
               (datetime.utcnow() + timedelta(days=365)),  # 1 year temporary ban
        violation_ids=data.get('violation_ids', []),
        previous_bans=previous_bans
    )
    
    # Invalidate user's active sessions
    UserSession.query.filter_by(user_id=user.id, is_active=True).update({
        'is_active': False,
        'expires_at': datetime.utcnow()
    })
    
    # Deactivate user account
    user.is_active = False
    
    db.session.add(ban)
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='user_banned',
        details={
            'user_id': user.id,
            'ban_id': ban.id,
            'reason': ban.reason,
            'is_permanent': ban.is_permanent,
            'expires_at': ban.expires_at.isoformat() if ban.expires_at else None
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    # TODO: Notify user
    
    return jsonify({
        'id': ban.id,
        'user_id': user.id,
        'reason': ban.reason,
        'is_permanent': ban.is_permanent,
        'expires_at': ban.expires_at.isoformat() if ban.expires_at else None
    }), 201

# Content moderation
@bp.route('/content/<content_type>/<int:content_id>/remove', methods=['POST'])
@jwt_required()
@permission_required(Permission.MODERATE_POSTS | Permission.MODERATE_COMMENTS)
def remove_content(content_type, content_id):
    """Remove a post or comment"""
    if content_type not in ['post', 'comment']:
        return jsonify({'error': 'Invalid content type'}), 400
    
    current_user = get_current_user()
    data = request.get_json()
    
    # Get the content
    if content_type == 'post':
        content = Post.query.get_or_404(content_id)
    else:
        content = Comment.query.get_or_404(content_id)
    
    # Mark as removed
    content.is_removed = True
    content.removed_by = current_user.id
    content.removed_at = datetime.utcnow()
    content.removal_reason = data.get('reason', 'No reason provided')
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action=f'{content_type}_removed',
        details={
            'content_id': content.id,
            'content_type': content_type,
            'author_id': content.user_id,
            'reason': content.removal_reason
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    return jsonify({
        'id': content.id,
        'status': 'removed',
        'removed_at': content.removed_at.isoformat(),
        'removed_by': current_user.username,
        'reason': content.removal_reason
    })

# Audit logs
@bp.route('/audit-logs', methods=['GET'])
@jwt_required()
@permission_required(Permission.VIEW_AUDIT_LOGS)
def get_audit_logs():
    """Get audit logs (for admins)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    
    query = AuditLog.query
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    pagination = query.order_by(AuditLog.created_at.desc())\
                     .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'logs': [{
            'id': log.id,
            'action': log.action,
            'user_id': log.user_id,
            'user': log.user.username if log.user else None,
            'details': log.details,
            'ip_address': log.ip_address,
            'created_at': log.created_at.isoformat()
        } for log in pagination.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    })

# User management
@bp.route('/users/<int:user_id>/roles', methods=['GET'])
@jwt_required()
@permission_required(Permission.MANAGE_ROLES)
def get_user_roles(user_id):
    """Get a user's roles"""
    user = User.query.get_or_404(user_id)
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'roles': [{
            'id': role.id,
            'name': role.name,
            'description': role.description
        } for role in user.roles]
    })

@bp.route('/users/<int:user_id>/roles', methods=['POST'])
@jwt_required()
@permission_required(Permission.MANAGE_ROLES)
def update_user_roles(user_id):
    """Update a user's roles"""
    current_user = get_current_user()
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if 'role_ids' not in data:
        return jsonify({'error': 'Missing role_ids'}), 400
    
    # Get the roles
    roles = Role.query.filter(Role.id.in_(data['role_ids'])).all()
    
    # Update user's roles
    user.roles = roles
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='user_roles_updated',
        details={
            'user_id': user.id,
            'roles': [role.name for role in roles]
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    return jsonify({
        'user_id': user.id,
        'roles': [{
            'id': role.id,
            'name': role.name
        } for role in user.roles]
    })

# Role management
@bp.route('/roles', methods=['GET'])
@jwt_required()
@permission_required(Permission.MANAGE_ROLES)
def get_roles():
    """Get all roles"""
    roles = Role.query.all()
    
    return jsonify([{
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'is_default': role.is_default,
        'permissions': role.permissions,
        'user_count': len(role.users)
    } for role in roles])

@bp.route('/roles', methods=['POST'])
@jwt_required()
@permission_required(Permission.MANAGE_ROLES)
def create_role():
    """Create a new role"""
    current_user = get_current_user()
    data = request.get_json()
    
    required_fields = ['name', 'permissions']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if role with this name already exists
    if Role.query.filter_by(name=data['name']).first():
        return jsonify({'error': 'Role with this name already exists'}), 400
    
    # Create role
    role = Role(
        name=data['name'],
        description=data.get('description', ''),
        permissions=data['permissions'],
        is_default=data.get('is_default', False)
    )
    
    db.session.add(role)
    
    # Log the action
    audit_log = AuditLog(
        user_id=current_user.id,
        action='role_created',
        details={
            'role_id': role.id,
            'role_name': role.name,
            'permissions': role.permissions
        },
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(audit_log)
    
    db.session.commit()
    
    return jsonify({
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'permissions': role.permissions,
        'is_default': role.is_default
    }), 201

# User status
@bp.route('/users/<int:user_id>/status', methods=['GET'])
@jwt_required()
def get_user_status(user_id):
    """Get a user's moderation status"""
    user = User.query.get_or_404(user_id)
    
    # Get active warnings
    warnings = UserWarning.query.filter_by(user_id=user.id, is_active=True).all()
    
    # Get active suspension
    suspension = UserSuspension.query.filter_by(user_id=user.id, is_active=True).first()
    
    # Check if banned
    ban = UserBan.query.filter_by(user_id=user.id, is_active=True).first()
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'is_active': user.is_active,
        'warnings': [{
            'id': w.id,
            'reason': w.reason,
            'violation_type': w.violation_type,
            'created_at': w.created_at.isoformat(),
            'expires_at': w.expires_at.isoformat() if w.expires_at else None,
            'is_active': w.is_active
        } for w in warnings],
        'suspension': {
            'id': suspension.id,
            'reason': suspension.reason,
            'expires_at': suspension.expires_at.isoformat() if suspension else None,
            'is_active': suspension.is_active if suspension else False
        } if suspension else None,
        'ban': {
            'id': ban.id,
            'reason': ban.reason,
            'is_permanent': ban.is_permanent,
            'expires_at': ban.expires_at.isoformat() if ban and ban.expires_at else None,
            'is_active': ban.is_active if ban else False
        } if ban else None
    })

"""
Decorators for permission and role-based access control
"""
from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from app.models.auth import Permission
from app.models.forum import User

def permission_required(permission):
    """
    Decorator to check if the current user has the required permission
    
    Usage:
        @bp.route('/protected')
        @jwt_required()
        @permission_required(Permission.MODERATE_POSTS)
        def protected_route():
            return jsonify({"message": "You have permission!"})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or not user.can(permission):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_permission': str(permission)
                }), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """
    Decorator to check if the current user is an admin
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_admin:
            return jsonify({
                'error': 'Admin access required'
            }), 403
            
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    """
    Decorator to check if the current user is a moderator or admin
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not (user.is_moderator or user.is_admin):
            return jsonify({
                'error': 'Moderator access required'
            }), 403
            
        return f(*args, **kwargs)
    return decorated_function

def track_activity(action_name):
    """
    Decorator to track user activity in the audit log
    
    Usage:
        @bp.route('/do-something')
        @jwt_required()
        @track_activity('did_something')
        def do_something():
            return jsonify({"message": "Action performed"})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.models.forum import AuditLog
            from flask import request
            
            # Get user ID from JWT if available
            user_id = None
            try:
                verify_jwt_in_request(optional=True)
                user_id = get_jwt_identity()
            except:
                pass
            
            # Get additional context from the request
            details = {
                'method': request.method,
                'endpoint': request.endpoint,
                'args': dict(request.args),
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string
            }
            
            # Add any additional context from the function
            if hasattr(f, '_activity_context'):
                details.update(f._activity_context)
            
            # Log the action
            if user_id:
                audit_log = AuditLog(
                    user_id=user_id,
                    action=action_name,
                    details=details,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                from app import db
                db.session.add(audit_log)
                db.session.commit()
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def rate_limit(requests=100, window=60, by="ip"):
    """
    Decorator to implement rate limiting
    
    Args:
        requests: Number of requests allowed per window
        window: Time window in seconds
        by: What to rate limit by ('ip' or 'user')
    """
    from functools import lru_cache
    from time import time
    from flask import request, jsonify
    
    # In-memory rate limit storage (for development)
    # In production, use Redis or similar
    rate_limits = {}
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get the key to use for rate limiting
            if by == "user":
                try:
                    verify_jwt_in_request()
                    key = f"user:{get_jwt_identity()}"
                except:
                    # Fall back to IP if not authenticated
                    key = f"ip:{request.remote_addr}"
            else:
                key = f"ip:{request.remote_addr}"
            
            # Get current timestamp
            now = time()
            
            # Initialize rate limit for this key if it doesn't exist
            if key not in rate_limits:
                rate_limits[key] = {
                    'count': 0,
                    'start_time': now,
                    'reset_time': now + window
                }
            
            # Reset the counter if the window has passed
            if now > rate_limits[key]['reset_time']:
                rate_limits[key] = {
                    'count': 0,
                    'start_time': now,
                    'reset_time': now + window
                }
            
            # Increment the counter
            rate_limits[key]['count'] += 1
            
            # Check if rate limit exceeded
            if rate_limits[key]['count'] > requests:
                return jsonify({
                    'error': 'Too many requests',
                    'retry_after': int(rate_limits[key]['reset_time'] - now)
                }), 429
            
            # Add rate limit headers to the response
            response = f(*args, **kwargs)
            response.headers['X-RateLimit-Limit'] = str(requests)
            response.headers['X-RateLimit-Remaining'] = str(requests - rate_limits[key]['count'])
            response.headers['X-RateLimit-Reset'] = str(int(rate_limits[key]['reset_time']))
            
            return response
        
        return decorated_function
    return decorator

"""
Password recovery routes.
"""
from flask import Blueprint, request, jsonify, render_template, url_for, redirect, flash
from flask_login import current_user
from werkzeug.security import check_password_hash

from ..extensions import db, limiter
from ..models import User
from ..security.password_recovery import password_recovery_manager
from ..utils.decorators import rate_limited

bp = Blueprint('password_recovery', __name__, url_prefix='/auth/password')

@bp.route('/forgot', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limiting to prevent abuse
def forgot_password():
    """Handle password reset request."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'Email is required.'
                }), 400
            flash('Email is required.', 'error')
            return render_template('auth/forgot_password.html')
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        # Always return success to prevent email enumeration
        if user:
            password_recovery_manager.send_password_reset_email(user)
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'If an account with that email exists, we have sent a password reset link.'
            })
            
        flash('If an account with that email exists, we have sent a password reset link.', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')

@bp.route('/reset/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limiting to prevent abuse
def reset_password(token):
    """Handle password reset with token."""
    # Check if token is valid
    user = password_recovery_manager.validate_reset_token(token)
    
    if not user:
        if request.is_json:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired password reset link.'
            }), 400
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Validate passwords
        if not password or len(password) < 8:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'Password must be at least 8 characters long.'
                }), 400
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        if password != confirm_password:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'Passwords do not match.'
                }), 400
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        # Check if new password is different from current one
        if check_password_hash(user.password_hash, password):
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'New password must be different from the current one.'
                }), 400
            flash('New password must be different from the current one.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        # Reset password
        success, _ = password_recovery_manager.reset_password(token, password)
        
        if success:
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'Your password has been reset successfully.'
                })
            flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
            return redirect(url_for('auth.login'))
        else:
            if request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'An error occurred while resetting your password. Please try again.'
                }), 500
            flash('An error occurred while resetting your password. Please try again.', 'error')
    
    return render_template('auth/reset_password.html', token=token)

@bp.route('/change', methods=['POST'])
@login_required
def change_password():
    """Change password for authenticated users."""
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'JSON request required.'
        }), 400
    
    data = request.get_json()
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    
    # Validate input
    if not all([current_password, new_password]):
        return jsonify({
            'success': False,
            'message': 'Current password and new password are required.'
        }), 400
    
    # Verify current password
    if not current_user.check_password(current_password):
        return jsonify({
            'success': False,
            'message': 'Current password is incorrect.'
        }), 401
    
    # Check if new password is different from current one
    if current_user.check_password(new_password):
        return jsonify({
            'success': False,
            'message': 'New password must be different from the current one.'
        }), 400
    
    # Update password
    try:
        current_user.set_password(new_password)
        db.session.commit()
        
        # TODO: Send email notification about password change
        
        return jsonify({
            'success': True,
            'message': 'Your password has been changed successfully.'
        })
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error changing password: {e}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while changing your password.'
        }), 500

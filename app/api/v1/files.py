"""
File sharing API endpoints with encryption and access control.
"""
import os
import uuid
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, create_access_token,
    get_jwt, verify_jwt_in_request
)
from werkzeug.utils import secure_filename
from io import BytesIO

from app.models.file import File, FileAccess, FileShare
from app.services.file_service import FileService
from app.extensions import db
from app.utils.security import admin_required, rate_limit

bp = Blueprint('files', __name__, url_prefix='/api/v1/files')

# Initialize file service
file_service = FileService()

@bp.route('/upload', methods=['POST'])
@jwt_required()
@rate_limit(limit=10, period=60)  # 10 requests per minute
async def upload_file():
    """
    Upload a file with optional encryption and sharing settings.
    
    Request body (multipart/form-data):
    - file: The file to upload (required)
    - password: Optional password for encryption
    - expires_in: Expiration time in days (default: 7)
    - max_downloads: Maximum number of downloads (default: None, unlimited)
    - is_public: Whether the file is publicly accessible (default: False)
    """
    try:
        # Get current user ID
        user_id = get_jwt_identity()
        
        # Check if file is present in the request
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        # Get additional parameters
        password = request.form.get('password')
        expires_in = int(request.form.get('expires_in', 7))
        max_downloads = request.form.get('max_downloads')
        is_public = request.form.get('is_public', 'false').lower() == 'true'
        
        # Generate a unique file ID
        file_id = str(uuid.uuid4())
        original_filename = secure_filename(file.filename)
        
        # Read file data
        file_data = file.read()
        
        # Upload and encrypt the file
        upload_result = file_service.upload_file(
            file_data=file_data,
            filename=original_filename,
            password=password,
            expiration_days=expires_in
        )
        
        # Create file record in database
        new_file = File(
            id=file_id,
            user_id=user_id,
            original_filename=original_filename,
            stored_filename=upload_result['stored_filename'],
            file_size=len(file_data),
            mime_type=upload_result['mime_type'],
            is_encrypted=bool(password),
            is_public=is_public,
            expires_at=datetime.utcnow() + timedelta(days=expires_in) if expires_in else None,
            max_downloads=max_downloads
        )
        
        # Save encryption key if password was provided
        if password and 'key' in upload_result:
            # In a real app, you'd want to encrypt this key with the user's public key
            new_file.encryption_key = upload_result['key']
        
        db.session.add(new_file)
        db.session.commit()
        
        # Prepare response
        response = {
            "file_id": file_id,
            "filename": original_filename,
            "size": len(file_data),
            "mime_type": upload_result['mime_type'],
            "is_encrypted": bool(password),
            "expires_at": new_file.expires_at.isoformat() if new_file.expires_at else None,
            "download_url": f"/api/v1/files/download/{file_id}",
            "share_url": f"/api/v1/files/share/{file_id}" if not is_public else None
        }
        
        return jsonify(response), 201
        
    except Exception as e:
        current_app.logger.error(f"File upload failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to upload file"}), 500

@bp.route('/download/<file_id>', methods=['GET'])
@jwt_required(optional=True)
async def download_file(file_id):
    """
    Download a file by ID with access control.
    """
    try:
        # Get current user ID (None if not authenticated)
        current_user_id = get_jwt_identity()
        
        # Find the file
        file = File.query.get_or_404(file_id)
        
        # Check access
        if not file.is_public and current_user_id != file.user_id:
            # Check if user has been granted access
            access = FileAccess.query.filter_by(
                file_id=file_id,
                user_id=current_user_id
            ).first()
            
            if not access:
                return jsonify({"error": "Access denied"}), 403
        
        # Check if file has expired
        if file.expires_at and file.expires_at < datetime.utcnow():
            return jsonify({"error": "File has expired"}), 410
            
        # Check download limit
        if file.max_downloads is not None and file.download_count >= file.max_downloads:
            return jsonify({"error": "Download limit reached"}), 429
        
        # Get password if needed
        password = request.args.get('password')
        
        # Download and decrypt the file
        try:
            decrypted_data = file_service.download_file(
                file_id=file_id,
                password=password,
                key=file.encryption_key
            )
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        
        # Update download count
        file.download_count += 1
        file.last_downloaded_at = datetime.utcnow()
        db.session.commit()
        
        # Return the file
        return send_file(
            BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file.original_filename,
            mimetype=file.mime_type
        )
        
    except Exception as e:
        current_app.logger.error(f"File download failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to download file"}), 500

@bp.route('/share/<file_id>', methods=['POST'])
@jwt_required()
async def share_file(file_id):
    """
    Share a file with another user.
    
    Request body (JSON):
    - user_id: ID of the user to share with
    - can_edit: Whether the user can edit the file (default: False)
    - expires_at: When the share should expire (ISO format)
    """
    try:
        # Get current user ID
        current_user_id = get_jwt_identity()
        
        # Find the file
        file = File.query.get_or_404(file_id)
        
        # Check ownership
        if file.user_id != current_user_id:
            return jsonify({"error": "You don't have permission to share this file"}), 403
        
        # Parse request data
        data = request.get_json() or {}
        target_user_id = data.get('user_id')
        can_edit = data.get('can_edit', False)
        expires_at = data.get('expires_at')
        
        if not target_user_id:
            return jsonify({"error": "User ID is required"}), 400
            
        # Create share record
        share = FileShare(
            file_id=file_id,
            shared_by=current_user_id,
            shared_with=target_user_id,
            can_edit=can_edit,
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None
        )
        
        db.session.add(share)
        db.session.commit()
        
        return jsonify({
            "message": "File shared successfully",
            "share_id": share.id
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"File share failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to share file"}), 500

@bp.route('/list', methods=['GET'])
@jwt_required()
async def list_files():
    """
    List all files accessible by the current user.
    """
    try:
        user_id = get_jwt_identity()
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        # Query files
        query = File.query.filter(
            (File.user_id == user_id) | 
            (File.is_public == True) |
            (File.shares.any(FileShare.shared_with == user_id))
        )
        
        # Apply pagination
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        files = pagination.items
        
        # Prepare response
        result = {
            'items': [{
                'id': file.id,
                'filename': file.original_filename,
                'size': file.file_size,
                'mime_type': file.mime_type,
                'is_encrypted': file.is_encrypted,
                'created_at': file.created_at.isoformat(),
                'expires_at': file.expires_at.isoformat() if file.expires_at else None,
                'download_url': f"/api/v1/files/download/{file.id}"
            } for file in files],
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }
        
        return jsonify(result)
        
    except Exception as e:
        current_app.logger.error(f"Failed to list files: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve files"}), 500

@bp.route('/<file_id>', methods=['DELETE'])
@jwt_required()
async def delete_file(file_id):
    """
    Delete a file.
    """
    try:
        user_id = get_jwt_identity()
        
        # Find the file
        file = File.query.get_or_404(file_id)
        
        # Check ownership
        if file.user_id != user_id:
            return jsonify({"error": "You don't have permission to delete this file"}), 403
        
        # Delete the file from storage
        try:
            file_path = os.path.join(file_service.storage_path, file.stored_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            current_app.logger.error(f"Failed to delete file from storage: {str(e)}")
        
        # Delete database records
        db.session.delete(file)
        db.session.commit()
        
        return jsonify({"message": "File deleted successfully"})
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to delete file: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to delete file"}), 500

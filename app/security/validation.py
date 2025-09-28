""
Request validation and sanitization utilities.
"""
import re
import bleach
from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.security import safe_str_cmp
from typing import Dict, List, Any, Callable, Optional, Union

class InputValidationError(ValueError):
    """Custom exception for input validation errors."""
    def __init__(self, message: str, field: str = None, error_code: str = None):
        self.message = message
        self.field = field
        self.error_code = error_code or 'validation_error'
        super().__init__(message)

class Sanitizer:
    """Input sanitization utilities."""
    
    # Common patterns for validation
    EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    USERNAME_REGEX = r'^[a-zA-Z0-9_\-.]{3,30}$'
    PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'
    
    # Allowed HTML tags and attributes for rich content
    ALLOWED_TAGS = [
        'p', 'br', 'b', 'i', 'u', 'em', 'strong', 'a', 'ul', 'ol', 'li',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre'
    ]
    
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title', 'target', 'rel'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'code': ['class'],
        'pre': ['class']
    }
    
    @classmethod
    def sanitize_input(cls, data: Any, field_type: str = 'text') -> Any:
        """Sanitize input based on field type."""
        if data is None:
            return None
            
        if isinstance(data, str):
            data = data.strip()
            
            # Basic XSS protection
            data = bleach.clean(
                data,
                tags=cls.ALLOWED_TAGS,
                attributes=cls.ALLOWED_ATTRIBUTES,
                strip=True
            )
            
            # Type-specific sanitization
            if field_type == 'email':
                if not re.match(cls.EMAIL_REGEX, data):
                    raise InputValidationError("Invalid email format", "email")
                return data.lower()
                
            elif field_type == 'username':
                if not re.match(cls.USERNAME_REGEX, data):
                    raise InputValidationError(
                        "Username can only contain letters, numbers, underscores, hyphens, and periods",
                        "username"
                    )
                return data.lower()
                
            elif field_type == 'password':
                if not re.match(cls.PASSWORD_REGEX, data):
                    raise InputValidationError(
                        "Password must be at least 12 characters long and include uppercase, "
                        "lowercase, numbers, and special characters",
                        "password"
                    )
                return data
                
            elif field_type == 'integer':
                try:
                    return int(data)
                except (ValueError, TypeError):
                    raise InputValidationError("Must be a valid integer", field_type)
                    
            elif field_type == 'float':
                try:
                    return float(data)
                except (ValueError, TypeError):
                    raise InputValidationError("Must be a valid number", field_type)
                    
            elif field_type == 'boolean':
                if data.lower() in ('true', 'yes', '1', 't'):
                    return True
                elif data.lower() in ('false', 'no', '0', 'f'):
                    return False
                raise InputValidationError("Must be a boolean value", field_type)
                
        elif isinstance(data, (list, tuple)):
            return [cls.sanitize_input(item, field_type) for item in data]
            
        elif isinstance(data, dict):
            return {k: cls.sanitize_input(v, field_type) for k, v in data.items()}
            
        return data

    @classmethod
    def validate_json(cls, schema: Dict[str, Any]) -> Callable:
        ""
        Decorator to validate JSON request data against a schema.
        
        Example schema:
        {
            'username': {'type': 'username', 'required': True},
            'email': {'type': 'email', 'required': True},
            'age': {'type': 'integer', 'min': 18, 'max': 120, 'required': False}
        }
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                if not request.is_json:
                    return jsonify({
                        'error': 'Invalid content type',
                        'message': 'Content-Type must be application/json'
                    }), 415
                
                data = request.get_json()
                if data is None:
                    return jsonify({
                        'error': 'Invalid JSON',
                        'message': 'Request body must be valid JSON'
                    }), 400
                
                try:
                    # Validate required fields
                    for field, config in schema.items():
                        field_type = config.get('type', 'text')
                        required = config.get('required', False)
                        
                        if field not in data and required:
                            raise InputValidationError(
                                f"Missing required field: {field}",
                                field
                            )
                        
                        if field in data:
                            # Type validation
                            value = data[field]
                            
                            # Skip None values for non-required fields
                            if value is None and not required:
                                continue
                                
                            # Sanitize the input
                            sanitized_value = cls.sanitize_input(value, field_type)
                            
                            # Additional validation
                            if 'choices' in config and sanitized_value not in config['choices']:
                                raise InputValidationError(
                                    f"{field} must be one of: {', '.join(map(str, config['choices']))}",
                                    field
                                )
                                
                            if field_type == 'integer' or field_type == 'float':
                                if 'min' in config and sanitized_value < config['min']:
                                    raise InputValidationError(
                                        f"{field} must be at least {config['min']}",
                                        field
                                    )
                                if 'max' in config and sanitized_value > config['max']:
                                    raise InputValidationError(
                                        f"{field} must be at most {config['max']}",
                                        field
                                    )
                            
                            # Update with sanitized value
                            data[field] = sanitized_value
                    
                    # Add sanitized data to request object
                    request.sanitized_data = data
                    return f(*args, **kwargs)
                    
                except InputValidationError as e:
                    return jsonify({
                        'error': 'Validation failed',
                        'message': e.message,
                        'field': e.field,
                        'code': e.error_code
                    }), 400
                    
                except Exception as e:
                    current_app.logger.error(f"Validation error: {str(e)}", exc_info=True)
                    return jsonify({
                        'error': 'Server error',
                        'message': 'An error occurred while processing your request'
                    }), 500
            
            return wrapper
        return decorator

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize a filename to prevent directory traversal and other attacks."""
        if not filename:
            return ""
            
        # Remove any path information
        filename = os.path.basename(filename)
        
        # Replace or remove invalid characters
        filename = re.sub(r'[^\w\-_.]', '_', filename)
        
        # Limit length
        max_length = 255
        if len(filename) > max_length:
            name, ext = os.path.splitext(filename)
            name = name[:max_length - len(ext) - 1]
            filename = f"{name}{ext}"
            
        return filename

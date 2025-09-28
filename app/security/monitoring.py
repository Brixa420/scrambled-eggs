""
Security monitoring and logging utilities.
"""
import os
import json
import logging
import functools
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List, Tuple
from flask import request, g, current_app

class SecurityEvent:
    """Represents a security-related event."""
    
    def __init__(
        self,
        event_type: str,
        severity: str = 'info',
        message: str = '',
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_data: Optional[Dict[str, Any]] = None
    ):
        """Initialize a security event."""
        self.timestamp = datetime.utcnow()
        self.event_type = event_type
        self.severity = severity.lower()
        self.message = message
        self.details = details or {}
        self.user_id = user_id
        self.ip_address = ip_address or getattr(request, 'remote_addr', None)
        self.user_agent = user_agent or (request.user_agent.string if request.user_agent else None)
        self.request_data = request_data or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'severity': self.severity,
            'message': self.message,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'request': {
                'method': request.method,
                'path': request.path,
                'endpoint': request.endpoint,
                'args': dict(request.args),
                'data': self.request_data,
                'headers': dict(request.headers)
            } if request else {}
        }
    
    def log(self, logger: Optional[logging.Logger] = None):
        """Log the security event."""
        logger = logger or current_app.logger
        log_method = getattr(logger, self.severity, logger.info)
        log_method(json.dumps(self.to_dict(), default=str), extra={'security_event': True})


class SecurityMonitor:
    """Monitors and logs security events."""
    
    def __init__(self, app=None):
        self.app = app
        self.handlers = []
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the security monitor with the Flask app."""
        self.app = app
        
        # Configure logging
        self._configure_logging(app)
        
        # Register request hooks
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        
        # Register error handler
        @app.errorhandler(Exception)
        def handle_exception(e):
            self.log_exception(e)
            return e
    
    def _configure_logging(self, app):
        """Configure logging for security events."""
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(app.root_path, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Create a file handler for security logs
        security_log = os.path.join(log_dir, 'security.log')
        file_handler = logging.FileHandler(security_log)
        file_handler.setLevel(logging.INFO)
        
        # Create a formatter and set it for the handler
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Add the handler to the security logger
        security_logger = logging.getLogger('security')
        security_logger.addHandler(file_handler)
        security_logger.setLevel(logging.INFO)
        
        # Prevent the security logs from propagating to the root logger
        security_logger.propagate = False
    
    def _before_request(self):
        """Set up request context for security monitoring."""
        g.security_events = []
    
    def _after_request(self, response):
        """Process any security events after the request."""
        # Log any security events that occurred during the request
        for event in getattr(g, 'security_events', []):
            event.log()
        
        return response
    
    def log_event(
        self,
        event_type: str,
        message: str,
        severity: str = 'info',
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        request_data: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """Log a security event."""
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            details=details or {},
            user_id=user_id,
            request_data=request_data or {}
        )
        
        # Add to request context to be logged after the request completes
        if 'security_events' not in g:
            g.security_events = []
        g.security_events.append(event)
        
        # Call any registered handlers
        for handler in self.handlers:
            try:
                handler(event)
            except Exception as e:
                current_app.logger.error(f"Error in security event handler: {e}", exc_info=True)
        
        return event
    
    def log_auth_attempt(
        self,
        success: bool,
        username: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """Log an authentication attempt."""
        event_type = 'auth_success' if success else 'auth_failure'
        message = f"{'Successful' if success else 'Failed'} login attempt for user: {username}"
        
        if details is None:
            details = {}
        
        details.update({
            'username': username,
            'user_id': user_id,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string if request.user_agent else None
        })
        
        return self.log_event(
            event_type=event_type,
            message=message,
            severity='warning' if not success else 'info',
            details=details,
            user_id=user_id
        )
    
    def log_security_alert(
        self,
        alert_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None
    ) -> SecurityEvent:
        """Log a security alert."""
        return self.log_event(
            event_type=f'security_alert_{alert_type}',
            message=message,
            severity='warning',
            details=details or {},
            user_id=user_id
        )
    
    def log_exception(
        self,
        exception: Exception,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None
    ) -> SecurityEvent:
        """Log an exception as a security event."""
        if details is None:
            details = {}
        
        details.update({
            'exception_type': exception.__class__.__name__,
            'exception_message': str(exception),
            'traceback': self._get_traceback(exception)
        })
        
        return self.log_event(
            event_type='exception',
            message=message or f"Unhandled exception: {str(exception)}",
            severity='error',
            details=details,
            user_id=user_id
        )
    
    def _get_traceback(self, exception: Exception) -> str:
        """Get the traceback for an exception as a string."""
        import traceback
        return '\n'.join(traceback.format_exception(
            type(exception), exception, exception.__traceback__
        ))
    
    def add_handler(self, handler: Callable[[SecurityEvent], None]):
        """Add a handler for security events."""
        self.handlers.append(handler)
    
    def remove_handler(self, handler: Callable[[SecurityEvent], None]):
        """Remove a handler for security events."""
        if handler in self.handlers:
            self.handlers.remove(handler)


def monitor_security_events(f):
    """Decorator to monitor and log security events for a route."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Log the start of the request
        monitor = current_app.extensions.get('security_monitor')
        if monitor:
            monitor.log_event(
                event_type='request_start',
                message=f"Request started: {request.method} {request.path}",
                severity='debug',
                details={
                    'method': request.method,
                    'path': request.path,
                    'endpoint': request.endpoint,
                    'args': dict(request.args),
                    'headers': dict(request.headers)
                }
            )
        
        try:
            # Execute the route handler
            response = f(*args, **kwargs)
            
            # Log successful completion
            if monitor:
                monitor.log_event(
                    event_type='request_complete',
                    message=f"Request completed: {request.method} {request.path}",
                    severity='debug',
                    details={
                        'status_code': response.status_code,
                        'content_type': response.content_type
                    }
                )
            
            return response
            
        except Exception as e:
            # Log the exception
            if monitor:
                monitor.log_exception(
                    exception=e,
                    message=f"Error in {request.endpoint}: {str(e)}",
                    details={
                        'method': request.method,
                        'path': request.path,
                        'endpoint': request.endpoint,
                        'args': dict(request.args),
                        'headers': dict(request.headers)
                    }
                )
            
            # Re-raise the exception to be handled by Flask
            raise
    
    return decorated_function

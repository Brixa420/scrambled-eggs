"""Security middleware for the application."""

import re
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from flask import Response, current_app, g, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests
from werkzeug.wrappers import Response as WerkzeugResponse

from .config import get_config
from .utils import security_utils

# Initialize config
config = get_config()


class SecurityMiddleware:
    """Security middleware for the application."""

    def __init__(self, app=None):
        """Initialize the security middleware."""
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the security middleware with the Flask app."""
        # Register before_request and after_request handlers
        app.before_request(self._before_request)
        app.after_request(self._after_request)

        # Register error handlers
        app.register_error_handler(400, self._handle_bad_request)
        app.register_error_handler(403, self._handle_forbidden)
        app.register_error_handler(404, self._handle_not_found)
        app.register_error_handler(405, self._handle_method_not_allowed)
        app.register_error_handler(429, self._handle_too_many_requests)
        app.register_error_handler(500, self._handle_server_error)

        # Add security headers to all responses
        app.after_request(self._add_security_headers)

        # Add request validation
        app.before_request(self._validate_request)

    def _before_request(self) -> Optional[Response]:
        """Process the request before routing."""
        # Add start time to measure request duration
        g.start_time = datetime.utcnow()

        # Check for suspicious user agents
        if self._is_suspicious_user_agent():
            security_utils.log_security_event(
                "suspicious_user_agent",
                ip_address=request.remote_addr,
                details=f"Suspicious User-Agent: {request.user_agent.string}",
            )
            return (
                jsonify({"status": "error", "message": "Access denied", "code": "access_denied"}),
                403,
            )

        # Check for common attack patterns in URL and headers
        if self._detect_attack_patterns():
            security_utils.log_security_event(
                "potential_attack_detected",
                ip_address=request.remote_addr,
                details=f"Potential attack detected in request: {request.path}",
            )
            return (
                jsonify(
                    {"status": "error", "message": "Invalid request", "code": "invalid_request"}
                ),
                400,
            )

        return None

    def _after_request(self, response: WerkzeugResponse) -> WerkzeugResponse:
        """Process the response before sending it to the client."""
        # Calculate request duration
        duration = (datetime.utcnow() - g.get("start_time", datetime.utcnow())).total_seconds()

        # Add request ID if not present
        if not hasattr(g, "request_id"):
            g.request_id = security_utils.generate_secure_token(16)

        # Add security headers
        response = self._add_security_headers(response)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = g.request_id

        # Log the request
        self._log_request(response, duration)

        return response

    def _add_security_headers(self, response: WerkzeugResponse) -> WerkzeugResponse:
        """Add security headers to the response."""
        # Add security headers from config
        for header, value in config.SECURITY_HEADERS.items():
            if header not in response.headers:
                response.headers[header] = value

        # Remove server header
        if "Server" in response.headers:
            del response.headers["Server"]

        # Add HSTS preload directive in production
        if config.SESSION_COOKIE_SECURE and "Strict-Transport-Security" in response.headers:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response

    def _validate_request(self) -> Optional[Response]:
        """Validate the incoming request."""
        # Check content type for POST, PUT, PATCH requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("Content-Type", "")

            # For JSON APIs, require Content-Type: application/json
            if request.path.startswith("/api/") and "application/json" not in content_type:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Content-Type must be application/json",
                            "code": "invalid_content_type",
                        }
                    ),
                    400,
                )

            # Validate JSON for JSON requests
            if "application/json" in content_type and request.get_data():
                try:
                    request.get_json()
                except Exception as e:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "message": "Invalid JSON",
                                "code": "invalid_json",
                                "details": str(e),
                            }
                        ),
                        400,
                    )

        # Check for missing or malformed CSRF token for non-GET requests
        if config.WTF_CSRF_ENABLED and request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            if not self._validate_csrf_token():
                security_utils.log_security_event(
                    "csrf_validation_failed",
                    ip_address=request.remote_addr,
                    details=f"CSRF validation failed for {request.method} {request.path}",
                )
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "CSRF token missing or invalid",
                            "code": "invalid_csrf_token",
                        }
                    ),
                    403,
                )

        return None

    def _validate_csrf_token(self) -> bool:
        """Validate the CSRF token."""
        # Skip CSRF check for API endpoints with token auth
        if request.path.startswith("/api/") and "Authorization" in request.headers:
            return True

        # Get the token from the form or header
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")

        if not token:
            return False

        # In a real app, you would validate the token against the user's session
        # For this example, we'll just check if it's a valid token format
        return bool(re.match(r"^[a-zA-Z0-9_-]{32,}$", token))

    def _is_suspicious_user_agent(self) -> bool:
        """Check if the user agent is suspicious."""
        user_agent = request.user_agent.string.lower()

        # List of suspicious user agents or patterns
        suspicious_patterns = [
            "nmap",
            "nikto",
            "sqlmap",
            "w3af",
            "nessus",
            "metasploit",
            "burp",
            "dirbuster",
            "nikto",
            "acunetix",
            "paros",
            "skipfish",
            "wpscan",
            "sql injection",
            "xss",
            "lfi",
            "rfi",
            "exec",
            "eval",
            "union select",
            "--",
            ";--",
            "1=1",
            "1=0",
            " or ",
            " and ",
            "/*",
            "*/",
            "script>",
            "<script",
            "onerror=",
            "onload=",
            "onmouseover=",
            "javascript:",
            "vbscript:",
            "data:text/html",
            "base64",
        ]

        return any(pattern in user_agent for pattern in suspicious_patterns)

    def _detect_attack_patterns(self) -> bool:
        """Detect common attack patterns in the request."""
        # Check URL for SQL injection patterns
        sql_patterns = [
            r"(?:\b(?:select|union|insert|update|delete|drop|alter|create|truncate|exec|xp_|sp_|--|;|/\*|\*/)\b)",
            r"(?:\b(?:or\s+\d+=\d+|\d+=\d+\s+or\b|\b(?:and|or)\s+[\w\[\]]+\s*[=<>]+\s*[\w\[\]]+)",
            r"(?:\b(?:select|union).*?from|insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
        ]

        # Check for XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"on\w+\s*=",
            r"javascript:",
            r"vbscript:",
            r"expression\s*\(",
            r'<[^>]*(?:src|href)\s*=\s*[\'"](?:javascript:|data:)',
        ]

        # Check for path traversal
        path_traversal_patterns = [
            r"(?:\.\./|\.\\){2,}",
            r"(?:/|\\)\.\.(?:/|\\)",
            r"\b(?:etc|passwd|shadow|hosts|config|env|secret|key)\b",
        ]

        # Combine all patterns
        all_patterns = sql_patterns + xss_patterns + path_traversal_patterns

        # Check URL and query parameters
        url = request.url.lower()
        if any(re.search(pattern, url, re.IGNORECASE | re.DOTALL) for pattern in all_patterns):
            return True

        # Check form data
        if request.form:
            form_data = str(request.form).lower()
            if any(
                re.search(pattern, form_data, re.IGNORECASE | re.DOTALL) for pattern in all_patterns
            ):
                return True

        # Check JSON data
        if request.is_json:
            try:
                json_data = str(request.get_json()).lower()
                if any(
                    re.search(pattern, json_data, re.IGNORECASE | re.DOTALL)
                    for pattern in all_patterns
                ):
                    return True
            except:
                pass

        return False

    def _log_request(self, response: WerkzeugResponse, duration: float) -> None:
        """Log the request details."""
        if not hasattr(current_app, "logger"):
            return

        # Get user ID if authenticated
        user_id = None
        if hasattr(g, "user") and g.user:
            user_id = str(g.user.id)

        # Log the request
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "duration": f"{duration:.3f}s",
            "ip": request.remote_addr,
            "user_agent": request.user_agent.string,
            "user_id": user_id,
            "request_id": getattr(g, "request_id", None),
        }

        current_app.logger.info(f"REQUEST: {log_data}")

    # Error handlers
    def _handle_bad_request(self, error):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Bad request",
                    "code": "bad_request",
                    "details": str(error) if current_app.debug else None,
                }
            ),
            400,
        )

    def _handle_forbidden(self, error):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Forbidden",
                    "code": "forbidden",
                    "details": str(error) if current_app.debug else None,
                }
            ),
            403,
        )

    def _handle_not_found(self, error):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Not found",
                    "code": "not_found",
                    "details": str(error) if current_app.debug else None,
                }
            ),
            404,
        )

    def _handle_method_not_allowed(self, error):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Method not allowed",
                    "code": "method_not_allowed",
                    "details": str(error) if current_app.debug else None,
                }
            ),
            405,
        )

    def _handle_too_many_requests(self, error):
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Too many requests",
                    "code": "rate_limit_exceeded",
                    "details": str(error) if current_app.debug else None,
                }
            ),
            429,
        )

    def _handle_server_error(self, error):
        # Log the error
        current_app.logger.error(f"Server error: {error}", exc_info=True)

        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Internal server error",
                    "code": "internal_server_error",
                    "details": str(error) if current_app.debug else None,
                }
            ),
            500,
        )


# Create an instance for easy importing
security_middleware = SecurityMiddleware()

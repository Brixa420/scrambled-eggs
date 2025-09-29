"""
Error handlers for the application.
"""

from flask import jsonify
from werkzeug.exceptions import HTTPException


def init_error_handlers(app):
    """Initialize error handlers for the application."""

    @app.errorhandler(400)
    def bad_request_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "bad_request",
                    "message": "The request was invalid or cannot be served.",
                }
            ),
            400,
        )

    @app.errorhandler(401)
    def unauthorized_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "unauthorized",
                    "message": "Authentication is required to access this resource.",
                }
            ),
            401,
        )

    @app.errorhandler(403)
    def forbidden_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "forbidden",
                    "message": "You do not have permission to access this resource.",
                }
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "not_found",
                    "message": "The requested resource was not found.",
                }
            ),
            404,
        )

    @app.errorhandler(405)
    def method_not_allowed_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "method_not_allowed",
                    "message": "The method is not allowed for the requested URL.",
                }
            ),
            405,
        )

    @app.errorhandler(500)
    def internal_server_error(error):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "internal_server_error",
                    "message": "An internal server error occurred.",
                }
            ),
            500,
        )

    @app.errorhandler(Exception)
    def handle_exception(error):
        # Pass through HTTP errors
        if isinstance(error, HTTPException):
            return error

        # Log the error
        app.logger.error(f"Unhandled exception: {str(error)}", exc_info=True)

        # Return a 500 error for unhandled exceptions
        return (
            jsonify(
                {
                    "success": False,
                    "error": "internal_server_error",
                    "message": "An unexpected error occurred.",
                }
            ),
            500,
        )

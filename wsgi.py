"""
WSGI config for Scrambled Eggs application.

This module contains the WSGI application used by the application server.
"""
import os
from web_app import create_app

# Create the Flask application
app = create_app()

if __name__ == "__main__":
    # For local development
    app.run(host='0.0.0.0', port=5000, debug=True)

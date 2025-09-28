"""
Application routes.
"""
from flask import Blueprint

# Create main blueprint
main = Blueprint('main', __name__)

# Import routes after creating the blueprint to avoid circular imports
from . import chat, tor, analysis  # noqa

""
API Blueprint for the application.
"""
from flask import Blueprint
from . import analysis

# Create the main API blueprint
bp = Blueprint('api', __name__)

def init_app(app):
    """Initialize the API with the Flask app."""
    # Register blueprints
    bp.register_blueprint(analysis.bp)
    
    # Register the main API blueprint
    app.register_blueprint(bp, url_prefix='/api')
    
    return app

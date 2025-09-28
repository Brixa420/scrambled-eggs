import os
import sys
import logging
from datetime import timedelta
from flask import Flask, jsonify, render_template, redirect, url_for, session, request
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask extensions
socketio = SocketIO()
active_users = {}

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Generate secure secret key if not set
    secret_key = os.environ.get('FLASK_SECRET_KEY')
    if not secret_key:
        secret_key = os.urandom(24).hex()
        os.environ['FLASK_SECRET_KEY'] = secret_key
    
    # Configure the application
    app.config.update(
        # Security configurations
        SECRET_KEY=secret_key,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),  # Session expires after 1 hour
        
        # Security headers
        SECURITY_HEADERS={
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
        },
        
        # Application settings
        TEMPLATES_AUTO_RELOAD=True,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URI', 'sqlite:///app.db')
    )
    
    # Initialize extensions
    from app.extensions import db, login_manager
    
    # Initialize SQLAlchemy
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins=[])
    
    # Create database tables if they don't exist
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created/verified")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
    
    # Add routes
    @app.route('/')
    def index():
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return render_template('index.html', user_id=session.get('user_id'))
    
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'ok',
            'timestamp': '2025-09-27T21:32:00Z'  # Will be replaced with actual timestamp
        })
    
    # WebSocket handlers
    @socketio.on('connect')
    def handle_connect():
        if 'user_id' not in session:
            return False
        user_id = session['user_id']
        active_users[request.sid] = user_id
        emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    
    @socketio.on('disconnect')
    def handle_disconnect():
        if request.sid in active_users:
            user_id = active_users.pop(request.sid)
            emit('user_left', {'user_id': user_id}, broadcast=True)
    
    return app

def main():
    """Main entry point for the application."""
    logger.info("Starting Scrambled Eggs web interface...")
    
    try:
        port = int(os.environ.get('PORT', 5000))
        app = create_app()
        
        # Start the server with SocketIO
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=port, 
            debug=True, 
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
        
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()

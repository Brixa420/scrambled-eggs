import os
import sys
import logging
import click
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, redirect, url_for, session, request, current_app
from flask_socketio import SocketIO, emit
from flask_migrate import Migrate
from dotenv import load_dotenv
from app.extensions import db, login_manager, migrate
from app.models import User, Message, EncryptionKey
from app.services.email_service import email_service
from app.security.ai_crypto_orchestrator import AICryptoOrchestrator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask extensions and AI Crypto Orchestrator
socketio = SocketIO()
active_users = {}

# Initialize AI Crypto Orchestrator
crypto_orchestrator = None

def register_extensions(app):
    """Register Flask extensions with the application."""
    global crypto_orchestrator
    
    # Initialize database and migrations
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize SocketIO
    socketio.init_app(app, cors_allowed_origins=[])
    
    # Initialize login manager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    # Initialize AI Crypto Orchestrator
    config_path = os.path.join(app.instance_path, 'crypto_config.json')
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    crypto_orchestrator = AICryptoOrchestrator(config_path=config_path)
    
    # Start security monitoring in a separate thread
    def start_security_monitor():
        with app.app_context():
            app.logger.info("Starting AI Security Monitor...")
            crypto_orchestrator.monitor_security()
    
    monitor_thread = threading.Thread(
        target=start_security_monitor,
        daemon=True,
        name="SecurityMonitor"
    )
    monitor_thread.start()
    
    # Log current protocol
    if crypto_orchestrator.current_protocol:
        app.logger.info(
            f"Initialized with encryption protocol: "
            f"{crypto_orchestrator.current_protocol.name} "
            f"v{crypto_orchestrator.current_protocol.version}"
        )
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Default configuration
    app.config.update(
        # Security
        SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex()),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        
        # Database
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///app.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        
        # Application settings
        TEMPLATES_AUTO_RELOAD=True,
        UPLOAD_FOLDER='uploads',
        
        # Security headers
        SECURITY_HEADERS={
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
        },
        
        # AI Security Settings
        AI_SECURITY_CONFIG={
            'monitor_interval': 3600,  # Check security every hour
            'auto_update': True,       # Allow automatic protocol updates
            'min_key_size': 256,       # Minimum key size in bits
            'min_kdf_iterations': 100000,  # Minimum KDF iterations
            'security_log': 'security.log'  # Security log file
        }
    )
    
    # Override with any provided config
    if config:
        app.config.update(config)
    
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
    # Register extensions
    register_extensions(app)
    
    # Initialize database models
    from app.models import init_models
    init_models(app)
    
    # Register blueprints
    try:
        from app.routes import auth_routes, chat_routes, api_routes
        app.register_blueprint(auth_routes.bp, url_prefix='/auth')
        app.register_blueprint(chat_routes.bp, url_prefix='/chat')
        app.register_blueprint(api_routes.bp, url_prefix='/api')
        
        # Register security API routes
        @app.route('/api/security/status', methods=['GET'])
        def security_status():
            """Get current security status and protocol information"""
            if not crypto_orchestrator:
                return jsonify({'error': 'Security orchestrator not initialized'}), 500
                
            try:
                status = {
                    'status': 'operational',
                    'current_protocol': crypto_orchestrator.current_protocol.to_dict() if crypto_orchestrator.current_protocol else None,
                    'security_report': crypto_orchestrator.analyze_security(),
                    'available_protocols': [
                        proto.to_dict() for proto in crypto_orchestrator.protocols.values()
                    ] if hasattr(crypto_orchestrator, 'protocols') else []
                }
                return jsonify(status)
            except Exception as e:
                app.logger.error(f"Security status error: {str(e)}")
                return jsonify({'error': 'Could not retrieve security status'}), 500
        
        @app.route('/api/security/upgrade', methods=['POST'])
        def upgrade_security():
            """Manually trigger a security protocol upgrade"""
            if not crypto_orchestrator:
                return jsonify({'error': 'Security orchestrator not initialized'}), 500
                
            try:
                if not crypto_orchestrator.current_protocol:
                    return jsonify({'error': 'No active security protocol'}), 400
                    
                new_proto = crypto_orchestrator.evolve_protocol()
                if new_proto:
                    return jsonify({
                        'message': f'Upgraded to {new_proto.name} v{new_proto.version}',
                        'new_protocol': new_proto.to_dict()
                    })
                return jsonify({'message': 'No upgrade available'}), 200
                    
            except Exception as e:
                app.logger.error(f"Security upgrade error: {str(e)}")
                return jsonify({'error': 'Failed to upgrade security protocol'}), 500
                
    except ImportError as e:
        app.logger.warning(f"Failed to import some routes: {e}")
        # Register a simple route if auth routes fail to load
        @app.route('/')
        def index():
            return 'Scrambled Eggs API is running. Some routes may not be available.'
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register shell context
    register_shell_context(app)
    
    # Register commands
    register_commands(app)
    
    # Ensure the upload folder exists
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint for monitoring."""
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            return jsonify({
                'status': 'ok',
                'database': 'connected',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        except Exception as e:
            current_app.logger.error(f'Health check failed: {str(e)}', exc_info=True)
            return jsonify({
                'status': 'error',
                'database': 'disconnected',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 500
            
    @app.route('/')
    def index():
        """Main application route."""
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return render_template('index.html', user_id=session.get('user_id'))
    
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

def register_error_handlers(app):
    """Register error handlers for the application."""
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403


def register_shell_context(app):
    """Register shell context for Flask shell."""
    def shell_context():
        return {
            'db': db,
            'User': User,
            'Message': Message,
            'EncryptionKey': EncryptionKey
        }
    
    app.shell_context_processor(shell_context)


def register_commands(app):
    """Register Click commands."""
    @app.cli.command('init-db')
    def init_db():
        """Initialize the database."""
        db.create_all()
        print('Database initialized.')
    
    @app.cli.command('create-admin')
    @click.argument('username')
    @click.argument('email')
    @click.argument('password')
    def create_admin(username, email, password):
        """Create an admin user."""
        user = User(username=username, email=email, is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f'Admin user {username} created successfully.')




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
            debug=app.config.get('DEBUG', False), 
            use_reloader=app.config.get('USE_RELOADER', True),
            allow_unsafe_werkzeug=app.config.get('DEBUG', False)
        )
        
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()

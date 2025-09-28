""
Application factory for creating and configuring the Flask application.
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, current_app
from .extensions import db, login_manager, socketio, migrate, bootstrap, csrf, limiter, mail, assets
from .config import Config
from .models.user import User
from .routes import main as main_blueprint


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config_class)
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register shell context
    register_shell_context(app)
    
    # Register commands
    register_commands(app)
    
    # Configure logging
    configure_logging(app)
    
    # Register request handlers
    register_request_handlers(app)
    
    return app


def initialize_extensions(app):
    ""Initialize Flask extensions."""
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(
        app, 
        cors_allowed_origins=[],
        message_queue=app.config.get('REDIS_URL') or None,
        async_mode=app.config.get('SOCKETIO_ASYNC_MODE', 'eventlet')
    )
    migrate.init_app(app, db)
    bootstrap.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    assets.init_app(app)
    
    # Configure login manager
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


def register_blueprints(app):
    """Register Flask blueprints."""
    app.register_blueprint(main_blueprint)
    
    # Register API blueprints
    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')


def register_error_handlers(app):
    """Register error handlers."""
    
    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith('/api/'):
            return {'error': 'Not found'}, 404
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith('/api/'):
            return {'error': 'Forbidden'}, 403
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f'500 Error: {str(e)}')
        if request.path.startswith('/api/'):
            return {'error': 'Internal server error'}, 500
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith('/api/'):
            return {
                'error': 'ratelimit exceeded', 
                'message': str(e.description)
            }, 429
        return render_template('errors/429.html', error=e), 429


def register_shell_context(app):
    """Register shell context objects."""
    @app.shell_context_processor
    def make_shell_context():
        from .models.user import User
        from .models.message import Message
        from .models.room import Room
        
        return {
            'db': db,
            'User': User,
            'Message': Message,
            'Room': Room
        }


def register_commands(app):
    """Register Click commands."""
    import click
    from .models.user import User
    
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
        if User.query.filter_by(username=username).first():
            print(f'User {username} already exists.')
            return
            
        user = User(username=username, email=email, is_admin=True)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        print(f'Admin user {username} created.')


def configure_logging(app):
    ""Configure logging."""
    if not app.debug and not app.testing:
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.mkdir('logs')
            
        # File handler for errors
        file_handler = RotatingFileHandler(
            'logs/scrambled-eggs.log',
            maxBytes=10240,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Scrambled Eggs startup')


def register_request_handlers(app):
    ""Register request handlers."""
    @app.before_request
    def before_request():
        ""Execute before each request."""
        # Update last seen time for authenticated users
        if current_user.is_authenticated:
            current_user.last_seen = datetime.utcnow()
            db.session.commit()
    
    @app.after_request
    def add_security_headers(response):
        ""Add security headers to responses."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        if 'Content-Security-Policy' not in response.headers:
            csp = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "frame-ancestors 'self'"
            ]
            response.headers['Content-Security-Policy'] = '; '.join(csp)
            
        return response

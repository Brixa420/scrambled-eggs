"""
Scrambled Eggs - Secure P2P Messaging

A secure, end-to-end encrypted P2P messaging and file sharing application
with self-modifying encryption that evolves when security is compromised.
"""

__version__ = "0.1.0"


def create_app(config_class="config.settings"):
    """Create and configure the Flask application."""
    from flask import Flask

    # Create the Flask application
    app = Flask(__name__)

    try:
        # Load configuration
        app.config.from_object(config_class)

        # Initialize extensions
        from .extensions import assets, bootstrap, csrf, db, login_manager, mail, migrate

        # Initialize extensions
        db.init_app(app)
        login_manager.init_app(app)
        migrate.init_app(app, db)
        bootstrap.init_app(app)
        csrf.init_app(app)
        mail.init_app(app)
        assets.init_app(app)

        # Configure login manager
        login_manager.login_view = "auth.login"
        login_manager.login_message_category = "info"

        # Register blueprints
        from .api import api_bp
        from .routes.forum import bp as forum_bp

        app.register_blueprint(api_bp, url_prefix="/api")
        app.register_blueprint(forum_bp)

        # Register error handlers
        from .errors import init_error_handlers

        init_error_handlers(app)

        # Initialize database
        with app.app_context():
            db.create_all()

        return app

    except Exception as e:
        # Log the error
        app.logger.error(f"Failed to initialize application: {str(e)}")
        raise

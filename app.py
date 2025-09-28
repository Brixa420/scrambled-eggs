"""
Scrambled Eggs - Main Application Entry Point
"""
import os
from app import create_app, db
from app.models.user import User
from flask_migrate import Migrate

# Create the Flask application
app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Shell context for Flask shell
@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
    }

if __name__ == '__main__':
    app.run(debug=True)

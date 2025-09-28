@echo off

:: Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install flask flask-migrate flask-sqlalchemy flask-login flask-socketio flask-bootstrap flask-wtf flask-limiter flask-mail flask-assets
) else (
    call venv\Scripts\activate.bat
)

:: Set environment variables
set FLASK_APP=run.py
set FLASK_ENV=development

:: Create uploads directory if it doesn't exist
if not exist uploads mkdir uploads

:: Initialize and upgrade the database
echo Initializing database...
python -m flask db init
python -m flask db migrate -m "Initial migration"
python -m flask db upgrade

:: Create an admin user
echo.
echo Creating admin user...
python -c "from app import create_app; from app.extensions import db; from app.models.user import User; app = create_app(); app.app_context().push(); User.query.filter_by(username='admin').first() or User(username='admin', email='admin@example.com', is_admin=True).set_password('admin123') and print('Admin user created with username: admin, password: admin123')"

echo.
echo Starting the application...
python run.py

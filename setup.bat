@echo off
:: Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install --upgrade pip
    pip install -r requirements.txt
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
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

echo "\nSetup complete! Run 'flask run' to start the application."

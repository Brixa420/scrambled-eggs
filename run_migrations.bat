@echo off
echo Setting up database migrations...
python -m pip install -r requirements.txt
set FLASK_APP=web_app.py
set FLASK_ENV=development
python migrate_db.py
pause

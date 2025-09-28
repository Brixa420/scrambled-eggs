@echo off
set PYTHONPATH=%~dp0
set QT_DEBUG_PLUGINS=1
python -v "%~dp0simple_gui.py"
pause

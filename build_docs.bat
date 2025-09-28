@echo off
REM Batch script to build Scrambled Eggs documentation

echo Setting up documentation...

REM Create necessary directories
if not exist "docs\source\_static" mkdir "docs\source\_static"
if not exist "docs\source\_templates" mkdir "docs\source\_templates"
if not exist "docs\source\_static\css" mkdir "docs\source\_static\css"

echo Installing required packages...
pip install sphinx sphinx-rtd-theme sphinx-copybutton sphinx-tabs myst-parser

if errorlevel 1 (
    echo Failed to install required packages.
    exit /b 1
)

echo Creating documentation files...

REM Create conf.py if it doesn't exist
if not exist "docs\source\conf.py" (
    echo Creating conf.py...
    (
    echo # Configuration file for the Sphinx documentation builder.
echo.
echo import os
echo import sys
echo from datetime import datetime
echo.
echo # Add project to path

echo sys.path.insert(0, os.path.abspath('../..'))
echo.
echo # Project information

echo project = 'Scrambled Eggs'
echo copyright = f'2025, Your Organization'
echo author = 'Your Team'
echo release = '1.0.0'
echo.
echo # Extensions

echo extensions = [
echo     'sphinx.ext.autodoc',
echo     'sphinx.ext.napoleon',
echo     'sphinx.ext.viewcode',
echo     'sphinx.ext.intersphinx',
echo     'sphinx_copybutton',
echo     'sphinx_tabs.tabs',
echo     'sphinx_rtd_theme',
echo     'myst_parser',
echo ]
echo.
echo # Templates

echo templates_path = ['_templates']
echo exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
echo.
echo # HTML Theme

echo html_theme = 'sphinx_rtd_theme'
echo html_static_path = ['_static']
echo html_css_files = ['css/custom.css']
    ) > "docs\source\conf.py"
)

REM Create index.rst if it doesn't exist
if not exist "docs\source\index.rst" (
    echo Creating index.rst...
    (
    echo .. Scrambled Eggs documentation master file

echo.
echo Welcome to Scrambled Eggs
echo =========================
echo.
echo .. toctree::
echo    :maxdepth: 2
echo    :caption: Contents:
echo.
echo    getting_started
echo    user_guide
echo    api
echo.
echo Indices and tables
echo ==================
echo.
echo * :ref:`genindex`
echo * :ref:`modindex`
echo * :ref:`search`
    ) > "docs\source\index.rst"
)

REM Create getting_started.rst if it doesn't exist
if not exist "docs\source\getting_started.rst" (
    echo Creating getting_started.rst...
    (
    echo .. _getting_started:
echo.
echo Getting Started
echo ===============
echo.
echo Welcome to Scrambled Eggs! This guide will help you get started with the application.
echo.
echo Installation
echo ------------
echo.
echo .. code-block:: bash
echo.
echo     pip install -e .
echo.
echo Quick Start
echo -----------
echo.
echo 1. Start the application:
echo.
echo    .. code-block:: bash
echo.
echo       python -m scrambled_eggs
echo.
echo 2. Open your browser to http://localhost:5000
echo.
echo 3. Follow the on-screen instructions to set up your account.
echo.
echo Next Steps
echo ----------
echo.
echo - :ref:`User Guide ^<user_guide^>`
echo - :ref:`API Reference ^<api^>`
    ) > "docs\source\getting_started.rst"
)

REM Create custom.css if it doesn't exist
if not exist "docs\source\_static\css\custom.css" (
    echo Creating custom.css...
    (
    echo /* Custom styles for Scrambled Eggs documentation */
echo.
echo /* Make the page content wider */
echo .wy-nav-content {
echo     max-width: 1200px !important;
echo }
echo.
echo /* Style for code blocks */
echo .highlight {
echo     background: #f8f8f8;
echo     border: 1px solid #e1e4e5;
echo     border-radius: 4px;
echo     margin: 1em 0;
echo     padding: 0.5em;
echo }
echo.
echo /* Style for API documentation */
echo .py.class, .py.function, .py.method {
echo     margin-bottom: 2em;
echo     padding-bottom: 1em;
echo     border-bottom: 1px solid #e1e4e5;
echo }
    ) > "docs\source\_static\css\custom.css"
)

echo Building documentation...
python -m sphinx -T -E -b html -d _build/doctrees -D language=en docs/source docs/_build/html

if errorlevel 1 (
    echo Failed to build documentation.
    exit /b 1
)

echo.
echo Documentation built successfully!
echo You can view the documentation by opening: docs\_build\html\index.html

pause

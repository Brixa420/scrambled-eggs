@echo off
echo Starting Scrambled Eggs with Tor support...

:: Set Tor path
set TOR_PATH=C:\Users\admin\Desktop\Tor Browser\Browser\TorBrowser\Tor

:: Add Tor to PATH
set PATH=%PATH%;%TOR_PATH%

:: Set Tor-related environment variables
set ENABLE_TOR=true
set TOR_SOCKS_PORT=9150  # Default for Tor Browser
set TOR_CONTROL_PORT=9151  # Default for Tor Browser

:: Start the application
echo.
echo Starting Flask application...
echo Tor SOCKS5 Proxy: localhost:%TOR_SOCKS_PORT%
python web_app.py

:: Keep the window open if there's an error
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Troubleshooting steps:
    echo 1. Make sure Tor Browser is running
    echo 2. Check if Tor is running on port %TOR_SOCKS_PORT%
    echo 3. Try restarting Tor Browser
    echo.
    echo Press any key to exit.
    pause >nul
)

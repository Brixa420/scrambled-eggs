"""
Scrambled Eggs - Application Launcher
"""
import os
import sys
import logging
from web_app import create_app, socketio

def main():
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and configure the application
    app = create_app()
    
    # Get the port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application with SocketIO
    socketio.run(app, host='0.0.0.0', port=port, debug=True)

if __name__ == '__main__':
    main()

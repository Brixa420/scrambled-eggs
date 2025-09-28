#!/usr/bin/env python3
"""
Scrambled Eggs - Decentralized Server

This is the main entry point for the Scrambled Eggs decentralized server.
It initializes and starts all the necessary components.
"""
import os
import sys
import logging
import argparse
import signal
import atexit
from pathlib import Path

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.absolute()))

# Configure logging before importing other modules
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/scrambled-eggs.log')
    ]
)

# Import application components
try:
    from app.factory import create_app
    from app.network.p2p_manager import P2PManager
    from app.network.tor_manager import TorManager
    from app.config import (
        HOST, PORT, DEBUG, TOR_ENABLED, P2P_ENABLED,
        TOR_SOCKS_PORT, TOR_CONTROL_PORT, TOR_PASSWORD,
        P2P_PORT, P2P_BOOTSTRAP_NODES, P2P_MAX_PEERS
    )
except ImportError as e:
    logging.critical(f"Failed to import required modules: {e}")
    logging.critical("Make sure all dependencies are installed and the project structure is correct.")
    sys.exit(1)

# Global variables
app = None
p2p_manager = None
tor_manager = None


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logging.info("Shutting down Scrambled Eggs server...")
    shutdown()
    sys.exit(0)


def register_signal_handlers():
    """Register signal handlers for graceful shutdown."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def initialize_tor():
    """Initialize the Tor manager if Tor is enabled."""
    global tor_manager
    
    if not TOR_ENABLED:
        logging.info("Tor integration is disabled.")
        return
    
    try:
        logging.info("Initializing Tor manager...")
        tor_manager = TorManager(
            control_port=TOR_CONTROL_PORT,
            socks_port=TOR_SOCKS_PORT,
            password=TOR_PASSWORD
        )
        tor_manager.start()
        logging.info("Tor manager started successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize Tor: {e}")
        if DEBUG:
            logging.exception("Tor initialization error:")
        else:
            logging.warning("Continuing without Tor support.")


def initialize_p2p():
    """Initialize the P2P network if enabled."""
    global p2p_manager
    
    if not P2P_ENABLED:
        logging.info("P2P networking is disabled.")
        return
    
    try:
        logging.info("Initializing P2P network...")
        p2p_config = {
            'peer_id': f"node_{os.urandom(4).hex()}",
            'port': P2P_PORT,
            'bootstrap_nodes': [node for node in P2P_BOOTSTRAP_NODES if node],
            'max_peers': P2P_MAX_PEERS
        }
        
        p2p_manager = P2PManager(p2p_config)
        p2p_manager.start()
        logging.info(f"P2P network started on port {p2p_manager.port}")
    except Exception as e:
        logging.error(f"Failed to initialize P2P network: {e}")
        if DEBUG:
            logging.exception("P2P initialization error:")
        else:
            logging.warning("Continuing without P2P support.")


def shutdown():
    """Shutdown all components gracefully."""
    logging.info("Shutting down components...")
    
    # Shutdown P2P network
    if p2p_manager:
        try:
            p2p_manager.shutdown()
            logging.info("P2P network stopped.")
        except Exception as e:
            logging.error(f"Error stopping P2P network: {e}")
    
    # Shutdown Tor
    if tor_manager:
        try:
            tor_manager.shutdown()
            logging.info("Tor manager stopped.")
        except Exception as e:
            logging.error(f"Error stopping Tor manager: {e}")
    
    logging.info("Shutdown complete.")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run the Scrambled Eggs decentralized server.')
    parser.add_argument('--host', type=str, default=HOST,
                      help=f'Host to bind to (default: {HOST})')
    parser.add_argument('--port', type=int, default=PORT,
                      help=f'Port to listen on (default: {PORT})')
    parser.add_argument('--debug', action='store_true', default=DEBUG,
                      help=f'Enable debug mode (default: {DEBUG})')
    parser.add_argument('--no-tor', action='store_true',
                      help='Disable Tor integration')
    parser.add_argument('--no-p2p', action='store_true',
                      help='Disable P2P networking')
    
    return parser.parse_args()


def main():
    """Main entry point for the Scrambled Eggs server."""
    global app
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Override config with command line arguments
    host = args.host
    port = args.port
    debug = args.debug
    
    if args.no_tor:
        from app.config import config
        config.TOR_ENABLED = False
    
    if args.no_p2p:
        from app.config import config
        config.P2P_ENABLED = False
    
    # Register signal handlers for graceful shutdown
    register_signal_handlers()
    
    # Register shutdown function to run on exit
    atexit.register(shutdown)
    
    try:
        # Initialize the Flask application
        app = create_app()
        
        # Initialize Tor (if enabled)
        initialize_tor()
        
        # Initialize P2P network (if enabled)
        initialize_p2p()
        
        # Start the web server
        logging.info(f"Starting Scrambled Eggs server on {host}:{port} (debug: {debug})")
        app.run(host=host, port=port, debug=debug, use_reloader=False)
        
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        if debug:
            logging.exception("Error details:")
        sys.exit(1)
    finally:
        shutdown()


if __name__ == '__main__':
    main()

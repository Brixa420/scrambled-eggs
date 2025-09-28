""
Command-line interface for the Tor manager.
"""
import argparse
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List

from .manager import TorManager, tor_manager
from .config import get_tor_config, configure_logging
from .utils import test_tor_connection, install_tor, get_tor_connection_info

logger = logging.getLogger(__name__)

class TorCLI:
    """Command-line interface for the Tor manager."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.parser = self._create_parser()
        self.args = None
        self.config = None
        self.manager = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            description='Scrambled Eggs Tor Manager',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Global options
        parser.add_argument(
            '--config',
            type=str,
            help='Path to configuration file'
        )
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default='INFO',
            help='Logging level'
        )
        parser.add_argument(
            '--log-file',
            type=str,
            help='Log file path'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start the Tor manager')
        start_parser.add_argument(
            '--daemon',
            action='store_true',
            help='Run as a daemon'
        )
        
        # Stop command
        stop_parser = subparsers.add_parser('stop', help='Stop the Tor manager')
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show Tor status')
        status_parser.add_argument(
            '--json',
            action='store_true',
            help='Output as JSON'
        )
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Test Tor connection')
        test_parser.add_argument(
            '--json',
            action='store_true',
            help='Output as JSON'
        )
        
        # Install command
        install_parser = subparsers.add_parser('install', help='Install Tor')
        
        # New identity command
        newid_parser = subparsers.add_parser('newid', help='Get a new Tor identity')
        
        # Dashboard command
        dashboard_parser = subparsers.add_parser('dashboard', help='Start the web dashboard')
        dashboard_parser.add_argument(
            '--host',
            type=str,
            default='127.0.0.1',
            help='Host to bind the dashboard to'
        )
        dashboard_parser.add_argument(
            '--port',
            type=int,
            default=8050,
            help='Port to bind the dashboard to'
        )
        
        return parser
    
    def parse_args(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """Parse command-line arguments."""
        self.args = self.parser.parse_args(args)
        
        # Load configuration
        self.config = get_tor_config()
        
        # Override with command-line arguments
        if self.args.log_level:
            self.config['log_level'] = self.args.log_level
        if self.args.log_file:
            self.config['log_file'] = self.args.log_file
        
        # Configure logging
        configure_logging(self.config)
        
        return self.args
    
    def run(self) -> int:
        """Run the CLI."""
        if not self.args or not self.config:
            self.parse_args()
        
        # Handle commands
        command = self.args.command or 'help'
        handler = getattr(self, f'cmd_{command}', self.cmd_help)
        
        try:
            return handler()
        except KeyboardInterrupt:
            logger.info("Operation cancelled by user")
            return 0
        except Exception as e:
            logger.error(f"Error: {e}", exc_info=True)
            return 1
    
    def cmd_help(self) -> int:
        """Show help message."""
        self.parser.print_help()
        return 0
    
    def cmd_start(self) -> int:
        """Start the Tor manager."""
        # Initialize the Tor manager
        self.manager = TorManager(**self.config)
        
        # Set up signal handlers
        def handle_signal(signum, frame):
            logger.info("Received signal %d, shutting down...", signum)
            self.manager.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        
        # Start the manager
        logger.info("Starting Tor manager...")
        if not self.manager.start():
            logger.error("Failed to start Tor manager")
            return 1
        
        # Run as daemon if requested
        if self.args.daemon:
            import daemon
            with daemon.DaemonContext():
                self.manager.run_forever()
        else:
            self.manager.run_forever()
        
        return 0
    
    def cmd_stop(self) -> int:
        """Stop the Tor manager."""
        # TODO: Implement proper process management
        logger.warning("The 'stop' command is not fully implemented yet")
        return 0
    
    def cmd_status(self) -> int:
        """Show Tor status."""
        # Test Tor connection
        result = test_tor_connection(
            control_port=self.config['control_port'],
            socks_port=self.config['socks_port']
        )
        
        # Get detailed connection info
        connection_info = get_tor_connection_info(control_port=self.config['control_port'])
        
        if self.args.json:
            # Output as JSON
            status = {
                'connection_test': result,
                'connection_info': connection_info
            }
            print(json.dumps(status, indent=2))
        else:
            # Output as human-readable text
            print("\n=== Tor Status ===")
            print(f"Tor running: {'Yes' if result['tor_running'] else 'No'}")
            print(f"Control port accessible: {'Yes' if result['control_port_accessible'] else 'No'}")
            print(f"SOCKS port accessible: {'Yes' if result['socks_port_accessible'] else 'No'}")
            print(f"Using Tor: {'Yes' if result['is_using_tor'] else 'No'}")
            
            if result['external_ip']:
                print(f"\nExternal IP: {result['external_ip']}")
            if result['tor_ip']:
                print(f"Tor exit node IP: {result['tor_ip']}")
            
            if connection_info.get('is_running'):
                print(f"\nTor version: {connection_info.get('tor_version', 'Unknown')}")
                print(f"Uptime: {connection_info.get('uptime', 0)} seconds")
                print(f"Circuits: {len(connection_info.get('circuits', []))}")
                print(f"Active streams: {len(connection_info.get('streams', []))}")
        
        return 0
    
    def cmd_test(self) -> int:
        """Test Tor connection."""
        result = test_tor_connection(
            control_port=self.config['control_port'],
            socks_port=self.config['socks_port']
        )
        
        if self.args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n=== Tor Connection Test ===")
            print(f"Success: {'Yes' if result['success'] else 'No'}")
            
            if result['error']:
                print(f"Error: {result['error']}")
            
            print(f"\nTor running: {'Yes' if result['tor_running'] else 'No'}")
            print(f"Control port accessible: {'Yes' if result['control_port_accessible'] else 'No'}")
            print(f"SOCKS port accessible: {'Yes' if result['socks_port_accessible'] else 'No'}")
            print(f"Using Tor: {'Yes' if result['is_using_tor'] else 'No'}")
            
            if result['external_ip']:
                print(f"\nExternal IP: {result['external_ip']}")
            if result['tor_ip']:
                print(f"Tor exit node IP: {result['tor_ip']}")
            
            print(f"\nTest completed in {result['time_taken']:.2f} seconds")
        
        return 0 if result['success'] else 1
    
    def cmd_install(self) -> int:
        """Install Tor."""
        print("Installing Tor...")
        if install_tor():
            print("Tor installed successfully")
            return 0
        else:
            print("Failed to install Tor", file=sys.stderr)
            return 1
    
    def cmd_newid(self) -> int:
        """Get a new Tor identity."""
        from .utils import renew_tor_identity
        
        print("Requesting new Tor identity...")
        if renew_tor_identity(
            control_port=self.config['control_port'],
            password=self.config.get('password')
        ):
            print("New Tor identity acquired")
            return 0
        else:
            print("Failed to get new Tor identity", file=sys.stderr)
            return 1
    
    def cmd_dashboard(self) -> int:
        """Start the web dashboard."""
        # Override dashboard settings from command line
        dashboard_config = self.config.copy()
        dashboard_config['enable_dashboard'] = True
        dashboard_config['dashboard_host'] = self.args.host
        dashboard_config['dashboard_port'] = self.args.port
        
        # Initialize the Tor manager
        self.manager = TorManager(**dashboard_config)
        
        # Start the manager
        logger.info("Starting Tor manager with dashboard...")
        if not self.manager.start():
            logger.error("Failed to start Tor manager")
            return 1
        
        print(f"\nTor dashboard is running at: http://{self.args.host}:{self.args.port}")
        print("Press Ctrl+C to stop\n")
        
        # Keep the process running
        try:
            self.manager.run_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.manager.stop()
        
        return 0

def main():
    """Main entry point for the CLI."""
    cli = TorCLI()
    sys.exit(cli.run())

if __name__ == '__main__':
    main()

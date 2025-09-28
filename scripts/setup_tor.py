#!/usr/bin/env python3
"""
Script to set up and configure Tor for the application.
"""
import os
import sys
import subprocess
import platform
import shutil
import stat
from pathlib import Path
from typing import Optional, List, Dict, Any

# Configuration
TOR_VERSION = "0.4.8.7"  # Latest stable version as of knowledge cutoff
TOR_PORTS = {
    'control': 9051,
    'socks': 9050,
    'dns': 54,
    'http': 9063,
    'https': 9064
}

class TorInstaller:
    """Handles Tor installation and configuration."""
    
    def __init__(self, config_dir: str = None):
        """Initialize the Tor installer."""
        self.system = platform.system().lower()
        self.config_dir = Path(config_dir) if config_dir else Path.home() / '.scrambled_eggs'
        self.tor_data_dir = self.config_dir / 'tor_data'
        self.torrc_path = self.config_dir / 'torrc'
        self.torrc_defaults_path = self.config_dir / 'torrc-defaults'
        self.tor_binary = self._find_tor_binary()
        
    def _find_tor_binary(self) -> Optional[Path]:
        """Find the Tor binary in common locations."""
        # Check common locations
        common_paths = [
            '/usr/bin/tor',
            '/usr/local/bin/tor',
            '/usr/sbin/tor',
            '/usr/local/sbin/tor',
            'C:\\Program Files\\Tor\\tor.exe',
            'C:\\Program Files (x86)\\Tor\\tor.exe',
        ]
        
        for path in common_paths:
            if os.path.isfile(path):
                return Path(path)
        return None
    
    def install_tor(self) -> bool:
        """Install Tor if not already installed."""
        if self.tor_binary and self.tor_binary.exists():
            print(f"✓ Tor is already installed at {self.tor_binary}")
            return True
            
        print("Tor not found. Attempting to install...")
        
        try:
            if self.system == 'linux':
                return self._install_tor_linux()
            elif self.system == 'darwin':
                return self._install_tor_macos()
            elif self.system == 'windows':
                return self._install_tor_windows()
            else:
                print(f"❌ Unsupported operating system: {self.system}")
                return False
        except Exception as e:
            print(f"❌ Failed to install Tor: {e}")
            return False
    
    def _install_tor_linux(self) -> bool:
        """Install Tor on Linux."""
        try:
            # Try package managers
            if os.path.exists('/etc/debian_version'):
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 'tor'], check=True)
            elif os.path.exists('/etc/redhat-release'):
                subprocess.run(['sudo', 'yum', 'install', '-y', 'tor'], check=True)
            elif os.path.exists('/etc/arch-release'):
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', 'tor'], check=True)
            else:
                print("❌ Unsupported Linux distribution. Please install Tor manually.")
                return False
                
            self.tor_binary = Path('/usr/bin/tor')
            print("✓ Tor installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install Tor: {e}")
            return False
    
    def _install_tor_macos(self) -> bool:
        """Install Tor on macOS using Homebrew."""
        try:
            # Check if Homebrew is installed
            if not shutil.which('brew'):
                print("❌ Homebrew is required to install Tor on macOS. Please install it first.")
                return False
                
            subprocess.run(['brew', 'install', 'tor'], check=True)
            self.tor_binary = Path('/usr/local/bin/tor')
            print("✓ Tor installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install Tor: {e}")
            return False
    
    def _install_tor_windows(self) -> bool:
        """Provide instructions for manual Tor installation on Windows."""
        print("\nPlease install Tor Browser Bundle on Windows:")
        print("1. Download from: https://www.torproject.org/download/")
        print("2. Run the installer")
        print("3. Add the Tor directory to your PATH")
        print("\nAfter installation, run this script again.")
        return False
    
    def configure_tor(self) -> bool:
        """Configure Tor with application-specific settings."""
        try:
            # Create config directory
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self.tor_data_dir.mkdir(parents=True, exist_ok=True)
            
            # Create torrc file
            torrc_content = self._generate_torrc()
            self.torrc_path.write_text(torrc_content)
            
            # Set permissions (Unix-like systems)
            if self.system != 'windows':
                self.torrc_path.chmod(0o600)
                
            print(f"✓ Tor configuration created at {self.torrc_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to configure Tor: {e}")
            return False
    
    def _generate_torrc(self) -> str:
        """Generate torrc configuration."""
        return f"""## Scrambled Eggs Tor Configuration
## Generated by setup_tor.py

# Data directory
DataDirectory {self.tor_data_dir}

# Ports
ControlPort {TOR_PORTS['control']}
SocksPort {TOR_PORTS['socks']}
DNSPort {TOR_PORTS['dns']}
HTTPTunnelPort {TOR_PORTS['http']}
HTTPSPort {TOR_PORTS['https']}

# Security settings
SafeLogging 1
Log notice file {self.config_dir / 'tor_notice.log'} 
Log notice stdout

# Performance settings
NumEntryGuards 3
NumEntryGuards 8
NumDirectoryGuards 3
GuardLifetime 30 days
UseEntryGuards 1
EnforceDistinctSubnets 1

# Circuit settings
CircuitBuildTimeout 60
LearnCircuitBuildTimeout 1
CircWindowParameter 1000
NewCircuitPeriod 30
MaxCircuitDirtiness 600
MaxClientCircuitsPending 16
ClientUseIPv4 1
ClientUseIPv6 0
ClientPreferIPv6ORPort 0

# Connection settings
UseEntryGuards 1
UseGuardFraction 1
UseMicrodescriptors 1
UseMicrodescriptorsForCircuits 1

# Security enhancements
HardwareAccel 1
NoExec 1
SafeLogging 1
TestSocks 1
WarnUnsafeSocks 1

# Disable network features that might leak
DisableNetwork 0
DisableDebuggerAttachment 0

# Hidden services (if needed)
# HiddenServiceDir {self.tor_data_dir / 'hidden_service'}
# HiddenServicePort 80 127.0.0.1:8080

# Exit policy (be conservative)
ExitPolicy reject *:*
ExitPolicy reject6 *:*

# Bridge configuration (if needed)
# UseBridges 1
# Bridge obfs4 1.2.3.4:1234 FINGERPRINT cert=...
"""
    
    def create_systemd_service(self) -> bool:
        """Create a systemd service for Tor."""
        if self.system != 'linux':
            print("⚠ Systemd service creation is only supported on Linux")
            return False
            
        try:
            service_content = f"""[Unit]
Description=Scrambled Eggs Tor Service
After=network.target

[Service]
Type=simple
User={user}
ExecStart={self.tor_binary} -f {self.torrc_path}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
"""
            service_path = "/etc/systemd/system/scrambled-eggs-tor.service"
            
            # Get current user
            user = os.getenv('SUDO_USER') or os.getenv('USER')
            if not user:
                user = 'tor'
                
            # Write service file
            with open(service_path, 'w') as f:
                f.write(service_content)
                
            # Set permissions
            os.chmod(service_path, 0o644)
            
            # Reload systemd
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            
            print(f"✓ Systemd service created at {service_path}")
            print("\nTo enable and start the service:")
            print("  sudo systemctl enable scrambled-eggs-tor")
            print("  sudo systemctl start scrambled-eggs-tor")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to create systemd service: {e}")
            return False
    
    def verify_installation(self) -> bool:
        """Verify that Tor is installed and properly configured."""
        if not self.tor_binary or not self.tor_binary.exists():
            print("❌ Tor binary not found")
            return False
            
        # Check Tor version
        try:
            result = subprocess.run(
                [str(self.tor_binary), '--version'],
                capture_output=True,
                text=True
            )
            print(f"✓ {result.stdout.strip()}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to verify Tor installation: {e}")
            return False

def main():
    """Main function."""
    print("=== Scrambled Eggs Tor Setup ===\n")
    
    # Create installer
    installer = TorInstaller()
    
    # Install Tor
    if not installer.install_tor():
        print("\n❌ Tor installation failed. Please install Tor manually and try again.")
        sys.exit(1)
    
    # Configure Tor
    if not installer.configure_tor():
        print("\n❌ Tor configuration failed.")
        sys.exit(1)
    
    # Create systemd service (Linux only)
    if installer.system == 'linux':
        if input("\nCreate systemd service? [y/N] ").lower() == 'y':
            installer.create_systemd_service()
    
    # Verify installation
    print("\nVerifying installation...")
    if installer.verify_installation():
        print("\n✓ Tor setup completed successfully!")
        print(f"\nConfiguration directory: {installer.config_dir}")
        print(f"Tor configuration: {installer.torrc_path}")
        print("\nTo start Tor manually:")
        print(f"  {installer.tor_binary} -f {installer.torrc_path}")
    else:
        print("\n❌ Tor setup completed with warnings. Some features may not work correctly.")
        sys.exit(1)

if __name__ == "__main__":
    main()

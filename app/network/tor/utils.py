""
Utility functions for the Tor manager.
"""
import os
import socket
import time
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

import requests
from stem import Signal
from stem.control import Controller

logger = logging.getLogger(__name__)

def is_port_available(port: int, host: str = '127.0.0.1') -> bool:
    """Check if a port is available.
    
    Args:
        port: Port number to check
        host: Host to check (default: 127.0.0.1)
        
    Returns:
        bool: True if the port is available, False otherwise
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port: int = 9000, max_attempts: int = 100) -> int:
    """Find an available port starting from the given port.
    
    Args:
        start_port: Port to start checking from
        max_attempts: Maximum number of ports to check
        
    Returns:
        int: Available port number
        
    Raises:
        RuntimeError: If no available port is found
    """
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    raise RuntimeError(f"No available port found in range {start_port}-{start_port + max_attempts}")

def is_tor_running(control_port: int = 9051) -> bool:
    """Check if Tor is running and the control port is accessible.
    
    Args:
        control_port: Tor control port
        
    Returns:
        bool: True if Tor is running and the control port is accessible
    """
    try:
        with Controller.from_port(port=control_port) as controller:
            controller.authenticate()
            return True
    except:
        return False

def get_tor_version(tor_binary: str = 'tor') -> Optional[str]:
    """Get the version of the Tor binary.
    
    Args:
        tor_binary: Path to the Tor binary
        
    Returns:
        str: Tor version string or None if not found
    """
    try:
        result = subprocess.run(
            [tor_binary, '--version'],
            capture_output=True,
            text=True,
            check=True
        )
        version_line = result.stdout.split('\n')[0]
        return version_line.split(' ')[2]
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError) as e:
        logger.warning(f"Failed to get Tor version: {e}")
        return None

def get_external_ip(proxy: Optional[Dict[str, str]] = None, timeout: int = 10) -> Optional[str]:
    """Get the external IP address using the specified proxy.
    
    Args:
        proxy: Dictionary with proxy settings (e.g., {'http': 'socks5://127.0.0.1:9050'})
        timeout: Request timeout in seconds
        
    Returns:
        str: External IP address or None if the request failed
    """
    ip_services = [
        'https://api.ipify.org',
        'https://ident.me',
        'https://ifconfig.me/ip',
        'https://ipinfo.io/ip'
    ]
    
    for service in ip_services:
        try:
            response = requests.get(service, proxies=proxy, timeout=timeout)
            if response.status_code == 200:
                return response.text.strip()
        except:
            continue
    
    return None

def test_tor_connection(control_port: int = 9051, socks_port: int = 9050, timeout: int = 30) -> Dict[str, Any]:
    """Test the Tor connection and return the results.
    
    Args:
        control_port: Tor control port
        socks_port: Tor SOCKS port
        timeout: Test timeout in seconds
        
    Returns:
        Dictionary with test results
    """
    start_time = time.time()
    result = {
        'success': False,
        'error': None,
        'tor_running': False,
        'control_port_accessible': False,
        'socks_port_accessible': False,
        'external_ip': None,
        'tor_ip': None,
        'is_using_tor': False,
        'time_taken': 0
    }
    
    try:
        # Check if Tor is running
        result['tor_running'] = is_tor_running(control_port)
        
        if not result['tor_running']:
            result['error'] = 'Tor is not running or control port is not accessible'
            return result
        
        # Test control port
        try:
            with Controller.from_port(port=control_port) as controller:
                controller.authenticate()
                result['control_port_accessible'] = True
        except Exception as e:
            result['error'] = f'Control port authentication failed: {str(e)}'
            return result
        
        # Test SOCKS port
        try:
            proxy = {
                'http': f'socks5h://127.0.0.1:{socks_port}',
                'https': f'socks5h://127.0.0.1:{socks_port}'
            }
            
            # Get external IP without Tor
            result['external_ip'] = get_external_ip(timeout=timeout)
            
            # Get external IP with Tor
            result['tor_ip'] = get_external_ip(proxy=proxy, timeout=timeout)
            
            if result['tor_ip']:
                result['socks_port_accessible'] = True
                result['is_using_tor'] = result['external_ip'] != result['tor_ip']
                result['success'] = True
            else:
                result['error'] = 'Failed to get IP through Tor'
        
        except Exception as e:
            result['error'] = f'SOCKS port test failed: {str(e)}'
    
    except Exception as e:
        result['error'] = f'Unexpected error during Tor connection test: {str(e)}'
    
    finally:
        result['time_taken'] = time.time() - start_time
        return result

def renew_tor_identity(control_port: int = 9051, password: Optional[str] = None) -> bool:
    """Request a new Tor identity (new circuit).
    
    Args:
        control_port: Tor control port
        password: Tor control port password (if required)
        
    Returns:
        bool: True if the identity was renewed, False otherwise
    """
    try:
        with Controller.from_port(port=control_port) as controller:
            if password:
                controller.authenticate(password=password)
            else:
                controller.authenticate()
            
            # Signal Tor to establish a new clean circuit
            controller.signal(Signal.NEWNYM)
            
            # Wait for the new circuit to be established
            time.sleep(controller.get_newnym_wait())
            
            return True
    
    except Exception as e:
        logger.error(f"Failed to renew Tor identity: {e}")
        return False

def get_tor_connection_info(control_port: int = 9051) -> Dict[str, Any]:
    """Get information about the Tor connection.
    
    Args:
        control_port: Tor control port
        
    Returns:
        Dictionary with Tor connection information
    """
    info = {
        'tor_version': None,
        'is_running': False,
        'circuits': [],
        'streams': [],
        'bandwidth_used': None,
        'uptime': None,
        'exit_policy': None,
        'exit_nodes': None,
        'nickname': None,
        'fingerprint': None
    }
    
    try:
        with Controller.from_port(port=control_port) as controller:
            controller.authenticate()
            
            info['is_running'] = True
            info['tor_version'] = controller.get_version().version_str
            info['nickname'] = controller.get_conf('Nickname', 'unnamed')
            info['fingerprint'] = controller.get_info('fingerprint')
            info['uptime'] = int(controller.get_info('uptime', '0'))
            info['bandwidth_used'] = {
                'read': int(controller.get_info('traffic/read', '0')),
                'written': int(controller.get_info('traffic/written', '0'))
            }
            info['exit_policy'] = controller.get_exit_policy()
            
            # Get circuits
            for circuit in controller.get_circuits():
                if circuit.purpose == 'GENERAL':
                    info['circuits'].append({
                        'id': circuit.id,
                        'status': circuit.status,
                        'path': [f"{hop[0]} ({hop[1]})" for hop in circuit.path],
                        'purpose': circuit.purpose,
                        'build_flags': circuit.build_flags,
                        'time_created': circuit.time_created
                    })
            
            # Get streams
            for stream in controller.get_streams():
                info['streams'].append({
                    'id': stream.id,
                    'purpose': stream.purpose,
                    'target': f"{stream.target_address}:{stream.target_port}",
                    'status': stream.status,
                    'circuit_id': stream.circuit_id,
                    'source': stream.source_address
                })
            
            # Get exit nodes
            try:
                info['exit_nodes'] = controller.get_info('exit-policy/full').split('\n')
            except:
                info['exit_nodes'] = []
    
    except Exception as e:
        logger.error(f"Failed to get Tor connection info: {e}")
    
    return info

def install_tor() -> bool:
    """Install Tor on the system.
    
    Note: This is a platform-specific function and may require root/administrator privileges.
    
    Returns:
        bool: True if installation was successful, False otherwise
    """
    import platform
    import subprocess
    import sys
    
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            # Check for package manager
            if os.path.exists('/etc/debian_version'):
                # Debian/Ubuntu
                subprocess.check_call(['sudo', 'apt-get', 'update'])
                subprocess.check_call(['sudo', 'apt-get', 'install', '-y', 'tor'])
            elif os.path.exists('/etc/redhat-release'):
                # RHEL/CentOS
                subprocess.check_call(['sudo', 'yum', 'install', '-y', 'tor'])
            elif os.path.exists('/etc/arch-release'):
                # Arch Linux
                subprocess.check_call(['sudo', 'pacman', '-S', '--noconfirm', 'tor'])
            else:
                logger.error("Unsupported Linux distribution")
                return False
        
        elif system == 'darwin':  # macOS
            if os.path.exists('/opt/homebrew/bin/brew'):
                subprocess.check_call(['brew', 'install', 'tor'])
            else:
                logger.error("Homebrew is required to install Tor on macOS")
                return False
        
        elif system == 'windows':
            # Download Tor Expert Bundle
            import urllib.request
            import zipfile
            import tempfile
            
            # Get latest stable version
            response = requests.get('https://dist.torproject.org/torbrowser/update_3/release/downloads.json')
            data = response.json()
            version = data['tor_expert_bundle']['version']
            
            # Download and extract
            url = f"https://dist.torproject.org/tor-win64-{version}.zip"
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, 'tor.zip')
            
            logger.info(f"Downloading Tor Expert Bundle {version}...")
            urllib.request.urlretrieve(url, zip_path)
            
            logger.info("Extracting Tor...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Add Tor to PATH (temporary for current session)
            tor_dir = os.path.join(temp_dir, f'tor-win64-{version}')
            os.environ['PATH'] = f"{tor_dir};{os.environ['PATH']}"
            
            logger.info(f"Tor installed to {tor_dir}")
            logger.info("Please add this directory to your system PATH")
        
        else:
            logger.error(f"Unsupported operating system: {system}")
            return False
        
        logger.info("Tor installed successfully")
        return True
    
    except Exception as e:
        logger.error(f"Failed to install Tor: {e}")
        return False

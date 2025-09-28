#!/usr/bin/env python3
"""
Scrambled Eggs Installation Script
--------------------------------
This script helps install and configure the Scrambled Eggs P2P Messaging application.
"""

import os
import sys
import platform
import subprocess
import shutil
import venv
from pathlib import Path
from typing import Optional, List, Dict, Any

# Constants
APP_NAME = "Scrambled Eggs"
APP_VERSION = "1.1.0"
REQUIREMENTS_FILE = "requirements.txt"
PYTHON_MIN_VERSION = (3, 8)
PYTHON_RECOMMENDED_VERSION = (3, 9)

# Platform-specific configurations
PLATFORM_CONFIG = {
    'Windows': {
        'venv_name': 'venv',
        'activate_cmd': 'Scripts\\activate',
        'python_cmd': 'python',
        'pip_cmd': 'pip',
        'clear': 'cls',
    },
    'Linux': {
        'venv_name': 'venv',
        'activate_cmd': 'bin/activate',
        'python_cmd': 'python3',
        'pip_cmd': 'pip3',
        'clear': 'clear',
    },
    'Darwin': {
        'venv_name': 'venv',
        'activate_cmd': 'bin/activate',
        'python_cmd': 'python3',
        'pip_cmd': 'pip3',
        'clear': 'clear',
    }
}

# ANSI color codes
COLORS = {
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKCYAN': '\033[96m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
}

def color_text(text: str, color: str) -> str:
    """Return colored text if colors are supported."""
    if sys.stdout.isatty() and os.name != 'nt':  # Don't color on Windows
        return f"{COLORS.get(color, '')}{text}{COLORS['ENDC']}"
    return text

def print_header():
    """Print the installation header."""
    clear_screen()
    header = f"""
    {color_text('╔══════════════════════════════════════════════════╗', 'OKBLUE')}
    {color_text('║', 'OKBLUE')}      {color_text('✨ Scrambled Eggs P2P Messaging', 'OKCYAN')} {color_text('✨', 'OKBLUE')}      {color_text('║', 'OKBLUE')}
    {color_text('║', 'OKBLUE')}            {color_text(f'Version {APP_VERSION}', 'OKGREEN')}                   {color_text('║', 'OKBLUE')}
    {color_text('╚══════════════════════════════════════════════════╝', 'OKBLUE')}
    """
    print(header)

def clear_screen():
    """Clear the terminal screen."""
    os.system(PLATFORM_CONFIG[platform.system()]['clear'])

def check_python_version() -> bool:
    """Check if the Python version meets the minimum requirements."""
    if sys.version_info < PYTHON_MIN_VERSION:
        print(color_text(
            f"Error: Python {PYTHON_MIN_VERSION[0]}.{PYTHON_MIN_VERSION[1]} or higher is required. "
            f"You have Python {sys.version_info.major}.{sys.version_info.minor}.",
            'FAIL'
        ))
        return False
    
    if sys.version_info < PYTHON_RECOMMENDED_VERSION:
        print(color_text(
            f"Warning: Python {PYTHON_RECOMMENDED_VERSION[0]}.{PYTHON_RECOMMENDED_VERSION[1]} or higher is recommended. "
            f"You have Python {sys.version_info.major}.{sys.version_info.minor}.",
            'WARNING'
        )
        if not ask_yes_no("Continue anyway?", default=False):
            return False
    
    return True

def ask_yes_no(question: str, default: bool = True) -> bool:
    """Ask a yes/no question and return the answer."""
    yes_no = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            reply = input(f"{question} {yes_no} ").strip().lower()
            if not reply:
                return default
            if reply in ('y', 'yes'):
                return True
            if reply in ('n', 'no'):
                return False
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)
        print("Please respond with 'y' or 'n'.")

def run_command(cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> int:
    """Run a shell command and return the exit code."""
    try:
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env or os.environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Stream output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
        
        return process.returncode
    except Exception as e:
        print(color_text(f"Error running command: {e}", 'FAIL'))
        return 1

def create_virtualenv(venv_path: str) -> bool:
    """Create a Python virtual environment."""
    print(f"Creating virtual environment at {venv_path}...")
    try:
        venv.create(venv_path, with_pip=True)
        return True
    except Exception as e:
        print(color_text(f"Failed to create virtual environment: {e}", 'FAIL'))
        return False

def install_dependencies(venv_path: str) -> bool:
    """Install Python dependencies using pip."""
    print("Installing dependencies...")
    
    # Get the pip command for the virtual environment
    pip_cmd = os.path.join(venv_path, PLATFORM_CONFIG[platform.system()]['pip_cmd'])
    if platform.system() == 'Windows':
        pip_cmd += '.exe'
    
    # Install requirements
    cmd = [pip_cmd, 'install', '-r', REQUIREMENTS_FILE]
    if run_command(cmd) != 0:
        return False
    
    # Install in development mode
    cmd = [pip_cmd, 'install', '-e', '.']
    if run_command(cmd) != 0:
        return False
    
    return True

def create_directories() -> bool:
    """Create necessary directories for the application."""
    print("Creating application directories...")
    try:
        # Create data directory
        data_dir = os.path.join(os.path.expanduser('~'), '.scrambled-eggs')
        os.makedirs(data_dir, exist_ok=True)
        
        # Create cache directory
        cache_dir = os.path.join(os.path.expanduser('~'), '.cache', 'scrambled-eggs')
        os.makedirs(cache_dir, exist_ok=True)
        
        # Create log directory
        log_dir = os.path.join(os.path.expanduser('~'), '.local', 'share', 'scrambled-eggs', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        return True
    except Exception as e:
        print(color_text(f"Failed to create directories: {e}", 'FAIL'))
        return False

def generate_config() -> bool:
    """Generate a default configuration file."""
    print("Generating configuration...")
    try:
        config_path = os.path.join(os.path.expanduser('~'), '.scrambled-eggs', 'config.json')
        if os.path.exists(config_path):
            if not ask_yes_no("Configuration file already exists. Overwrite?", default=False):
                print("Using existing configuration file.")
                return True
        
        # Import the config module to access DEFAULTS
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from scrambled_eggs.config import Config
        
        # Create a new config with defaults
        config = Config()
        config.save()
        
        print(f"Configuration file created at {config_path}")
        return True
    except Exception as e:
        print(color_text(f"Failed to generate configuration: {e}", 'FAIL'))
        return False

def install_system_dependencies() -> bool:
    """Install system-level dependencies if needed."""
    system = platform.system()
    print(f"Checking system dependencies for {system}...")
    
    if system == 'Windows':
        # Check for Visual C++ Redistributable
        print("On Windows, make sure you have the latest Visual C++ Redistributable installed.")
        print("You can download it from: https://aka.ms/vs/17/release/vc_redist.x64.exe")
        
    elif system == 'Linux':
        # Check for FFmpeg and other dependencies
        print("Checking for FFmpeg...")
        if run_command(["which", "ffmpeg"]) != 0:
            print("FFmpeg is required for audio/video calls.")
            if ask_yes_no("Install FFmpeg now? (requires sudo)"):
                if os.path.exists("/etc/debian_version"):  # Debian/Ubuntu
                    cmd = ["sudo", "apt-get", "update"]
                    if run_command(cmd) != 0:
                        return False
                    cmd = ["sudo", "apt-get", "install", "-y", "ffmpeg", "libavdevice-dev", "libavfilter-dev", "libopus-dev", "libvpx-dev", "libx264-dev", "pkg-config", "libsrtp2-dev", "libvpx-dev", "libx264-dev"]
                elif os.path.exists("/etc/redhat-release"):  # RHEL/CentOS
                    cmd = ["sudo", "yum", "install", "-y", "ffmpeg", "ffmpeg-devel", "opus-devel", "libvpx-devel", "x264-devel", "pkgconfig", "libsrtp2-devel", "gcc-c++", "make"]
                else:
                    print(color_text("Unsupported Linux distribution. Please install FFmpeg and required development libraries manually.", 'WARNING'))
                    return False
                
                if run_command(cmd) != 0:
                    print(color_text("Failed to install system dependencies. Please install them manually.", 'FAIL'))
                    return False
    
    elif system == 'Darwin':  # macOS
        print("Checking for Homebrew...")
        if run_command(["which", "brew"]) != 0:
            print("Homebrew is required to install dependencies on macOS.")
            if ask_yes_no("Install Homebrew now?"):
                cmd = "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                if os.system(cmd) != 0:
                    print(color_text("Failed to install Homebrew. Please install it manually.", 'FAIL'))
                    return False
        
        print("Installing dependencies with Homebrew...")
        cmd = ["brew", "install", "ffmpeg", "openssl@1.1", "libsrtp", "pkg-config"]
        if run_command(cmd) != 0:
            print(color_text("Failed to install dependencies with Homebrew. Please install them manually.", 'FAIL'))
            return False
    
    return True

def setup_complete(venv_path: str):
    """Display completion message with next steps."""
    print("\n" + "=" * 50)
    print(color_text(f"🎉 {APP_NAME} has been successfully installed!", 'OKGREEN'))
    print("=" * 50)
    
    # Get the activate script path
    activate_script = os.path.join(venv_path, PLATFORM_CONFIG[platform.system()]['activate_cmd'])
    
    print("\nTo activate the virtual environment and start using the application:")
    print("\nOn Linux/macOS:")
    print(f"  source {activate_script}")
    print("  scrambled-eggs")
    
    print("\nOn Windows:")
    print(f"  {os.path.join(venv_path, 'Scripts', 'activate')}")
    print("  scrambled-eggs")
    
    print("\nTo start the signaling server (in a separate terminal):")
    print(f"  {os.path.join(venv_path, 'bin', 'python')} -m scrambled_eggs.signaling.server")
    
    print("\nFor more information, please refer to the documentation at:")
    print("https://github.com/yourusername/scrambled-eggs")
    print("\n" + "=" * 50)

def main():
    """Main installation function."""
    try:
        print_header()
        
        # Check Python version
        if not check_python_version():
            sys.exit(1)
        
        # Ask for confirmation
        print("This will install Scrambled Eggs P2P Messaging on your system.")
        print("The following steps will be performed:")
        print("  1. Create a Python virtual environment")
        print("  2. Install required Python packages")
        print("  3. Create necessary directories")
        print("  4. Generate default configuration")
        print("  5. Install system dependencies (if needed)")
        
        if not ask_yes_no("\nDo you want to continue?"):
            print("Installation cancelled.")
            sys.exit(0)
        
        # Create virtual environment
        venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv')
        if os.path.exists(venv_path):
            if ask_yes_no("Virtual environment already exists. Recreate?", default=False):
                shutil.rmtree(venv_path, ignore_errors=True)
            else:
                print("Using existing virtual environment.")
        
        if not os.path.exists(venv_path):
            if not create_virtualenv(venv_path):
                sys.exit(1)
        
        # Install system dependencies
        if not install_system_dependencies():
            if not ask_yes_no("Continue with installation? (Some features may not work)"):
                sys.exit(1)
        
        # Install Python dependencies
        if not install_dependencies(venv_path):
            print(color_text("Failed to install Python dependencies.", 'FAIL'))
            sys.exit(1)
        
        # Create directories
        if not create_directories():
            print(color_text("Failed to create application directories.", 'WARNING'))
        
        # Generate config
        if not generate_config():
            print(color_text("Failed to generate configuration.", 'WARNING'))
        
        # Display completion message
        setup_complete(venv_path)
        
    except KeyboardInterrupt:
        print("\nInstallation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(color_text(f"\nAn error occurred during installation: {e}", 'FAIL'))
        sys.exit(1)

if __name__ == "__main__":
    main()

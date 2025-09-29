#!/usr/bin/env python3
"""
Dependency Management Script for Scrambled Eggs

This script automates the process of updating and managing project dependencies.
It can update Python packages, check for security vulnerabilities, and ensure
consistent dependency versions across development and production environments.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Project root directory
PROJECT_ROOT = Path(__file__).parent.absolute()

# Configuration
REQUIREMENTS_FILES = {
    'main': 'requirements.txt',
    'dev': 'requirements-dev.txt',
    'test': 'requirements-test.txt',
}

# Platform-specific commands
PLATFORM = platform.system().lower()
IS_WINDOWS = PLATFORM == 'windows'
IS_LINUX = PLATFORM == 'linux'
IS_MAC = PLATFORM == 'darwin'

# Color codes for console output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text: str) -> None:
    """Print a formatted header."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.upper():^60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}\n")

def run_command(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> Tuple[bool, str]:
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=IS_WINDOWS
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, str(e)

def check_python_version() -> bool:
    """Check if the Python version meets requirements."""
    print(f"{Colors.OKBLUE}Checking Python version...{Colors.ENDC}")
    required = (3, 8)
    current = sys.version_info[:2]
    
    if current < required:
        print(f"{Colors.FAIL}Error: Python {required[0]}.{required[1]}+ is required (found {current[0]}.{current[1]}){Colors.ENDC}")
        return False
    
    print(f"{Colors.OKGREEN}✓ Python {current[0]}.{current[1]} is compatible{Colors.ENDC}")
    return True

def check_pip() -> bool:
    """Check if pip is installed and up to date."""
    print(f"\n{Colors.OKBLUE}Checking pip...{Colors.ENDC}")
    
    # Check if pip is installed
    success, output = run_command([sys.executable, "-m", "pip", "--version"], check=False)
    if not success:
        print(f"{Colors.FAIL}Error: pip is not installed or not in PATH{Colors.ENDC}")
        return False
    
    # Get pip version
    pip_version = output.split()[1] if 'pip' in output else 'unknown'
    print(f"Found pip version: {pip_version}")
    
    # Upgrade pip
    print("Upgrading pip...")
    success, output = run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    if success:
        print(f"{Colors.OKGREEN}✓ pip is up to date{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}Warning: Failed to update pip: {output}{Colors.ENDC}")
    
    return True

def install_dependencies() -> bool:
    """Install project dependencies using pip."""
    print_header("Installing Dependencies")
    
    # Install base requirements
    if not install_requirements('main'):
        return False
    
    # Install dev requirements if specified
    if args.dev:
        if not install_requirements('dev'):
            return False
    
    # Install test requirements if specified
    if args.test:
        if not install_requirements('test'):
            return False
    
    return True

def install_requirements(env: str) -> bool:
    """Install requirements for a specific environment."""
    req_file = REQUIREMENTS_FILES.get(env)
    if not req_file or not (PROJECT_ROOT / req_file).exists():
        print(f"{Colors.WARNING}Warning: {env} requirements file not found{Colors.ENDC}")
        return True  # Not a critical error
    
    print(f"\n{Colors.OKBLUE}Installing {env} dependencies from {req_file}...{Colors.ENDC}")
    
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--upgrade",  # Upgrade packages to latest versions
        "--no-cache-dir",  # Don't use pip cache
        "-r", str(PROJECT_ROOT / req_file)
    ]
    
    success, output = run_command(cmd)
    
    if success:
        print(f"{Colors.OKGREEN}✓ Successfully installed {env} dependencies{Colors.ENDC}")
        return True
    else:
        print(f"{Colors.FAIL}Error installing {env} dependencies:{Colors.ENDC}\n{output}")
        return False

def check_vulnerabilities() -> bool:
    """Check for known security vulnerabilities in dependencies."""
    print_header("Checking for Security Vulnerabilities")
    
    # Check if safety is installed
    success, _ = run_command([sys.executable, "-m", "safety", "--version"], check=False)
    if not success:
        print(f"{Colors.WARNING}Warning: safety not installed. Installing...{Colors.ENDC}")
        success, _ = run_command([sys.executable, "-m", "pip", "install", "safety"])
        if not success:
            print(f"{Colors.WARNING}Warning: Failed to install safety. Skipping vulnerability check.{Colors.ENDC}")
            return True
    
    # Run safety check
    print("Running safety check...")
    success, output = run_command([
        sys.executable, "-m", "safety", "check",
        "--full-report",
        "--file", str(PROJECT_ROOT / "requirements.txt")
    ], check=False)
    
    if success:
        print(f"{Colors.OKGREEN}✓ No known security vulnerabilities found{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}{output}{Colors.ENDC}")
    
    return True

def update_dependencies() -> bool:
    """Update all dependencies to their latest versions."""
    print_header("Updating Dependencies")
    
    # Update pip packages
    print(f"{Colors.OKBLUE}Updating pip packages...{Colors.ENDC}")
    
    # Get list of outdated packages
    success, output = run_command([
        sys.executable, "-m", "pip", "list", "--outdated", "--format=json"
    ])
    
    if not success:
        print(f"{Colors.FAIL}Error checking for outdated packages: {output}{Colors.ENDC}")
        return False
    
    try:
        outdated_pkgs = json.loads(output)
        if not outdated_pkgs:
            print(f"{Colors.OKGREEN}All packages are up to date{Colors.ENDC}")
            return True
            
        # Update each outdated package
        for pkg in outdated_pkgs:
            pkg_name = pkg['name']
            current = pkg['version']
            latest = pkg['latest_version']
            
            print(f"Updating {pkg_name} from {current} to {latest}...")
            success, output = run_command([
                sys.executable, "-m", "pip", "install", "--upgrade", pkg_name
            ])
            
            if success:
                print(f"{Colors.OKGREEN}✓ Successfully updated {pkg_name}{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}Warning: Failed to update {pkg_name}: {output}{Colors.ENDC}"
    
    except json.JSONDecodeError:
        print(f"{Colors.WARNING}Warning: Could not parse pip output{Colors.ENDC}")
        return False
    
    return True

def generate_requirements() -> bool:
    """Generate requirements files from the current environment."""
    print_header("Generating Requirements Files")
    
    # Generate main requirements
    print(f"{Colors.OKBLUE}Generating main requirements...{Colors.ENDC}")
    success, output = run_command([
        sys.executable, "-m", "pip", "freeze"
    ])
    
    if success:
        with open(PROJECT_ROOT / "requirements.txt", "w") as f:
            f.write(output)
        print(f"{Colors.OKGREEN}✓ Generated requirements.txt{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}Error generating requirements: {output}{Colors.ENDC}")
        return False
    
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Manage project dependencies')
    
    # Main actions
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--install', '-i', action='store_true', help='Install all dependencies')
    group.add_argument('--update', '-u', action='store_true', help='Update all dependencies')
    group.add_argument('--check', '-c', action='store_true', help='Check for security vulnerabilities')
    group.add_argument('--generate', '-g', action='store_true', help='Generate requirements files')
    
    # Options
    parser.add_argument('--dev', action='store_true', help='Include development dependencies')
    parser.add_argument('--test', action='store_true', help='Include test dependencies')
    
    return parser.parse_args()

def main() -> int:
    """Main entry point."""
    global args
    args = parse_arguments()
    
    # Print header
    print(f"\n{Colors.HEADER}{Colors.BOLD}Scrambled Eggs - Dependency Management{Colors.ENDC}\n")
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Ensure pip is installed and up to date
    if not check_pip():
        return 1
    
    # Execute the requested action
    success = True
    
    if args.install:
        success = install_dependencies()
    elif args.update:
        success = update_dependencies()
    elif args.check:
        success = check_vulnerabilities()
    elif args.generate:
        success = generate_requirements()
    
    # Print summary
    print_header("Summary")
    if success:
        print(f"{Colors.OKGREEN}✓ Operation completed successfully{Colors.ENDC}")
        return 0
    else:
        print(f"{Colors.FAIL}✗ Operation failed{Colors.ENDC}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}An unexpected error occurred:{Colors.ENDC} {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

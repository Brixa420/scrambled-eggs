#!/usr/bin/env python3
"""
Setup and build the Scrambled Eggs documentation.
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(command, cwd=None):
    """Run a shell command and return its output."""
    print(f"Running: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stdout:
            print("=== STDOUT ===")
            print(e.stdout)
        if e.stderr:
            print("=== STDERR ===")
            print(e.stderr)
        return False

def setup_documentation():
    """Set up and build the documentation."""
    # Get the project root directory
    project_root = Path(__file__).parent.absolute()
    docs_dir = project_root / "docs"
    source_dir = docs_dir / "source"
    build_dir = docs_dir / "_build"
    
    print("Setting up documentation...")
    
    # Create necessary directories
    (source_dir / "_static").mkdir(parents=True, exist_ok=True)
    (source_dir / "_templates").mkdir(exist_ok=True)
    
    # Install required packages
    print("\nInstalling required packages...")
    requirements = [
        "sphinx>=4.0.0",
        "sphinx-rtd-theme>=1.0.0",
        "sphinx-copybutton>=0.3.0",
        "sphinx-tabs>=3.0.0",
        "myst-parser>=0.15.0",
        "sphinx-autodoc-typehints>=1.12.0"
    ]
    
    for package in requirements:
        if not run_command(f"pip install {package}"):
            print(f"Failed to install {package}")
            return False
    
    # Create conf.py if it doesn't exist
    conf_py = source_dir / "conf.py"
    if not conf_py.exists():
        print("\nCreating conf.py...")
        with open(conf_py, "w", encoding="utf-8") as f:
            f.write("""# Configuration file for the Sphinx documentation builder.

import os
import sys
from datetime import datetime

# Add project to path
sys.path.insert(0, os.path.abspath('../..'))

# Project information
project = 'Scrambled Eggs'
copyright = f'{datetime.now().year}, Your Organization'
author = 'Your Team'
release = '1.0.0'

# Extensions
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx_copybutton',
    'sphinx_tabs.tabs',
    'sphinx_rtd_theme',
    'myst_parser',
]

# Templates
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# HTML Theme
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
html_css_files = ['css/custom.css']

# API Docs
autodoc_mock_imports = ['tor', 'stem', 'cryptography']
""")
    
    # Create index.rst if it doesn't exist
    index_rst = source_dir / "index.rst"
    if not index_rst.exists():
        print("\nCreating index.rst...")
        with open(index_rst, "w", encoding="utf-8") as f:
            f.write(""".. Scrambled Eggs documentation master file

Welcome to Scrambled Eggs
=========================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting_started
   user_guide
   api

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
""")
    
    # Create a simple getting_started.rst
    getting_started = source_dir / "getting_started.rst"
    if not getting_started.exists():
        print("\nCreating getting_started.rst...")
        with open(getting_started, "w", encoding="utf-8") as f:
            f.write(""".. _getting_started:

Getting Started
===============

Welcome to Scrambled Eggs! This guide will help you get started with the application.

Installation
------------

.. code-block:: bash

    pip install -e .

Quick Start
-----------

1. Start the application:

   .. code-block:: bash

      python -m scrambled_eggs

2. Open your browser to http://localhost:5000

3. Follow the on-screen instructions to set up your account.

Next Steps
----------

- :ref:`User Guide <user_guide>`
- :ref:`API Reference <api>`
""")
    
    # Create a simple user_guide.rst
    user_guide = source_dir / "user_guide.rst"
    if not user_guide.exists():
        print("\nCreating user_guide.rst...")
        with open(user_guide, "w", encoding="utf-8") as f:
            f.write(""".. _user_guide:

User Guide
==========

This guide provides detailed information about using Scrambled Eggs.

Features
--------

- Secure messaging
- File sharing
- End-to-end encryption
- Tor integration

Configuration
------------

Create a ``config.py`` file in your project root with the following settings:

.. code-block:: python

    # Security settings
    SECRET_KEY = 'your-secret-key-here'
    SECURITY_PASSWORD_SALT = 'your-password-salt-here'
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    
    # Tor settings
    TOR_ENABLED = True
    TOR_CONTROL_PORT = 9051

Troubleshooting
--------------

Common issues and solutions:

1. **Tor connection failed**
   - Make sure Tor is installed and running
   - Check if the control port is accessible

2. **Database errors**
   - Try deleting the database file and restarting the application
   - Check file permissions
""")
    
    # Create a simple api.rst
    api = source_dir / "api.rst"
    if not api.exists():
        print("\nCreating api.rst...")
        with open(api, "w", encoding="utf-8") as f:
            f.write(""".. _api:

API Reference
============

This section contains the API reference for Scrambled Eggs.

Core Modules
------------

.. automodule:: app.utils.security
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: app.network.tor_manager
   :members:
   :undoc-members:
   :show-inheritance:

Models
------

.. automodule:: app.models.message
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: app.models.user
   :members:
   :undoc-members:
   :show-inheritance:
""")
    
    # Create custom CSS
    css_dir = source_dir / "_static" / "css"
    css_dir.mkdir(parents=True, exist_ok=True)
    
    custom_css = css_dir / "custom.css"
    if not custom_css.exists():
        print("\nCreating custom.css...")
        with open(custom_css, "w", encoding="utf-8") as f:
            f.write("""/* Custom styles for Scrambled Eggs documentation */

/* Make the page content wider */
.wy-nav-content {
    max-width: 1200px !important;
}

/* Style for code blocks */
.highlight {
    background: #f8f8f8;
    border: 1px solid #e1e4e5;
    border-radius: 4px;
    margin: 1em 0;
    padding: 0.5em;
}

/* Style for API documentation */
.py.class, .py.function, .py.method {
    margin-bottom: 2em;
    padding-bottom: 1em;
    border-bottom: 1px solid #e1e4e5;
}

/* Style for parameters */
.field-list dt {
    font-weight: bold;
    margin-top: 0.5em;
}

.field-list dd {
    margin-bottom: 1em;
}
""")
    
    # Build the documentation
    print("\nBuilding documentation...")
    if run_command("sphinx-build -M html . _build", cwd=str(docs_dir)):
        print("\nDocumentation built successfully!")
        print(f"You can view the documentation by opening: {build_dir / 'html' / 'index.html'}")
        return True
    else:
        print("\nFailed to build documentation.")
        return False

if __name__ == "__main__":
    if setup_documentation():
        sys.exit(0)
    else:
        sys.exit(1)

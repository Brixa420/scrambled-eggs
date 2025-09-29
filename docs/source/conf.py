# Configuration file for the Sphinx documentation builder.
import os
import sys
from datetime import datetime

# Add project to path
sys.path.insert(0, os.path.abspath("../.."))

# Project information
project = "Scrambled Eggs"
copyright = f"{datetime.now().year}, Your Organization"
author = "Your Team"
release = "1.0.0"

# Only include essential extensions
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_rtd_theme",
]

# Templates
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# HTML Theme
html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_css_files = ["css/custom.css"]
html_js_files = ["js/interactive.js"]

# Internationalization
language = "en"
locale_dirs = ["../translations/"]
gettext_compact = False
gettext_uuid = True

# API Docs
autodoc_mock_imports = ["tor", "stem", "cryptography"]
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

# Intersphinx
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "flask": ("https://flask.palletsprojects.com/en/2.0.x/", None),
}

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True

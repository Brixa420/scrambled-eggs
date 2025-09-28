""
Compatibility module for handling differences between Werkzeug versions.
"""
try:
    # Try to import from hmac first (Python standard library)
    from hmac import compare_digest as safe_str_cmp
except ImportError:
    # Fall back to werkzeug.security if hmac.compare_digest is not available
    from werkzeug.security import safe_str_cmp

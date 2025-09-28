.. _user_guide:

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

"""
A simple web interface for Scrambled Eggs as an alternative to the PyQt5 GUI.
"""
import base64
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.absolute()))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_interface.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Global encryption engine instance
encryption_engine = None
<html>
<head>
    <title>Scrambled Eggs - Web Interface</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .status {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
        }
        .form-group {
            margin-bottom: 15px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 8px;
            margin: 5px 0 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Scrambled Eggs</h1>
        
        <div id="status" class="status" style="display: none;"></div>
        
        <div class="form-group">
            <h2>Encrypt Message</h2>
            <form id="encryptForm">
                <label for="message">Message:</label>
                <input type="text" id="message" name="message" required>
                <br>
                <button type="submit">Encrypt</button>
            </form>
            <div id="encryptedResult" style="margin-top: 10px; word-break: break-all;"></div>
        </div>
        
        <hr>
        
        <div class="form-group">
            <h2>Decrypt Message</h2>
            <form id="decryptForm">
                <label for="encrypted">Encrypted Message:</label>
                <input type="text" id="encrypted" name="encrypted" required>
                <br>
                <button type="submit">Decrypt</button>
            </form>
            <div id="decryptedResult" style="margin-top: 10px; word-break: break-all;"></div>
        </div>
    </div>
    
    <script>
        // Handle form submissions
        document.getElementById('encryptForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const message = document.getElementById('message').value;
            const response = await fetch('/api/encrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });
            const result = await response.json();
            if (result.error) {
                showStatus('Error: ' + result.error, 'error');
            } else {
                document.getElementById('encryptedResult').textContent = result.encrypted || 'Encrypted message will appear here';
                showStatus('Message encrypted successfully!', 'success');
            }
        });
        
        document.getElementById('decryptForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const encrypted = document.getElementById('encrypted').value;
            const response = await fetch('/api/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ encrypted })
            });
            const result = await response.json();
            if (result.error) {
                showStatus('Error: ' + result.error, 'error');
            } else {
                document.getElementById('decryptedResult').textContent = result.decrypted || 'Decrypted message will appear here';
                showStatus('Message decrypted successfully!', 'success');
            }
        });
        
        function showStatus(message, type) {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + type;
            status.style.display = 'block';
            setTimeout(() => {
                status.style.display = 'none';
            }, 5000);
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Render the main page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """Encrypt a message."""
    try:
        data = request.get_json()
        message = data.get('message', '')
        
        # In a real implementation, this would use the actual encryption logic
        # For now, we'll just return a mock response
        return jsonify({
            'encrypted': f'ENCRYPTED_{message}_MOCK',
            'status': 'success'
        })
    except Exception as e:
        logger.error(f"Encryption error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """Decrypt a message."""
    try:
        data = request.get_json()
        encrypted = data.get('encrypted', '')
        
        # In a real implementation, this would use the actual decryption logic
        # For now, we'll just return a mock response
        if encrypted.startswith('ENCRYPTED_') and encrypted.endswith('_MOCK'):
            decrypted = encrypted[10:-5]  # Remove the mock encryption wrapper
            return jsonify({
                'decrypted': decrypted,
                'status': 'success'
            })
        else:
            return jsonify({'error': 'Invalid encrypted message format'}), 400
    except Exception as e:
        logger.error(f"Decryption error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Scrambled Eggs web interface...")
    try:
        # Try to import the actual Scrambled Eggs functionality
        try:
            from scrambled_eggs.core import ScrambledEggs
            logger.info("Successfully imported ScrambledEggs core")
            # In a real implementation, you would initialize the engine here
            # engine = ScrambledEggs(password="your-password")
        except ImportError as e:
            logger.warning(f"Could not import ScrambledEggs core: {e}")
            logger.warning("Running in demo mode with mock encryption")
        
        # Start the web server
        port = int(os.environ.get('PORT', 5000))
        logger.info(f"Starting web server on http://localhost:{port}")
        app.run(host='0.0.0.0', port=port, debug=True)
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}", exc_info=True)

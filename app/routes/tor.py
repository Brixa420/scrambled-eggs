""
Tor network integration routes.
"""
import os
import socket
import requests
from flask import jsonify, render_template, request, current_app
from flask_login import login_required
from ..services.tor_service import TorService
from . import main

# Initialize Tor service
tor_service = TorService()

@main.route('/tor/status')
@login_required
def tor_status():
    """Get the current status of the Tor service."""
    status = tor_service.get_status()
    return jsonify(status)

@main.route('/tor/control', methods=['POST'])
@login_required
def tor_control():
    """Control the Tor service (start/stop/restart)."""
    action = request.json.get('action')
    
    if action == 'start':
        result = tor_service.start_tor()
    elif action == 'stop':
        result = tor_service.stop_tor()
    elif action == 'restart':
        result = tor_service.restart_tor()
    else:
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400
    
    return jsonify(result)

@main.route('/tor/check-ip')
@login_required
def check_ip():
    """Check the current public IP address through Tor."""
    try:
        # Try to get IP through Tor
        session = tor_service.get_tor_session()
        response = session.get('https://check.torproject.org/api/ip')
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'status': 'success',
                'ip': data.get('IP'),
                'is_tor': data.get('IsTor', False),
                'country': data.get('Country')
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to check IP through Tor'
            }), 400
            
    except Exception as e:
        current_app.logger.error(f'Error checking Tor IP: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': f'Error checking Tor IP: {str(e)}'
        }), 500

@main.route('/tor/browser')
@login_required
def tor_browser():
    """Launch Tor Browser if available."""
    result = tor_service.launch_tor_browser()
    return jsonify(result)

@main.route('/tor/circuit')
@login_required
def tor_circuit():
    """Get information about the current Tor circuit."""
    try:
        circuit = tor_service.get_circuit_info()
        return jsonify({
            'status': 'success',
            'circuit': circuit
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to get circuit info: {str(e)}'
        }), 500

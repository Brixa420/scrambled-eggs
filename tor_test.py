"""
Test script to verify Tor connection.
"""
import socket
import sys

import requests
import socks


def test_tor_connection():
    """Test if Tor connection is working."""
    # Set up the proxy
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9053)
    socket.socket = socks.socksocket
    
    try:
        print("🔍 Testing Tor connection...")
        
        # Test 1: Check if we can reach Tor check page
        try:
            response = requests.get(
                "https://check.torproject.org/api/ip",
                timeout=10
            )
            data = response.json()
            print("✅ Tor connection successful!")
            print(f"🌐 Your IP: {data.get('IP')}")
            print(f"🛡️ Is Tor: {data.get('IsTor', False)}")
            print(f"📍 Country: {data.get('Country')}")
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to connect through Tor: {e}")
            print("\nTroubleshooting steps:")
            print("1. Make sure Tor is running (check your start_tor.py window)")
            print("2. Verify the SOCKS port (default: 9053)")
            print("3. Check your internet connection")
            return False
            
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        return False

if __name__ == "__main__":
    test_tor_connection()
    input("\nPress Enter to exit...")
</empty_file>

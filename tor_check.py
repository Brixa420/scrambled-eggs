"""
Test script to verify Tor connection.
"""

import sys

import requests


def test_tor_connection():
    """Test if Tor connection is working using requests with SOCKS proxy."""
    proxies = {"http": "socks5h://127.0.0.1:9053", "https": "socks5h://127.0.0.1:9053"}

    try:
        print("🔍 Testing Tor connection...")
        response = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=10)
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


if __name__ == "__main__":
    test_tor_connection()
    input("\nPress Enter to exit...")

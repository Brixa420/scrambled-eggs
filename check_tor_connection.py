import requests
import os

def check_tor():
    try:
        # Try to get IP through Tor
        session = requests.session()
        session.proxies = {
            'http': 'socks5h://localhost:9050',
            'https': 'socks5h://localhost:9050'
        }
        
        print("Testing Tor connection...")
        response = session.get('https://check.torproject.org/api/ip')
        
        if response.status_code == 200:
            data = response.json()
            if data.get('IsTor', False):
                print("✅ Success! You are connected to Tor.")
                print(f"Your Tor IP: {data.get('IP')}")
            else:
                print("❌ Connected to the internet but not through Tor")
        else:
            print(f"❌ Could not verify Tor connection. Status code: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error checking Tor connection: {str(e)}")
        print("\nTroubleshooting steps:")
        print("1. Make sure Tor Browser is running")
        print("2. Check if Tor is running on port 9050")
        print("3. Try restarting Tor Browser")

if __name__ == "__main__":
    check_tor()

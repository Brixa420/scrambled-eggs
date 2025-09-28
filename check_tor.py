import os
import sys

def check_tor_installation():
    # Common Tor installation paths on Windows
    tor_paths = [
        r"C:\Users\admin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        r"C:\Program Files\Tor\tor.exe",
        r"C:\Program Files (x86)\Tor\tor.exe"
    ]
    
    print("Checking for Tor installation...")
    found = False
    
    for path in tor_paths:
        if os.path.exists(path):
            print(f"✅ Found Tor at: {path}")
            print(f"\nTo use Tor with your application, run the following command:\n")
            print(f'set "PATH=%PATH%;{os.path.dirname(path)}"')
            print("python web_app.py")
            found = True
            break
    
    if not found:
        print("❌ Tor not found in common locations.")
        print("\nPlease ensure Tor Browser is installed or provide the full path to tor.exe")

if __name__ == "__main__":
    check_tor_installation()

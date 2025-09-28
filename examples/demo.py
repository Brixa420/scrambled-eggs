""
Scrambled Eggs Demo
------------------

This script demonstrates the usage of the Scrambled Eggs encryption system.
"""
import os
import time
import argparse
from pathlib import Path

# Add parent directory to path to import scrambled_eggs
import sys
sys.path.append(str(Path(__file__).parent.parent))

from scrambled_eggs import ScrambledEggs, encrypt_file, decrypt_file
from scrambled_eggs.utils import human_readable_size, setup_logging

def print_header(title: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f"{title:^80}")
    print("=" * 80)

def demo_basic_encryption():
    """Demonstrate basic encryption and decryption."""
    print_header("Basic Encryption Demo")
    
    # Initialize with a password
    password = "my_secure_password_123!"
    print(f"Password: {password}")
    
    # Create a ScrambledEggs instance
    print("\nInitializing ScrambledEggs...")
    scrambler = ScrambledEggs(password)
    print(f"Initial layers: {scrambler.layers}")
    
    # Encrypt a message
    message = b"This is a secret message that needs to be encrypted!"
    print(f"\nOriginal message: {message.decode()}")
    print(f"Message size: {human_readable_size(len(message))}")
    
    print("\nEncrypting...")
    start_time = time.time()
    ciphertext, metadata = scrambler.encrypt(message)
    elapsed = time.time() - start_time
    
    print(f"Encryption completed in {elapsed:.4f} seconds")
    print(f"Ciphertext (first 32 bytes): {ciphertext[:32].hex()}...")
    print(f"Layers used: {metadata['layers_used']}")
    print(f"Security level: {metadata.get('security_level', 'unknown')}")
    
    # Simulate breach detection
    print("\nSimulating breach detection...")
    scrambler.breach_detector.suspicion_level = 1.0  # Force breach detection
    
    print("Encrypting again after breach...")
    ciphertext2, metadata2 = scrambler.encrypt(message)
    
    print(f"New layer count: {scrambler.layers}")
    if 'security_updates' in metadata2['breach_info']:
        print("Security parameters were updated:")
        for k, v in metadata2['breach_info']['security_updates'].items():
            print(f"  - {k}: {v}")
    
    # Decrypt (in demo mode, this just returns a success message)
    print("\nDecrypting...")
    plaintext = scrambler.decrypt(ciphertext2, metadata2)
    print(f"Decryption result: {plaintext.decode()}")

def demo_file_encryption():
    """Demonstrate file encryption and decryption."""
    print_header("File Encryption Demo")
    
    # Create a test file
    test_dir = Path("test_files")
    test_dir.mkdir(exist_ok=True)
    
    # Create a test file with some content
    test_file = test_dir / "secret_document.txt"
    with open(test_file, "w") as f:
        f.write("This is a confidential document.\n")
        f.write("It contains sensitive information that needs to be protected.\n" * 100)
    
    file_size = os.path.getsize(test_file)
    print(f"Created test file: {test_file}")
    print(f"File size: {human_readable_size(file_size)}")
    
    # Encrypted file path
    encrypted_file = test_dir / "secret_document.enc"
    
    # Encrypt the file
    password = "file_encryption_password_456!"
    print(f"\nEncrypting file with password: {password}")
    
    start_time = time.time()
    metadata = encrypt_file(
        str(test_file),
        str(encrypted_file),
        password,
        layers=50  # Use fewer layers for faster demo
    )
    elapsed = time.time() - start_time
    
    print(f"File encrypted in {elapsed:.2f} seconds")
    print(f"Encrypted file: {encrypted_file}")
    print(f"Encrypted size: {human_readable_size(os.path.getsize(encrypted_file))}")
    print(f"Layers used: {metadata.get('layers_used', 'N/A')}")
    
    # Decrypt the file
    decrypted_file = test_dir / "decrypted_document.txt"
    print(f"\nDecrypting file to: {decrypted_file}")
    
    start_time = time.time()
    decrypt_file(
        str(encrypted_file),
        str(decrypted_file),
        password
    )
    elapsed = time.time() - start_time
    
    print(f"File decrypted in {elapsed:.2f} seconds")
    print(f"Decrypted size: {human_readable_size(os.path.getsize(decrypted_file))}")
    
    # Show first few lines of decrypted content
    print("\nFirst few lines of decrypted content:")
    with open(decrypted_file, "r") as f:
        for i, line in enumerate(f):
            if i >= 3:  # Show first 3 lines
                break
            print(f"  {line.strip()}")
    
    print("\nNote: In demo mode, the actual file content is not preserved. "
          "The decrypted file contains a success message instead.")

def main():
    """Run the demo."""
    parser = argparse.ArgumentParser(description="Scrambled Eggs Encryption Demo")
    parser.add_argument(
        "--demo", 
        choices=["basic", "file", "all"], 
        default="all",
        help="Which demo to run (default: all)"
    )
    args = parser.parse_args()
    
    # Set up logging
    setup_logging()
    
    # Run selected demos
    if args.demo in ["basic", "all"]:
        demo_basic_encryption()
    
    if args.demo in ["file", "all"]:
        demo_file_encryption()
    
    print("\n" + "=" * 80)
    print("Demo completed successfully!")
    print("=" * 80)

if __name__ == "__main__":
    main()

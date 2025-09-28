# Scrambled Eggs 🥚🔒

A revolutionary secure communication platform powered by Clippy, the autonomous AI security orchestrator. Scrambled Eggs provides private, end-to-end encrypted P2P communication with self-modifying encryption that evolves and improves over time. Backed by Tor network integration and advanced cryptographic protocols, it ensures maximum privacy and security for all your communications.

## 🌟 Features

### AI-Powered Security
- **Clippy AI Security Orchestrator**: Autonomous AI that continuously monitors and enhances security
- **Self-Evolving Encryption**: Clippy develops and deploys new encryption protocols automatically
- **Threat Detection & Response**: Real-time anomaly detection and automated threat mitigation
- **Adaptive Security Posture**: Security measures that evolve based on emerging threats

### Secure Communication
- **End-to-End Encryption**: Military-grade encryption using hybrid AES-256 and custom protocols
- **P2P Chat & Calls**: Direct peer-to-peer encrypted messaging, voice, and video
- **Tor Network Integration**: Built-in Tor browser and routing for anonymous communication
- **Self-Destructing Messages**: Ephemeral messages that disappear after reading

### Advanced File Security
- **Encrypted File Sharing**: Secure file transfer with automatic encryption/decryption
- **Scrambled Eggs Encryption**: Proprietary hybrid encryption protocol combining AES-256 with AI-enhanced security
- **Secure Cloud Storage**: Encrypted file storage with client-side encryption
- **Tor-Protected Transfers**: Anonymous file sharing through the Tor network

### Security Architecture
- **Autonomous AI Security**: Clippy continuously monitors and updates security protocols
- **Hybrid Encryption**: Combines AES-256 with custom AI-developed ciphers
- **Perfect Forward Secrecy**: Ephemeral key exchange for each session
- **Tor Network Integration**: Built-in Tor client for anonymous routing
- **Zero-Knowledge Architecture**: No access to unencrypted data
- **Self-Healing Security**: Automatic detection and mitigation of vulnerabilities

### Privacy
- **No Central Server**: No central point of failure or surveillance
- **Metadata Protection**: Minimizes metadata leakage
- **Ephemeral Messages**: Option to send self-destructing messages
- **Decentralized**: No single point of control or failure

### User Experience
- **Intuitive Interface**: Clean design with security-first approach
- **Cross-Platform**: Available on Windows, macOS, Linux, and mobile
- **Tor Browser**: Built-in Tor browser for secure web access
- **Contact Management**: Secure contact discovery and verification
- **Encrypted Storage**: All local data is encrypted at rest with user-controlled keys
- **Dark Mode**: Eye-friendly interface with privacy in mind

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- FFmpeg (for video/audio processing)
- OpenSSL 3.0 or higher
- Tor (included in package, but system-wide installation recommended)
- 4GB+ RAM (8GB recommended for optimal AI performance)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Brixa420/scrambled-eggs.git
   cd scrambled-eggs
   ```

2. **Create and activate a virtual environment** (recommended):
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   # Start the signaling server (in a separate terminal)
   python -m scrambled_eggs.signaling.server
   
   # Start the application (in another terminal)
   python -m scrambled_eggs
   ```

5. **Build and install** (optional):
   ```bash
   pip install -e .
   scrambled-eggs  # Run the application
   ```

## 💻 Usage

### Starting the Application

1. **Start the Signaling Server** (required for P2P connections):
   ```bash
   python -m scrambled_eggs.signaling.server
   ```

2. **Launch the Application**:
   ```bash
   python -m scrambled_eggs
   ```

### Basic Usage

1. **Add a Contact**:
   - Click the "Add Contact" button
   - Enter your contact's ID and public key
   - Click "Add"

2. **Send a Message**:
   - Select a contact from the list
   - Type your message in the input field
   - Press Enter or click "Send"

3. **Make a Call**:
   - Select a contact
   - Click the "Video Call" or "Voice Call" button
   - Wait for the recipient to accept the call

4. **Share Files**:
   - Click the paperclip icon in the chat window
   - Select the file you want to send
   - The file will be encrypted and sent to the recipient

### Command Line Interface (CLI)

```bash
# Start the application
scrambled-eggs

# Start in debug mode
scrambled-eggs --debug

# Specify a custom config file
scrambled-eggs --config /path/to/config.json
```

# Decrypt a file
scrambled-eggs decrypt file.enc --output file.txt

# Check system security status
scrambled-eggs status
```

### Python API

```python
from scrambled_eggs import ScrambledEggs, SecurityService, run_tray_app

# Basic encryption/decryption
scrambler = ScrambledEggs("my-secret-password")
ciphertext, metadata = scrambler.encrypt(b"My secret message")
decrypted = scrambler.decrypt(ciphertext, metadata)

# Start the security service as a background process
service = SecurityService("my-secret-password")
service.start()  # Runs in the background

# Start the system tray application
run_tray_app("my-secret-password")  # Requires GUI support
```

### File Encryption

```python
from scrambled_eggs import encrypt_file, decrypt_file

# Encrypt a file with automatic layer adjustment
metadata = encrypt_file("sensitive_document.pdf", "encrypted.segg", "my-password")
print(f"File encrypted with {metadata['layers_used']} layers")

decrypt_file("encrypted.segg", "decrypted.txt", "my-password")
```
## How It Works

### Core Security Flow
1. **AI-Enhanced Key Generation**: Clippy generates and manages cryptographic keys with AI-optimized parameters
2. **Secure Handshake**: Quantum-resistant key exchange using hybrid cryptography
3. **Adaptive Encryption**: Messages and files are encrypted with evolving algorithms
4. **Tor Integration**: All communications are optionally routed through the Tor network
5. **Continuous Monitoring**: Clippy monitors for threats and anomalies in real-time
6. **Self-Improving Security**: The system evolves its security measures based on threat intelligence

### Clippy AI Security Orchestrator
Clippy is the autonomous AI at the heart of Scrambled Eggs, responsible for:
- Continuously analyzing and improving encryption methods
- Detecting and responding to security threats in real-time
- Managing secure key exchange and storage
- Optimizing performance while maintaining maximum security
- Developing and deploying new security protocols as needed

### Scrambled Eggs Encryption Protocol
Our proprietary hybrid encryption combines:
- AES-256 for bulk encryption
- Custom AI-developed ciphers for enhanced security
- Post-quantum cryptographic primitives
- Continuous protocol evolution based on threat intelligence

## Security Features

{{ ... }}

MIT License - See [LICENSE](LICENSE) for details

## Contributing

We welcome contributions to the Scrambled Eggs ecosystem. Please review our [Security Guidelines](SECURITY.md) and [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests. All contributions are subject to security review by the Clippy AI Security Orchestrator.

## Security Research

We encourage responsible disclosure of security vulnerabilities. Please report any security issues to our [Security Team](mailto:security@scrambledeggs.app).

## License

Scrambled Eggs is released under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Scrambled Eggs is designed to provide strong security and privacy protections. However, no system can guarantee absolute security. Users are encouraged to practice good security hygiene and keep their software up to date.

## Roadmap

- [ ] Add more sophisticated breach detection
- [ ] Implement parallel hashing for better performance
- [ ] Add more encryption algorithms
- [ ] Create a GUI interface

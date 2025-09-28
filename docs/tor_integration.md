# Tor Integration Guide

This document provides comprehensive information about the Tor integration in Scrambled Eggs, including setup, configuration, and usage.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Performance Tuning](#performance-tuning)
- [Monitoring](#monitoring)
- [FAQs](#faqs)

## Overview

Scrambled Eggs integrates with the Tor network to provide anonymous communication and protect user privacy. The integration includes:

- Automatic Tor process management
- Circuit isolation for different types of traffic
- Secure communication channels
- Performance monitoring and metrics
- Systemd service for automatic startup

## Prerequisites

- Python 3.8+
- Tor (will be installed automatically if not present)
- `stem` Python package
- `psutil` for process monitoring
- `prometheus_client` for metrics (optional)

## Installation

### Automatic Installation

Run the setup script to install and configure Tor:

```bash
python scripts/setup_tor.py
```

This will:
1. Install Tor if not already installed
2. Create a configuration directory at `~/.scrambled_eggs/`
3. Generate a custom `torrc` file
4. Optionally create a systemd service

### Manual Installation

1. Install Tor using your system's package manager:
   - **Ubuntu/Debian**: `sudo apt-get install tor`
   - **Fedora**: `sudo dnf install tor`
   - **macOS**: `brew install tor`
   - **Windows**: Download from [torproject.org](https://www.torproject.org/download/)

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Tor Configuration

The main configuration file is located at `~/.scrambled_eggs/torrc`. Key settings:

```
# Data directory
DataDirectory ~/.scrambled_eggs/tor_data

# Ports
ControlPort 9051
SocksPort 9050
DNSPort 54
HTTPTunnelPort 9063
HTTPSPort 9064

# Security settings
SafeLogging 1
Log notice file ~/.scrambled_eggs/tor_notice.log

# Performance settings
NumEntryGuards 3
CircuitBuildTimeout 60
MaxCircuitDirtiness 600
```

### Application Configuration

Configure the Tor manager in your application:

```python
from app.network.tor_manager import TorManager

# Create a Tor manager instance
tor_manager = TorManager(
    control_port=9051,
    socks_port=9050,
    tor_data_dir="~/.scrambled_eggs/tor_data"
)

# Start Tor
tor_manager.start()
```

## Usage

### Basic Usage

```python
# Get a circuit for a specific purpose
circuit = tor_manager.get_circuit_for_purpose("browsing")

# Get connection status
status = tor_manager.get_connection_status()
print(f"Tor version: {status['version']}")
print(f"Uptime: {status['uptime']} seconds")

# Request a new identity
tor_manager.new_identity()

# Get network information
network_info = tor_manager.get_network_info()
```

### Circuit Isolation

Different purposes get different circuits by default:

```python
# These will use different circuits
browsing_circuit = tor_manager.get_circuit_for_purpose("browsing")
api_circuit = tor_manager.get_circuit_for_purpose("api")
```

### Monitoring

Start the monitoring service:

```bash
python scripts/monitor_tor.py --log-level INFO
```

View metrics at `http://localhost:9091/metrics`

## API Reference

### TorManager

#### Methods

- `start()`: Start the Tor manager
- `stop()`: Stop the Tor manager
- `get_circuit_for_purpose(purpose: str) -> TorCircuit`: Get or create a circuit
- `get_circuit_info(circuit_id: str) -> dict`: Get information about a circuit
- `get_all_circuits() -> List[dict]`: Get information about all circuits
- `close_circuit(circuit_id: str)`: Close a circuit
- `new_identity()`: Request a new identity (new circuit)
- `get_connection_status() -> dict`: Get connection status
- `get_network_info() -> dict`: Get network information

### TorCircuit

#### Properties

- `circuit_id`: Unique identifier for the circuit
- `purpose`: Purpose of the circuit
- `state`: Current state (NEW, BUILDING, READY, etc.)
- `created_at`: When the circuit was created
- `last_used`: When the circuit was last used
- `is_isolated`: Whether the circuit is isolated
- `stream_count`: Number of active streams
- `nodes`: List of nodes in the circuit

## Troubleshooting

### Common Issues

1. **Tor won't start**
   - Check if Tor is installed: `tor --version`
   - Check logs: `~/.scrambled_eggs/tor_notice.log`
   - Ensure the control port is not in use

2. **Connection issues**
   - Check if Tor is running: `ps aux | grep tor`
   - Verify the control port: `netstat -tuln | grep 9051`
   - Check firewall settings

3. **Performance problems**
   - Try increasing `CircuitBuildTimeout`
   - Adjust `NumEntryGuards`
   - Use bridges if Tor is blocked

## Security Considerations

- Always use the latest version of Tor
- Enable safe logging
- Use circuit isolation for sensitive operations
- Monitor for security advisories
- Consider using bridges in censored regions

## Performance Tuning

### Configuration Options

- `CircuitBuildTimeout`: Increase if circuits fail to build
- `NumEntryGuards`: More guards increase security but may reduce performance
- `MaxCircuitDirtiness`: How long to keep circuits open
- `NewCircuitPeriod`: How often to create new circuits

### Monitoring

Monitor these key metrics:
- Circuit build times
- Bandwidth usage
- Error rates
- Memory usage

## Monitoring

### Metrics

Prometheus metrics are available at `http://localhost:9091/metrics`:

- `tor_up`: Whether Tor is running
- `tor_circuits`: Number of active circuits
- `tor_streams`: Number of active streams
- `tor_bytes_read`: Total bytes read
- `tor_bytes_written`: Total bytes written
- `tor_uptime_seconds`: Tor daemon uptime

### Logs

Check these log files:
- `~/.scrambled_eggs/tor_notice.log`: Tor daemon logs
- `tor_monitor.log`: Monitoring service logs

## FAQs

### How do I update Tor?

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get upgrade tor

# Fedora
sudo dnf upgrade tor

# macOS
brew upgrade tor
```

### How do I use a bridge?

Add to your `torrc`:

```
UseBridges 1
Bridge obfs4 1.2.3.4:1234 FINGERPRINT cert=...
```

### How do I run as a service?

```bash
# Create systemd service
sudo python scripts/setup_tor.py

# Enable and start the service
sudo systemctl enable scrambled-eggs-tor
sudo systemctl start scrambled-eggs-tor
```

### How do I debug issues?

1. Enable debug logging in `torrc`:
   ```
   Log debug file ~/.scrambled_eggs/tor_debug.log
   ```

2. Run Tor in the foreground:
   ```bash
   tor -f ~/.scrambled_eggs/torrc
   ```

3. Check the logs:
   ```bash
   tail -f ~/.scrambled_eggs/tor_*.log
   ```

## Support

For additional help, please open an issue on our [GitHub repository](https://github.com/yourusername/scrambled-eggs/issues).

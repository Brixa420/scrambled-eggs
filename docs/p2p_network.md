# Brixa P2P Network Documentation

## Overview
The Brixa P2P Network is a decentralized peer-to-peer networking layer that enables nodes to discover and communicate with each other, even when behind NATs or firewalls. It includes advanced features like NAT traversal, connection monitoring, and metrics collection.

## Features

### Core Features
- **Peer Discovery**: Find and connect to other nodes in the network
- **NAT Traversal**: Automatically detect and work around NAT/firewall restrictions
- **Connection Monitoring**: Track connection health and performance metrics
- **Message Routing**: Efficiently route messages through the network
- **Load Balancing**: Distribute network load across multiple connections

### Advanced Features
- **TURN Relay Support**: Use TURN servers as relays when direct connections fail
- **Hole Punching**: Establish direct connections between peers behind NATs
- **Connection Pooling**: Manage multiple connections efficiently
- **Metrics Collection**: Monitor network performance and health

## Configuration

### Node Configuration

```python
from brixa.network import P2PNode, TURNServer

# Configure TURN servers
turn_servers = [
    TURNServer(
        host="turn.example.com",
        port=3478,
        username="your-username",
        password="your-password"
    )
]

# Create a P2P node
node = P2PNode(
    host="0.0.0.0",  # Listen on all interfaces
    port=5000,        # Port to listen on
    peer_id="my-node-1",  # Optional: specify a peer ID
    turn_servers=turn_servers,
    max_peers=100     # Maximum number of peers to connect to
)
```

### Metrics Collection

Metrics are collected automatically and can be exported in Prometheus format:

```python
from brixa.network.metrics import get_metrics

# Get metrics in Prometheus format
prometheus_metrics = get_metrics().to_prometheus()

# Get metrics as a dictionary
metrics_dict = get_metrics().to_dict()

# Get metrics as JSON
metrics_json = get_metrics().to_json()
```

## API Reference

### P2PNode

#### Methods

##### `start()`
Start the P2P node and begin listening for connections.

##### `stop()`
Stop the P2P node and close all connections.

##### `connect_to_peer(host: str, port: int) -> str`
Connect to a peer at the specified host and port.

##### `send_message(peer_id: str, message: bytes) -> bool`
Send a message to the specified peer.

##### `broadcast(message: bytes, exclude: List[str] = None) -> None`
Broadcast a message to all connected peers.

##### `get_connection_health(peer_id: str) -> Optional[Dict]`
Get health information for a connection.

### Metrics

#### Available Metrics

| Name | Type | Description |
|------|------|-------------|
| `p2p_messages_sent_total` | Counter | Total number of messages sent |
| `p2p_messages_received_total` | Counter | Total number of messages received |
| `p2p_peers_connected` | Gauge | Number of currently connected peers |
| `p2p_message_latency_seconds` | Histogram | Message round-trip latency |
| `p2p_uptime_seconds` | Gauge | Node uptime in seconds |

## Monitoring and Alerting

### Prometheus Configuration

Add the following to your Prometheus configuration to scrape metrics from your Brixa node:

```yaml
scrape_configs:
  - job_name: 'brixa_node'
    static_configs:
      - targets: ['localhost:8000']  # Update with your node's metrics endpoint
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
- name: brixa_alerts
  rules:
  - alert: HighMessageLatency
    expr: histogram_quantile(0.95, rate(p2p_message_latency_seconds_bucket[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High message latency
      description: '95th percentile message latency is {{ $value }}s'

  - alert: NoConnectedPeers
    expr: p2p_peers_connected == 0
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: No connected peers
      description: 'Node has been disconnected from all peers for 10 minutes'
```

## Troubleshooting

### Common Issues

#### Connection Failures
- **Symptom**: Unable to connect to peers
- **Check**:
  - Verify network connectivity
  - Check firewall settings
  - Ensure TURN servers are accessible

#### High Latency
- **Symptom**: Slow message delivery
- **Check**:
  - Monitor `p2p_message_latency_seconds`
  - Check network congestion
  - Verify TURN server performance

#### Memory Usage
- **Symptom**: High memory usage
- **Check**:
  - Monitor number of connected peers
  - Check message queue size
  - Review message handling code for leaks

## Best Practices

1. **Connection Management**:
   - Use connection pooling for frequently communicating peers
   - Implement exponential backoff for reconnection attempts
   - Monitor connection health and rotate unhealthy connections

2. **Message Handling**:
   - Use message compression for large payloads
   - Implement message validation
   - Use timeouts for message delivery

3. **Security**:
   - Use TLS for all connections
   - Implement message authentication
   - Rate limit incoming connections

## Performance Tuning

### Connection Pool Size
Adjust the maximum number of peers based on your hardware:

```python
# For resource-constrained devices
node = P2PNode(max_peers=20)

# For high-performance servers
node = P2PNode(max_peers=1000)
```

### Message Queue
Tune the message queue size based on your workload:

```python
# Default queue size is 1000 messages
node = P2PNode(message_queue_size=5000)
```

## Example: Creating a Simple P2P Application

```python
import asyncio
from brixa.network import P2PNode

class SimpleP2PApp:
    def __init__(self, port):
        self.node = P2PNode(port=port)
        self.node.on_message = self.handle_message
    
    async def start(self):
        await self.node.start()
        print(f"Node started on port {self.node.port}")
    
    async def handle_message(self, peer_id: str, message: bytes):
        print(f"Received from {peer_id}: {message.decode()}")
    
    async def send_message(self, peer_address: str, message: str):
        host, port = peer_address.split(":")
        peer_id = await self.node.connect_to_peer(host, int(port))
        await self.node.send_message(peer_id, message.encode())

async def main():
    # Start first node
    app1 = SimpleP2PApp(5000)
    await app1.start()
    
    # Start second node
    app2 = SimpleP2PApp(5001)
    await app2.start()
    
    # Send a message from node 1 to node 2
    await app1.send_message("localhost:5001", "Hello from node 1!")
    
    # Keep the nodes running
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
```

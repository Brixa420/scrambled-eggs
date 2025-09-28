const WebSocket = require('ws');
const http = require('http');
const url = require('url');

class SignalingServer {
  constructor(port = 8080) {
    this.port = port;
    this.rooms = new Map(); // roomId -> Set of WebSocket clients
    this.server = http.createServer();
    this.wss = new WebSocket.Server({ server: this.server });

    this.wss.on('connection', (ws, req) => {
      const { query } = url.parse(req.url, true);
      const { roomId, peerId } = query;

      if (!roomId || !peerId) {
        ws.close(4000, 'Missing roomId or peerId');
        return;
      }

      // Add client to room
      if (!this.rooms.has(roomId)) {
        this.rooms.set(roomId, new Map());
      }

      const room = this.rooms.get(roomId);
      room.set(peerId, ws);

      // Notify other peers in the room
      this.broadcastToRoom(roomId, peerId, {
        type: 'peer-connected',
        peerId,
        roomId
      });

      // Send list of existing peers to the new client
      const peers = Array.from(room.keys()).filter(id => id !== peerId);
      if (peers.length > 0) {
        ws.send(JSON.stringify({
          type: 'peers-list',
          peers,
          roomId
        }));
      }

      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          this.handleMessage(ws, roomId, peerId, data);
        } catch (error) {
          console.error('Error parsing message:', error);
        }
      });

      ws.on('close', () => {
        this.handleDisconnect(roomId, peerId);
      });

      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        this.handleDisconnect(roomId, peerId);
      });
    });
  }

  handleMessage(sender, roomId, senderId, message) {
    if (!this.rooms.has(roomId)) return;

    const room = this.rooms.get(roomId);
    const { target, type } = message;

    // Add sender information to the message
    const messageWithSender = {
      ...message,
      sender: senderId,
      roomId
    };

    if (target) {
      // Send to specific peer
      const targetWs = room.get(target);
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify(messageWithSender));
      }
    } else {
      // Broadcast to all peers in the room except sender
      this.broadcastToRoom(roomId, senderId, messageWithSender);
    }
  }

  broadcastToRoom(roomId, excludePeerId, message) {
    if (!this.rooms.has(roomId)) return;

    const room = this.rooms.get(roomId);
    room.forEach((ws, peerId) => {
      if (peerId !== excludePeerId && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    });
  }

  handleDisconnect(roomId, peerId) {
    if (!this.rooms.has(roomId)) return;

    const room = this.rooms.get(roomId);
    room.delete(peerId);

    // Notify other peers about disconnection
    this.broadcastToRoom(roomId, peerId, {
      type: 'peer-disconnected',
      peerId,
      roomId
    });

    // Clean up empty rooms
    if (room.size === 0) {
      this.rooms.delete(roomId);
    }
  }

  start() {
    this.server.listen(this.port, () => {
      console.log(`Signaling server running on ws://localhost:${this.port}`);
    });
  }

  stop() {
    this.wss.close(() => {
      console.log('Signaling server stopped');
    });
  }
}

// Start the server if this file is run directly
if (require.main === module) {
  const port = process.env.PORT || 8080;
  const server = new SignalingServer(port);
  server.start();

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('Shutting down signaling server...');
    server.stop();
    process.exit(0);
  });
}

module.exports = SignalingServer;

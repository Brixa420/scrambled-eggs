import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { AICrypto } from './encryption';

const PORT = 8080;

// Simple in-memory store for demonstration
const clients = new Set();

// Create HTTP server
const server = createServer();
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  console.log('New client connected');
  clients.add(ws);

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message.toString());
      console.log('Received:', data);
      
      // Echo the message back to all clients
      clients.forEach(client => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'message',
            data: `Echo: ${data.message}`,
            timestamp: new Date().toISOString()
          }));
        }
      });
    } catch (error) {
      console.error('Error handling message:', error);
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
    clients.delete(ws);
  });
});

// Start the server
server.listen(PORT, () => {
  console.log(`WebSocket server running on ws://localhost:${PORT}`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  wss.close(() => {
    server.close(() => {
      console.log('Server stopped');
      process.exit(0);
    });
  });
});

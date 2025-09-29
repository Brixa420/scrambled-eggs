import WebSocket from 'ws';
import { AICrypto } from './encryption';

const WS_URL = 'ws://localhost:8080';

class P2PClient {
  private ws: WebSocket | null = null;
  private messageHandlers: Map<string, (data: any) => void> = new Map();
  private messageQueue: string[] = [];
  private isConnected: boolean = false;

  constructor() {
    this.connect();
  }

  private connect() {
    this.ws = new WebSocket(WS_URL);

    this.ws.on('open', () => {
      console.log('Connected to server');
      this.isConnected = true;
      
      // Process any queued messages
      this.messageQueue.forEach(message => this.send(message));
      this.messageQueue = [];
    });

    this.ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        console.log('Received message:', message);
        
        // Trigger any registered handlers
        if (message.type && this.messageHandlers.has(message.type)) {
          this.messageHandlers.get(message.type)!(message.data);
        }
      } catch (error) {
        console.error('Error processing message:', error);
      }
    });

    this.ws.on('close', () => {
      console.log('Disconnected from server');
      this.isConnected = false;
      
      // Attempt to reconnect after a delay
      setTimeout(() => this.connect(), 3000);
    });

    this.ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
  }

  send(message: string) {
    if (!this.isConnected || !this.ws) {
      console.log('Queueing message (not connected):', message);
      this.messageQueue.push(message);
      return;
    }

    try {
      this.ws.send(JSON.stringify({
        type: 'message',
        data: message,
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      console.error('Error sending message:', error);
    }
  }

  onMessage(type: string, handler: (data: any) => void) {
    this.messageHandlers.set(type, handler);
    return () => this.messageHandlers.delete(type);
  }

  close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Example usage
async function test() {
  // Start server in the background
  if (process.argv.includes('--server')) {
    console.log('Starting WebSocket server...');
    await import('./server');
    return;
  }

  // Start client
  console.log('Starting WebSocket client...');
  const client = new P2PClient();

  // Handle incoming messages
  client.onMessage('message', (data) => {
    console.log('Received response:', data);
  });

  // Send a test message
  setInterval(() => {
    client.send(`Hello from client at ${new Date().toISOString()}`);
  }, 3000);

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('Shutting down client...');
    client.close();
    process.exit(0);
  });
}

test().catch(console.error);

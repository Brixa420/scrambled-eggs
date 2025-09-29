import { createLibp2p, Libp2p } from 'libp2p';
import { webRTC } from '@libp2p/webrtc'
import { noise } from '@chainsafe/libp2p-noise'
import { mplex } from '@libp2p/mplex'
import { kadDHT } from '@libp2p/kad-dht'
import { multiaddr } from '@multiformats/multiaddr'
import { peerIdFromString } from '@libp2p/peer-id'

interface P2PNodeOptions {
  listenAddresses?: string[];
  bootstrapPeers?: string[];
}

export class P2PNode {
  private node: Libp2p | null = null;
  private peerId: string = '';
  private connections: Set<string> = new Set();
  private messageHandlers: Map<string, (data: any) => void> = new Map();

  constructor() {
    this.initializeNode();
  }

  private async initializeNode() {
    const node = await createLibp2p({
      addresses: {
        listen: ['/ip4/0.0.0.0/tcp/0']
      },
      transports: [webRTC()],
      connectionEncryption: [noise()],
      streamMuxers: [mplex()],
      dht: kadDHT(),
      peerDiscovery: [
        // Auto-discover peers using mDNS
        async () => {
          const { mdns } = await import('@libp2p/mdns')
          return mdns()
        }
      ]
    });

    this.node = node;
    this.peerId = node.peerId.toString();

    node.addEventListener('peer:discovery', (evt) => {
      const peerId = evt.detail.id.toString();
      console.log(`Discovered peer: ${peerId}`);
      this.connectToPeer(peerId);
    });

    node.connectionManager.addEventListener('peer:connect', (evt) => {
      const peerId = evt.detail.remotePeer.toString();
      console.log(`Connected to peer: ${peerId}`);
      this.connections.add(peerId);
    });

    node.connectionManager.addEventListener('peer:disconnect', (evt) => {
      const peerId = evt.detail.remotePeer.toString();
      console.log(`Disconnected from peer: ${peerId}`);
      this.connections.delete(peerId);
    });

    // Handle incoming messages
    node.handle('/scrambled-eggs/1.0.0', async ({ stream }) => {
      const data = [];
      for await (const chunk of stream.source) {
        data.push(chunk);
      }
      const message = JSON.parse(Buffer.concat(data).toString());
      this.handleIncomingMessage(message);
    });

    await node.start();
    console.log('P2P Node started with ID:', this.peerId);
  }

  private handleIncomingMessage(message: any) {
    const { type, data } = message;
    const handler = this.messageHandlers.get(type);
    if (handler) {
      handler(data);
    }
  }

  async connectToPeer(peerId: string) {
    if (!this.node) return;
    
    try {
      await this.node.dial(peerIdFromString(peerId));
      console.log(`Successfully connected to ${peerId}`);
    } catch (error) {
      console.error(`Failed to connect to ${peerId}:`, error);
    }
  }

  async sendMessage(peerId: string, type: string, data: any) {
    if (!this.node) return false;

    try {
      const peer = peerIdFromString(peerId);
      const stream = await this.node.dialProtocol(peer, '/scrambled-eggs/1.0.0');
      
      const message = JSON.stringify({ type, data });
      const source = [Buffer.from(message)];
      
      await pipe(
        source,
        stream.sink
      );
      
      return true;
    } catch (error) {
      console.error('Failed to send message:', error);
      return false;
    }
  }

  onMessage(type: string, handler: (data: any) => void) {
    this.messageHandlers.set(type, handler);
    return () => this.messageHandlers.delete(type);
  }

  getPeerId(): string {
    return this.peerId;
  }

  getConnectedPeers(): string[] {
    return Array.from(this.connections);
  }

  async stop() {
    if (this.node) {
      await this.node.stop();
      this.node = null;
    }
  }
}

// Helper function for stream piping
async function* pipe(source: any) {
  for await (const chunk of source) {
    yield new Uint8Array(chunk);
  }
}

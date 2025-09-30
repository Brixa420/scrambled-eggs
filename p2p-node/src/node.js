import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import { noise } from '@chainsafe/libp2p-noise';
import { mplex } from '@libp2p/mplex';
import { kadDHT } from '@libp2p/kad-dht';
import { bootstrap } from '@libp2p/bootstrap';
import { multiaddr } from '@multiformats/multiaddr';

// For debugging
const debug = {
  error: console.error,
  log: console.log,
  warn: console.warn
};

export class BrixaNode {
  constructor(config = {}) {
    // Default configuration
    this.config = {
      // Listen on WebSocket transport
      listen: ['/ip4/0.0.0.0/tcp/0/ws'],
      
      // Enable DHT for peer discovery
      dht: true,
      
      // Bootstrap nodes for peer discovery
      bootstrap: [
        // IPFS public bootstrap nodes (WebSocket)
        '/dns4/ipfs-bootstrap-0.bootstrap.libp2p.io/tcp/443/wss/ipfs/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN',
        '/dns4/ipfs-bootstrap-1.bootstrap.libp2p.io/tcp/443/wss/ipfs/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa',
        '/dns4/ipfs-bootstrap-2.bootstrap.libp2p.io/tcp/443/wss/ipfs/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb',
        '/dns4/ipfs-bootstrap-3.bootstrap.libp2p.io/tcp/443/wss/ipfs/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt',
      ],
      
      // Merge with user config
      ...config
    };
    
    this.node = null;
    this.peers = new Set();
    
    // Bind methods
    this.start = this.start.bind(this);
    this.stop = this.stop.bind(this);
    this.connectToPeer = this.connectToPeer.bind(this);
    this.getPeers = this.getPeers.bind(this);
  }

  async start() {
    try {
      debug.log('🚀 Starting Brixa P2P Node...');
      
      // Create a simple libp2p node with WebSocket transport
      const nodeConfig = {
        addresses: {
          listen: this.config.listen
        },
        transports: [
          webSockets()
        ],
        connectionEncryption: [
          noise()
        ],
        streamMuxers: [
          mplex()
        ],
        peerDiscovery: [
          bootstrap({
            list: this.config.bootstrap,
            timeout: 1000, // 1 second timeout
            tagName: 'bootstrap'
          })
        ]
      };
      
      // Add DHT if enabled
      if (this.config.dht) {
        nodeConfig.dht = kadDHT({
          kBucketSize: 20,
          clientMode: false
        });
      }
      
      debug.log('Creating libp2p node with config:', JSON.stringify({
        ...nodeConfig,
        // Don't log the full bootstrap list
        peerDiscovery: [{
          ...nodeConfig.peerDiscovery[0],
          options: {
            ...nodeConfig.peerDiscovery[0].options,
            list: ['...'] // Don't log the full bootstrap list
          }
        }]
      }, null, 2));
      
      // Create the libp2p node
      this.node = await createLibp2p(nodeConfig);
      
      // Set up event handlers
      this.node.addEventListener('peer:connect', (evt) => {
        const peerId = evt.detail.remotePeer.toString();
        this.peers.add(peerId);
        debug.log(`✅ Connected to peer: ${peerId}`);
        debug.log(`🌐 Total peers: ${this.peers.size}`);
      });
      
      this.node.addEventListener('peer:disconnect', (evt) => {
        const peerId = evt.detail.remotePeer.toString();
        this.peers.delete(peerId);
        debug.log(`❌ Disconnected from peer: ${peerId}`);
        debug.log(`🌐 Remaining peers: ${this.peers.size}`);
      });
      
      // Start the node
      await this.node.start();
      
      // Get and log all listening addresses
      const addrs = this.node.getMultiaddrs();
      debug.log('\n🌐 Node started with ID:', this.node.peerId.toString());
      debug.log('📡 Listening on addresses:');
      addrs.forEach(addr => debug.log(`  - ${addr.toString()}/p2p/${this.node.peerId.toString()}`));
      
      // Try to connect to bootstrap nodes if DHT is enabled
      if (this.config.dht) {
        debug.log('\n🔍 Discovering peers via DHT...');
        
        // Start the DHT
        await this.node.dht.start();
        
        // Try to connect to bootstrap nodes
        for (const addr of this.config.bootstrap) {
          try {
            const ma = multiaddr(addr);
            debug.log(`Attempting to connect to bootstrap node: ${ma.toString()}`);
            await this.node.dial(ma);
          } catch (error) {
            debug.warn(`⚠️  Failed to connect to bootstrap node: ${addr}`, error.message);
          }
        }
      }
      
      return this; // Return the node instance for method chaining
    } catch (error) {
      console.error('Failed to start BrixaNode:', error);
      await this.stop().catch(err => console.error('Error during cleanup:', err));
      throw error; // Re-throw the error after cleanup
    }
  }

  async stop() {
    debug.log('🛑 Stopping BrixaNode...');
    const stopPromises = [];
    
    if (this.node) {
      debug.log('Stopping libp2p node...');
      stopPromises.push(
        (async () => {
          try {
            // Stop DHT if it was started
            if (this.node.dht) {
              await this.node.dht.stop();
            }
            await this.node.stop();
            debug.log('✅ libp2p node stopped');
          } catch (err) {
            debug.error('Error stopping libp2p node:', err);
            throw err;
          }
        })()
      );
    }
    
    // Wait for all stop operations to complete
    try {
      await Promise.allSettled(stopPromises);
      debug.log('✅ BrixaNode stopped successfully');
    } catch (error) {
      debug.error('Error during BrixaNode shutdown:', error);
      throw error;
    } finally {
      // Clear references
      this.node = null;
      this.peers.clear();
    }
  }

  async addVideo(content) {
    if (!this.ipfs) {
      throw new Error('IPFS node not started');
    }
    try {
      const { cid } = await this.ipfs.add({
        content: content,
        pin: true
      });
      console.log('Added video with CID:', cid.toString());
      return cid.toString();
    } catch (error) {
      console.error('Error adding video to IPFS:', error);
      throw error;
    }
  }

  async getVideo(cid) {
    if (!this.ipfs) {
      throw new Error('IPFS node not started');
    }
    try {
      const chunks = [];
      for await (const chunk of this.ipfs.cat(cid)) {
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    } catch (error) {
      console.error(`Error retrieving video with CID ${cid}:`, error);
      throw error;
    }
  }

  async connectToPeer(ma) {
    if (!this.node) {
      throw new Error('Libp2p node not started');
    }
    
    try {
      const maObj = multiaddr(ma);
      const peerId = maObj.getPeerId();
      
      if (!peerId) {
        throw new Error('No peer ID found in multiaddress');
      }
      
      debug.log(`🔗 Attempting to connect to peer: ${ma}`);
      
      // Check if we're already connected to this peer
      if (this.peers.has(peerId)) {
        debug.log(`ℹ️  Already connected to peer: ${peerId}`);
        return true;
      }
      
      // Try to connect to the peer
      await this.node.dial(maObj);
      
      // The peer:connect event handler will add the peer to this.peers
      debug.log(`✅ Successfully connected to peer: ${peerId}`);
      return true;
      
    } catch (error) {
      debug.error(`❌ Failed to connect to peer ${ma}:`, error.message);
      throw error; // Re-throw to allow caller to handle the error
    }
  }

  async getPeers() {
    if (!this.node) {
      throw new Error('Libp2p node not started');
    }
    
    // Return both the peer IDs we're tracking and the ones from libp2p
    const connectedPeers = Array.from(this.node.getPeers() || []);
    const trackedPeers = Array.from(this.peers);
    
    // Combine and dedupe
    const allPeers = [...new Set([...connectedPeers, ...trackedPeers])];
    
    debug.log(`🌐 Found ${allPeers.length} peers (${connectedPeers.length} connected, ${trackedPeers.length} tracked)`);
    
    return allPeers;
  }
}

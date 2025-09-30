import { BrixaNode } from '../src/node.js';
import { multiaddr } from '@multiformats/multiaddr';

describe('BrixaNode', () => {
  let node1, node2;

  beforeEach(async () => {
    // Create two nodes for testing
    node1 = new BrixaNode({
      listen: ['/ip4/0.0.0.0/tcp/0/ws'],
      dht: false // Disable DHT for faster tests
    });

    node2 = new BrixaNode({
      listen: ['/ip4/0.0.0.0/tcp/0/ws'],
      dht: false
    });

    await Promise.all([node1.start(), node2.start()]);
  }, 30000); // Increase timeout for node startup

  afterEach(async () => {
    await Promise.all([
      node1?.stop().catch(console.error),
      node2?.stop().catch(console.error)
    ]);
  });

  it('should start and stop successfully', async () => {
    expect(node1.node).toBeDefined();
    expect(node1.ipfs).toBeDefined();
    expect(node1.node.isStarted()).toBe(true);
  }, 10000);

  it('should connect to another node', async () => {
    const addr = node2.node.getMultiaddrs()[0];
    await node1.connectToPeer(addr);
    
    // Check if nodes are connected
    const connected = node1.node.getConnections()
      .some(conn => conn.remotePeer.toString() === node2.node.peerId.toString());
    
    expect(connected).toBe(true);
  }, 15000);

  it('should store and retrieve content', async () => {
    const testContent = 'Hello, Brixa!';
    const cid = await node1.storeContent(testContent);
    expect(cid).toBeDefined();
    
    const retrieved = await node1.retrieveContent(cid);
    expect(Buffer.from(retrieved).toString()).toBe(testContent);
  }, 20000);
});

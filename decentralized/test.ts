import { P2PNode } from './src/p2p.js';
import { AICrypto } from './src/encryption.js';

async function test() {
  console.log('Starting test...');
  
  // Create two nodes
  console.log('Creating P2P nodes...');
  const node1 = new P2PNode();
  const node2 = new P2PNode();

  // Wait for nodes to initialize
  console.log('Waiting for nodes to initialize...');
  await new Promise(resolve => setTimeout(resolve, 2000));

  // Test encryption
  console.log('Testing encryption...');
  const key = await AICrypto.generateKey();
  const encrypted = await AICrypto.encrypt('Hello, Scrambled Eggs!', key);
  const decrypted = await AICrypto.decrypt(encrypted, key);
  console.log('Decrypted:', decrypted.toString());

  // Test messaging
  console.log('Testing messaging...');
  node1.onMessage('greeting', (data) => {
    console.log('Node 1 received:', data);
  });

  // Connect nodes
  console.log('Connecting nodes...');
  console.log('Node 1 ID:', node1.getPeerId());
  console.log('Node 2 ID:', node2.getPeerId());
  
  // In a real scenario, you would use a discovery service or manual connection
  // For testing, we'll simulate a connection
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Send a message (this will fail until we have proper peer discovery)
  console.log('Sending test message...');
  try {
    await node1.sendMessage(node2.getPeerId(), 'greeting', { message: 'Hello from Node 1!' });
  } catch (error) {
    console.log('Message send failed (expected until peer discovery is implemented):', error.message);
  }

  // Clean up
  setTimeout(async () => {
    console.log('Cleaning up...');
    await node1.stop();
    await node2.stop();
    console.log('Test complete!');
    process.exit(0);
  }, 5000);
}

test().catch(console.error);

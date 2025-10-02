import { BrixaNode } from './node.js';
import readline from 'readline';
import { multiaddr } from '@multiformats/multiaddr';

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: '🌐 BrixaNode> '
});

// Create a new BrixaNode instance
const brixaNode = new BrixaNode({
  listen: [
    '/ip4/0.0.0.0/tcp/0/ws',
    '/ip4/127.0.0.1/tcp/0/ws'
  ],
  dht: true
});

// Track if the node is running
let isRunning = false;

// Handle command line arguments
const command = process.argv[2];
const arg = process.argv[3];

async function startNode() {
  if (isRunning) {
    console.log('ℹ️  Node is already running');
    promptUser();
    return;
  }

  try {
    console.log('🚀 Starting Brixa P2P Node...');
    await brixaNode.start();
    isRunning = true;
    
    // Show node info
    const addrs = brixaNode.node.getMultiaddrs();
    console.log('\n✅ Node started successfully!');
    console.log('🔑 Peer ID:', brixaNode.node.peerId.toString());
    console.log('📡 Listening on addresses:');
    addrs.forEach((addr, i) => console.log(`  ${i + 1}. ${addr.toString()}`));
    
    // Start the CLI
    promptUser();
  } catch (error) {
    console.error('❌ Failed to start BrixaNode:', error.message);
    process.exit(1);
  }
}

async function promptUser() {
  rl.question('', async (input) => {
    const [command, ...args] = input.trim().split(' ');
    
    try {
      if (!command) {
        // No command, just show prompt again
        promptUser();
        return;
      }
      
      switch (command.toLowerCase()) {
        case '':
        case 'help':
          showHelp();
          break;
          
        case 'peers':
          const peers = await brixaNode.getPeers();
          if (peers.length === 0) {
            console.log('\nNo connected peers. Try discovering peers with `discover` command.');
          } else {
            console.log(`\n📡 Connected peers (${peers.length}):`);
            peers.forEach((peer, i) => console.log(`  ${i + 1}. ${peer}`));
          }
          break;
          
        case 'connect':
          if (!args[0]) {
            console.log('\n❌ Please provide a multiaddress to connect to');
            console.log('Example: connect /ip4/1.2.3.4/tcp/1234/ws/p2p/QmPeerId');
            break;
          }
          try {
            console.log(`\n🔗 Attempting to connect to ${args[0]}...`);
            await brixaNode.connectToPeer(args[0]);
            console.log('✅ Successfully connected to peer');
          } catch (error) {
            console.error('❌ Failed to connect to peer:', error.message);
          }
          break;
          
        case 'discover':
          console.log('\n🔍 Discovering peers via DHT...');
          try {
            // This will trigger the DHT to find peers
            await brixaNode.node.dht.findPeer(brixaNode.node.peerId);
            console.log('✅ Discovery complete. Check peers with `peers` command.');
          } catch (error) {
            console.error('❌ Error discovering peers:', error.message);
          }
          break;
          
        case 'info':
          if (!brixaNode.node) {
            console.log('\n❌ Node is not running');
            break;
          }
          const peerId = brixaNode.node.peerId.toString();
          const addrs = brixaNode.node.getMultiaddrs().map(addr => addr.toString());
          const protocolCount = brixaNode.node.registrar.getProtocols().length;
          
          console.log('\n📊 Node Information:');
          console.log(`  Peer ID: ${peerId}`);
          console.log(`  Addresses (${addrs.length}):`);
          addrs.forEach((addr, i) => console.log(`    ${i + 1}. ${addr}`));
          console.log(`  Protocols: ${protocolCount} registered`);
          console.log(`  Status: ${isRunning ? '✅ Running' : '❌ Stopped'}`);
          break;
          
        case 'stop':
          console.log('\n🛑 Stopping node...');
          await brixaNode.stop();
          isRunning = false;
          console.log('✅ Node stopped successfully');
          break;
          
        case 'exit':
        case 'quit':
          shutdown();
          return; // Don't call promptUser() after this
          
        default:
          console.log(`\n❌ Unknown command: ${command}`);
          console.log('Type `help` to see available commands');
      }
    } catch (error) {
      console.error('\n❌ Error:', error.message);
    }
    
    // Show the prompt again
    if (isRunning) {
      promptUser();
    }
  });
}

function showHelp() {
  console.log('\n🌐 BrixaNode - P2P Video Streaming Node');
  console.log('===================================');
  console.log('Available commands:');
  console.log('  help          - Show this help message');
  console.log('  info          - Show node information');
  console.log('  peers         - List connected peers');
  console.log('  discover      - Discover peers via DHT');
  console.log('  connect <ma>  - Connect to a peer using multiaddress');
  console.log('  stop          - Stop the node');
  console.log('  exit/quit     - Shutdown the node and exit');
  console.log('===================================');
}

// Handle process termination
async function shutdown() {
  console.log('\n🛑 Shutting down BrixaNode...');
  try {
    if (brixaNode && isRunning) {
      await brixaNode.stop();
    }
    rl.close();
    console.log('👋 Goodbye!');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
}

// Handle process signals
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start the node
console.clear();
console.log('🌐 BrixaNode - P2P Video Streaming Node');
console.log('===================================');
startNode();
    await brixaNode.stop();
    rl.close();
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start the node
startNode();

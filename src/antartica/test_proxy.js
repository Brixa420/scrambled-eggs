import http from 'http';
import net from 'net';
import AntarcticaProxy from './proxy.js';

// Test server
const testServer = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    yourIp: req.headers['x-forwarded-for'],
    country: req.headers['x-geoip-country'],
    message: 'Hello from the test server!'
  }));
});

testServer.on('connect', (req, clientSocket, head) => {
  const [host, port] = req.url.split(':');
  const serverSocket = net.connect(port || 443, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });
  
  serverSocket.on('error', () => clientSocket.destroy());
  clientSocket.on('error', () => serverSocket.destroy());
});

// Start test server
const TEST_PORT = 8080;
testServer.listen(TEST_PORT, 'localhost', () => {
  console.log(`Test server running at http://localhost:${TEST_PORT}`);
  
  // Start Antarctica proxy
  const PROXY_PORT = 3000;
  const proxy = new AntarcticaProxy(PROXY_PORT);
  
  console.log(`\nTesting Antarctica Proxy...`);
  console.log(`1. Configure your browser/application to use proxy: localhost:${PROXY_PORT}`);
  console.log(`2. Visit http://localhost:${TEST_PORT} to test HTTP`);
  console.log(`3. Check the response headers to see Antarctica IP and country code`);
  
  // Test the proxy automatically
  setTimeout(() => {
    console.log('\nRunning automated test...');
    
    const options = {
      hostname: 'localhost',
      port: PROXY_PORT,
      path: `http://localhost:${TEST_PORT}`,
      method: 'GET',
      headers: {
        'Host': `localhost:${TEST_PORT}`
      }
    };
    
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          console.log('\nTest Results:');
          console.log('-'.repeat(50));
          console.log('Your IP (should be Antarctica IP):', result.yourIp);
          console.log('Country (should be AQ):', result.country);
          console.log('-'.repeat(50));
          console.log('\nProxy Stats:', proxy.getStats());
          console.log('\n✅ Test completed!');
          process.exit(0);
        } catch (e) {
          console.error('Error parsing response:', e);
          process.exit(1);
        }
      });
    });
    
    req.on('error', (e) => {
      console.error('Test request failed:', e);
      process.exit(1);
    });
    
    req.end();
  }, 1000);
});

// Handle server errors
testServer.on('error', (e) => {
  console.error('Test server error:', e);
  process.exit(1);
});

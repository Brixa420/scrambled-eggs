import net from 'net';
import http, { createServer } from 'http';
import { createHmac } from 'crypto';
import TorMiddleware from './tor_middleware.js';
import { TrafficEncryptor } from './crypto.js';
import SecurityManager from './security.js';
import AdminAPI from './admin_api.js';
import { createSecureServer, setupIPWhitelist } from './https_support.js';

class AntarcticaProxy {
  constructor(port = 3000, options = {}) {
    const {
      password = 'default-password-change-me',
      requireAuth = false,
      adminUsername = 'admin',
      adminPassword = 'change-me-please',
      rateLimit = 100,
      enableHttps = true,
      enableAdminApi = true,
      adminPort = 3001,
      ipWhitelist = []
    } = options;
    this.port = port;
    this.clients = new Map();
    this.server = null;
    this.encryptor = new TrafficEncryptor(password);
    this.encryptionEnabled = true;
    
    // Initialize Tor middleware if enabled
    if (enableTor) {
      this.tor = new TorMiddleware(this, {
        torOptions: {
          socksPort: 9050 + Math.floor(Math.random() * 100), // Random port to avoid conflicts
          ...torOptions
        }
      });
    }
    
    // Initialize security manager
    this.security = new SecurityManager();
    this.requireAuth = requireAuth;
    
    // Setup IP whitelist
    this.ipWhitelist = setupIPWhitelist(this);
    ipWhitelist.forEach(ip => this.ipWhitelist.add(ip));
    
    // Initialize admin API if enabled
    if (enableAdminApi) {
      this.adminApi = new AdminAPI(this, { port: adminPort });
      this.adminApi.start();
    }
    
    // Add default admin user if auth is required
    if (this.requireAuth) {
      this.security.addUser(adminUsername, adminPassword, {
        isAdmin: true,
        rateLimit: rateLimit * 2 // Admins get higher rate limits
      });
    }
    
    // Antarctica IP ranges (example - to be replaced with actual Antarctic IPs)
    this.antarcticaIps = [
      '45.56.0.0/16',  // Example - replace with actual Antarctic IPs
      '2001:67c:2e8::/48'  // Example IPv6 range
    ];
    
    this.start();
  }
  
  start() {
    const requestHandler = (req, res) => {
      // Check IP whitelist
      const clientIP = req.socket.remoteAddress.replace(/^::ffff:/, '');
      if (!this.ipWhitelist.check(clientIP)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'IP not whitelisted' }));
      }
      
      // Handle the request
      if (req.method === 'CONNECT') {
        this.handleConnect(req, req.socket, Buffer.alloc(0));
      } else {
        this.handleRequest(req, res);
      }
    };

    // Create secure or regular server based on configuration
    if (this.options.enableHttps) {
      this.server = createSecureServer({
        forceHttps: true,
        httpPort: 80,
        httpsPort: this.port
      }, requestHandler);
    } else {
      this.server = createServer(requestHandler);
      this.server.listen(this.port, () => {
        console.log(`HTTP Proxy Server running on port ${this.port}`);
      });
    }
    
    this.server.on('error', (error) => {
      console.error('Server error:', error);
    });
  }
  
  async handleRequest(clientReq, clientRes) {
    const clientIP = clientReq.socket.remoteAddress;
    
    // Handle Tor requests
    if (this.tor && clientReq.url.includes('.onion')) {
      return this.tor.handleRequest(clientReq, clientRes, clientReq.url);
    }
    
    // Check rate limiting
    const rateLimit = this.security.checkRateLimit(clientIP);
    if (!rateLimit.allowed) {
      clientRes.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': Math.ceil((rateLimit.reset - Date.now()) / 1000)
      });
      return clientRes.end(JSON.stringify({
        error: 'Too many requests',
        retryAfter: Math.ceil((rateLimit.reset - Date.now()) / 1000)
      }));
    }
    
    // Check authentication if required
    if (this.requireAuth) {
      const auth = clientReq.headers['proxy-authorization'];
      const user = this.security.authenticate(auth);
      
      if (!user) {
        this.security.logSecurityEvent({
          type: 'auth_failed',
          ip: clientIP,
          details: { path: clientReq.url }
        });
        
        clientRes.writeHead(407, {
          'Content-Type': 'application/json',
          'Proxy-Authenticate': 'Basic realm="Antarctica Proxy"'
        });
        return clientRes.end(JSON.stringify({
          error: 'Authentication required',
          code: 'PROXY_AUTH_REQUIRED'
        }));
      }
      
      // Log successful authentication
      this.security.logSecurityEvent({
        type: 'auth_success',
        ip: clientIP,
        details: { user: user.username }
      });
    }
    // Handle HTTP requests
    const options = {
      hostname: clientReq.headers.host.split(':')[0],
      port: clientReq.headers.host.split(':')[1] || 80,
      path: clientReq.url,
      method: clientReq.method,
      headers: { ...clientReq.headers }
    };

    // Remove hop-by-hop headers
    const hopByHopHeaders = [
      'connection', 'keep-alive', 'proxy-authenticate',
      'proxy-authorization', 'te', 'trailers', 'upgrade'
    ];
    hopByHopHeaders.forEach(header => delete options.headers[header]);
    
    // Add Antarctica geolocation headers
    options.headers['x-forwarded-for'] = this.getAntarcticaIP();
    options.headers['x-geoip-country'] = 'AQ'; // Antarctica country code
    
    // Encrypt the request if enabled
    if (this.encryptionEnabled) {
      try {
        const requestData = JSON.stringify({
          method: options.method,
          url: options.path,
          headers: options.headers,
          body: await this.readRequestBody(clientReq)
        });
        
        const encryptedRequest = await this.encryptor.encrypt(Buffer.from(requestData));
        options.headers['x-encrypted-request'] = encryptedRequest.toString('base64');
      } catch (error) {
        console.error('Request encryption failed:', error);
        clientRes.writeHead(500, { 'Content-Type': 'application/json' });
        return clientRes.end(JSON.stringify({ error: 'Failed to encrypt request' }));
      }
    }
    
    const proxyReq = http.request(options, (proxyRes) => {
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes);
    });
    
    clientReq.pipe(proxyReq);
  }
  
  async handleConnect(clientReq, clientSock, head) {
    // Handle HTTPS/WebSocket connections
    const [host, port] = clientReq.url.split(':');
    const proxySock = net.connect(port || 443, host, async () => {
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      
      // Add Antarctica IP to the connection
      if (proxySock.remoteAddress) {
        this.clients.set(proxySock.remoteAddress, {
          connectedAt: new Date(),
          bytesTransferred: 0
        });
      }
      
      proxySock.write(head);
      clientSock.pipe(proxySock);
      proxySock.pipe(clientSock);
    });
    
    proxySock.on('error', (e) => {
      console.error('Proxy socket error:', e);
      clientSock.end();
    });
  }
  
  getAntarcticaIP() {
    // Return a random IP from Antarctica ranges
    // In production, this would use actual Antarctic IPs
    const randomOctet = () => Math.floor(Math.random() * 255);
    return `45.56.${randomOctet()}.${randomOctet()}`;
  }
  
  async readRequestBody(req) {
    return new Promise((resolve) => {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  getStats() {
    return {
      activeConnections: this.clients.size,
      totalConnections: Array.from(this.clients.values()).length,
      bytesTransferred: Array.from(this.clients.values())
        .reduce((sum, client) => sum + client.bytesTransferred, 0),
      encryption: this.encryptionEnabled ? 'enabled' : 'disabled',
      security: {
        authentication: this.requireAuth ? 'required' : 'disabled',
        blockedIPs: this.security.blockedIPs.size,
        activeRateLimits: this.security.rateLimits.size,
        whitelistedIPs: this.ipWhitelist.list().length,
        https: this.options.enableHttps ? 'enabled' : 'disabled',
        adminApi: this.adminApi ? 'enabled' : 'disabled'
      }
    };
  }
  
  setEncryption(enabled) {
    this.encryptionEnabled = enabled;
    return { encryption: this.encryptionEnabled ? 'enabled' : 'disabled' };
  }
}

// Start the proxy if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const proxy = new AntarcticaProxy(3000);
  
  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('Shutting down Antarctica proxy...');
    proxy.server.close(() => process.exit(0));
  });
}

export default AntarcticaProxy;

import { SocksProxyAgent } from 'socks-proxy-agent';
import https from 'https';
import http from 'http';
import url from 'url';
import TorManager from './tor.js';

class TorMiddleware {
  constructor(proxy, options = {}) {
    this.proxy = proxy;
    this.tor = new TorManager(options.torOptions);
    this.options = {
      rotateIdentity: true,
      rotationInterval: 10 * 60 * 1000, // 10 minutes
      maxRetries: 3,
      retryDelay: 1000,
      ...options
    };
    
    this.rotationTimer = null;
    this.isRotating = false;
    this.agentCache = new Map();
  }

  async start() {
    try {
      await this.tor.start();
      this.setupRotation();
      return true;
    } catch (error) {
      console.error('Failed to start Tor middleware:', error);
      throw error;
    }
  }

  async stop() {
    this.clearRotation();
    await this.tor.stop();
  }

  setupRotation() {
    if (this.options.rotateIdentity && this.options.rotationInterval > 0) {
      this.rotationTimer = setInterval(
        () => this.rotateIdentity(),
        this.options.rotationInterval
      );
    }
  }

  clearRotation() {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
    }
  }

  async rotateIdentity() {
    if (this.isRotating) return;
    
    this.isRotating = true;
    try {
      console.log('Rotating Tor identity...');
      await this.tor.newIdentity();
      console.log('New Tor identity:', await this.tor.getCurrentIp());
      
      // Clear agent cache to ensure new connections use the new identity
      this.agentCache.clear();
      
      return true;
    } catch (error) {
      console.error('Failed to rotate Tor identity:', error);
      throw error;
    } finally {
      this.isRotating = false;
    }
  }

  getAgent(targetUrl) {
    const parsedUrl = typeof targetUrl === 'string' ? new URL(targetUrl) : targetUrl;
    const protocol = parsedUrl.protocol.replace(':', '');
    const cacheKey = `${protocol}:${this.tor.circuitId || 'default'}`;
    
    // Return cached agent if available
    if (this.agentCache.has(cacheKey)) {
      return this.agentCache.get(cacheKey);
    }
    
    // Create new agent
    const agent = this.createAgent(protocol);
    this.agentCache.set(cacheKey, agent);
    
    return agent;
  }

  createAgent(protocol) {
    const proxyUrl = `socks5h://127.0.0.1:${this.tor.options.socksPort}`;
    const agentOptions = {
      keepAlive: true,
      keepAliveMsecs: 10000,
      maxSockets: 100,
      timeout: 30000
    };
    
    const agent = new SocksProxyAgent(proxyUrl, agentOptions);
    
    // Handle agent errors
    agent.on('error', (error) => {
      console.error('Tor agent error:', error);
      this.agentCache.clear(); // Clear cache on error
    });
    
    return agent;
  }

  async handleRequest(clientReq, clientRes, targetUrl) {
    const parsedUrl = typeof targetUrl === 'string' ? new URL(targetUrl) : targetUrl;
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    // Get Tor SOCKS agent
    const agent = this.getAgent(parsedUrl);
    
    // Prepare request options
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + (parsedUrl.search || ''),
      method: clientReq.method,
      headers: {
        ...clientReq.headers,
        'x-tor-circuit': this.tor.circuitId || 'unknown',
        'x-tor-identity': this.tor.identity || 'unknown'
      },
      agent
    };
    
    // Track retry attempts
    let attempts = 0;
    
    const makeRequest = async () => {
      attempts++;
      
      try {
        return await new Promise((resolve, reject) => {
          const proxyReq = protocol.request(options, (proxyRes) => {
            // Forward status code and headers
            clientRes.writeHead(
              proxyRes.statusCode || 500,
              proxyRes.headers
            );
            
            // Stream the response
            proxyRes.pipe(clientRes);
            
            proxyRes.on('end', () => {
              resolve(true);
            });
            
            proxyRes.on('error', (error) => {
              reject(error);
            });
          });
          
          // Handle request errors
          proxyReq.on('error', (error) => {
            // If we get a connection error, try rotating identity
            if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
              this.rotateIdentity();
            }
            reject(error);
          });
          
          // Set timeout
          proxyReq.setTimeout(30000, () => {
            proxyReq.destroy(new Error('Request timeout'));
          });
          
          // Forward the request body
          clientReq.pipe(proxyReq);
        });
      } catch (error) {
        // If we have retries left and the error is retryable
        if (attempts < this.options.maxRetries && this.isRetryableError(error)) {
          console.log(`Retrying request (${attempts}/${this.options.maxRetries})...`);
          await new Promise(resolve => setTimeout(resolve, this.options.retryDelay * attempts));
          return makeRequest();
        }
        throw error;
      }
    };
    
    try {
      return await makeRequest();
    } catch (error) {
      console.error('Tor request failed:', error);
      
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          error: 'Tor request failed',
          message: error.message,
          code: error.code
        }));
      } else {
        clientRes.destroy();
      }
      
      // If the error is severe, rotate identity
      if (this.isSevereError(error)) {
        this.rotateIdentity();
      }
    }
  }
  
  isRetryableError(error) {
    // List of retryable error codes
    const retryableErrors = [
      'ECONNREFUSED',
      'ETIMEDOUT',
      'ESOCKETTIMEDOUT',
      'ECONNRESET',
      'EPIPE',
      'EAI_AGAIN'
    ];
    
    return retryableErrors.includes(error.code);
  }
  
  isSevereError(error) {
    // List of severe errors that warrant an identity rotation
    const severeErrors = [
      'ECONNREFUSED',
      'ETIMEDOUT',
      'EPIPE',
      'ECONNRESET'
    ];
    
    return severeErrors.includes(error.code);
  }
  
  getStatus() {
    return {
      ...this.tor.getStatus(),
      isRotating: this.isRotating,
      options: {
        rotateIdentity: this.options.rotateIdentity,
        rotationInterval: this.options.rotationInterval,
        maxRetries: this.options.maxRetries,
        retryDelay: this.options.retryDelay
      }
    };
  }
}

export default TorMiddleware;

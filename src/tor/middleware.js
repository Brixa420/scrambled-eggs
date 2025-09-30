import { SocksProxyAgent } from 'socks-proxy-agent';
import https from 'https';
import http from 'http';
import url from 'url';
import TorManager from './index.js';

class TorMiddleware {
  constructor(proxy, options = {}) {
    this.proxy = proxy;
    this.torManager = new TorManager(options.torOptions);
    this.rotationInterval = options.rotationInterval || 600000; // 10 minutes
    this.retryAttempts = 3;
    this.retryDelay = 5000; // 5 seconds
    this.agents = new Map();
    this.isStarting = false;
  }

  async start() {
    if (this.isStarting) return;
    this.isStarting = true;
    
    try {
      await this.torManager.start();
      this.setupRotation();
      
      // Add Tor request handler to the proxy
      this.proxy.on('request', this.handleRequest.bind(this));
      
      console.log('Tor middleware started');
      return true;
    } catch (error) {
      console.error('Failed to start Tor middleware:', error);
      throw error;
    } finally {
      this.isStarting = false;
    }
  }

  async stop() {
    this.clearRotation();
    await this.torManager.stop();
    this.agents.clear();
  }

  setupRotation() {
    if (this.rotationIntervalId) {
      clearInterval(this.rotationIntervalId);
    }
    this.rotationIntervalId = setInterval(
      () => this.rotateIdentity(),
      this.rotationInterval
    );
  }

  clearRotation() {
    if (this.rotationIntervalId) {
      clearInterval(this.rotationIntervalId);
      this.rotationIntervalId = null;
    }
  }

  async rotateIdentity() {
    try {
      console.log('Rotating Tor identity...');
      await this.torManager.newIdentity();
      this.agents.clear(); // Clear agent cache to use new identity
      console.log('Tor identity rotated successfully');
    } catch (error) {
      console.error('Failed to rotate Tor identity:', error);
    }
  }

  getAgent(targetUrl) {
    const protocol = new URL(targetUrl).protocol.replace(':', '');
    return this.createAgent(protocol);
  }

  createAgent(protocol) {
    const cacheKey = `${protocol}`;
    
    if (this.agents.has(cacheKey)) {
      return this.agents.get(cacheKey);
    }

    const agentOptions = {
      keepAlive: true,
      keepAliveMsecs: 60000,
      maxSockets: 100,
      maxFreeSockets: 10,
      timeout: 30000,
      proxy: {
        host: '127.0.0.1',
        port: this.torManager.options.socksPort,
        type: 'socks5',
      },
    };

    const Agent = protocol === 'https' ? https.Agent : http.Agent;
    const agent = new Agent(agentOptions);
    
    this.agents.set(cacheKey, agent);
    return agent;
  }

  async handleRequest(clientReq, clientRes, targetUrl) {
    const parsedUrl = url.parse(targetUrl);
    const isOnion = parsedUrl.hostname?.endsWith('.onion');

    if (!isOnion) {
      return false; // Let other middleware handle non-onion requests
    }

    console.log(`Proxying request to Tor hidden service: ${targetUrl}`);
    
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.path || '/',
      method: clientReq.method,
      headers: {
        ...clientReq.headers,
        host: parsedUrl.hostname,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
      },
      agent: this.getAgent(targetUrl),
      rejectUnauthorized: false, // For self-signed certs
    };

    const makeRequest = (attempt = 1) => {
      return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          clientRes.writeHead(res.statusCode || 500, res.headers);
          res.pipe(clientRes);
          resolve();
        });

        req.on('error', async (error) => {
          if (this.isRetryableError(error) && attempt <= this.retryAttempts) {
            console.log(`Retry ${attempt}/${this.retryAttempts} for ${targetUrl}`);
            await new Promise(r => setTimeout(r, this.retryDelay * attempt));
            makeRequest(attempt + 1).then(resolve).catch(reject);
          } else {
            console.error(`Request failed after ${attempt} attempts:`, error);
            clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
            clientRes.end('Tor connection failed');
            reject(error);
          }
        });

        clientReq.pipe(req);
      });
    };

    try {
      await makeRequest();
      return true;
    } catch (error) {
      console.error('Tor request failed:', error);
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end('Tor connection failed');
      }
      return false;
    }
  }

  isRetryableError(error) {
    const retryableErrors = [
      'ECONNRESET',
      'ETIMEDOUT',
      'ECONNREFUSED',
      'ESOCKETTIMEDOUT',
      'EPIPE',
      'EAI_AGAIN'
    ];
    
    return (
      retryableErrors.includes(error.code) ||
      error.message.includes('socket hang up') ||
      error.message.includes('read ECONNRESET')
    );
  }

  isSevereError(error) {
    const severeErrors = [
      'ENOTFOUND',
      'EAI_FAIL',
      'EPROTO',
      'ERR_TLS_CERT_ALTNAME_INVALID',
      'CERT_HAS_EXPIRED'
    ];
    
    return (
      severeErrors.includes(error.code) ||
      error.message.includes('certificate has expired') ||
      error.message.includes('self signed certificate')
    );
  }

  getStatus() {
    return {
      ...this.torManager.getStatus(),
      rotationInterval: this.rotationInterval,
      activeConnections: this.agents.size,
      lastRotation: this.lastRotation
    };
  }
}

export default TorMiddleware;

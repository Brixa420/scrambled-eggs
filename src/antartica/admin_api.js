import { createServer } from 'http';
import { URL } from 'url';
import { createHmac, randomBytes } from 'crypto';
import SecurityMonitor from './monitoring.js';

class AdminAPI {
  constructor(proxy, options = {}) {
    this.proxy = proxy;
    this.port = options.port || 3001;
    this.users = new Map();
    this.server = null;
    this.jwtSecret = options.jwtSecret || randomBytes(32).toString('hex');
    this.monitor = new SecurityMonitor({
      logFile: join(process.cwd(), 'logs', 'admin_api.log')
    });
    this.rateLimits = new Map();
    this.setupRoutes();
  }

  setupRoutes() {
    this.routes = {
      '/api/stats': {
        GET: this.handleGetStats.bind(this)
      },
      '/api/security/block-ip': {
        POST: this.handleBlockIP.bind(this),
        DELETE: this.handleUnblockIP.bind(this)
      },
      '/api/users': {
        GET: this.handleListUsers.bind(this),
        POST: this.handleAddUser.bind(this),
        DELETE: this.handleRemoveUser.bind(this)
      },
      '/api/logs': {
        GET: this.handleGetLogs.bind(this)
      },
      '/api/monitoring': {
        GET: this.handleGetMonitoring.bind(this)
      }
    };
  }

  async handleRequest(req, res) {
    const clientIP = req.socket.remoteAddress.replace(/^::ffff:/, '');
    const startTime = Date.now();
    
    try {
      // Log the request
      await this.monitor.logEvent({
        type: 'api_request',
        method: req.method,
        path: req.url,
        ip: clientIP,
        userAgent: req.headers['user-agent']
      });

      // Check rate limiting
      const rateLimit = this.checkRateLimit(clientIP);
      if (!rateLimit.allowed) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          error: 'Too many requests',
          retryAfter: rateLimit.retryAfter
        }));
      }

      // Authenticate the request
      const auth = await this.authenticateRequest(req);
      if (!auth.authenticated) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unauthorized' }));
      }

      const { pathname, searchParams } = new URL(req.url, `http://${req.headers.host}`);
      const method = req.method;
      
      // Find matching route
      const route = Object.entries(this.routes).find(([path, handlers]) => {
        return path === pathname && handlers[method];
      });

      if (route) {
        const [path, handlers] = route;
        const handler = handlers[method];
        
        try {
        return await route[method](req, res);
          const result = await handler.call(this, { req, res, searchParams });
          if (result) {
            this.sendResponse(res, 200, result);
          }
        } catch (error) {
          console.error('API Error:', error);
          this.monitor.logEvent({
            type: 'api_error',
            error: error.message,
            stack: error.stack,
            path: pathname,
            method,
            timestamp: new Date().toISOString()
          });
          this.sendResponse(res, 500, { error: 'Internal Server Error' });
        }
      } else {
        this.sendResponse(res, 404, { error: 'Not Found' });
      }
  }

  // Authentication middleware
  async authenticateRequest(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { authenticated: false };
    }

    const token = authHeader.split(' ')[1];
    try {
      // Verify JWT token
      const decoded = this.verifyToken(token);
      const user = this.users.get(decoded.username);
      
      if (!user || user.token !== token) {
        return { authenticated: false };
      }
      
      return { authenticated: true, user };
    } catch (error) {
      await this.monitor.logEvent({
        type: 'authentication_failed',
        ip: req.socket.remoteAddress,
        reason: 'Invalid token',
        timestamp: new Date().toISOString()
      });
      return { authenticated: false };
    }
  }

  // JWT token generation and verification
  generateToken(username) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const payload = Buffer.from(JSON.stringify({
      username,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour expiration
    })).toString('base64');
    
    const signature = createHmac('sha256', this.jwtSecret)
      .update(`${header}.${payload}`)
      .digest('base64');
      
    return `${header}.${payload}.${signature}`;
  }

  verifyToken(token) {
    const [header, payload, signature] = token.split('.');
    const expectedSignature = createHmac('sha256', this.jwtSecret)
      .update(`${header}.${payload}`)
      .digest('base64');
      
    if (signature !== expectedSignature) {
      throw new Error('Invalid signature');
    }
    
    const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
    
    // Check expiration
    if (decoded.exp < Date.now() / 1000) {
      throw new Error('Token expired');
    }
    
    return decoded;
  }

  // Rate limiting
  checkRateLimit(ip) {
    const WINDOW_MS = 60 * 1000; // 1 minute
    const MAX_REQUESTS = 100; // Max requests per window
    
    if (!this.rateLimits) {
      this.rateLimits = new Map();
    }
    
    const now = Date.now();
    const windowStart = now - WINDOW_MS;
    
    // Clean up old entries
    for (const [ip, entry] of this.rateLimits.entries()) {
      if (entry.timestamp < windowStart) {
        this.rateLimits.delete(ip);
      }
    }
    
    // Get or create rate limit entry
    let entry = this.rateLimits.get(ip) || { count: 0, timestamp: now };
    
    // Reset count if window has passed
    if (entry.timestamp < windowStart) {
      entry.count = 0;
      entry.timestamp = now;
    }
    
    // Check if rate limit exceeded
    if (entry.count >= MAX_REQUESTS) {
      return {
        allowed: false,
        retryAfter: Math.ceil((entry.timestamp + WINDOW_MS - now) / 1000)
      };
    }
    
    // Increment count and update timestamp
    entry.count++;
    this.rateLimits.set(ip, entry);
    
    return { allowed: true };
  }

  // Route Handlers
  async handleGetStats({ res }) {
    const stats = this.proxy.getStats();
    return stats;
  }

  async handleBlockIP({ req, res }) {
    // Implementation for blocking IPs
    return { success: true };
  }

  async handleListUsers({ res }) {
    const users = Array.from(this.users.entries()).map(([username, user]) => ({
      username,
      isAdmin: user.isAdmin,
      lastLogin: user.lastLogin
    }));
    return { users };
  }

  async handleAddUser({ req, res }) {
    // Implementation for adding users
    return { success: true };
  }

  async handleRemoveUser({ req, res }) {
    // Implementation for removing users
    return { success: true };
  }

  async handleGetLogs({ req, res }) {
    // Implementation for retrieving logs
    return { logs: [] };
  }

  async handleGetMonitoring({ req, res }) {
    // Implementation for monitoring data
    return this.monitor.getMetrics();
  }

  // Utility Methods
  sendResponse(res, statusCode, data) {
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = statusCode;
    res.end(JSON.stringify(data));
  }

  async readRequestBody(req) {
    return new Promise((resolve, reject) => {
      let body = [];
      req.on('data', (chunk) => body.push(chunk));
      req.on('end', () => {
        try {
          body = Buffer.concat(body).toString();
          resolve(JSON.parse(body));
        } catch (error) {
          reject(new Error('Invalid JSON'));
        }
      });
      req.on('error', reject);
    });
  }
      signer.update(`${header}.${payload}`);
      const isValid = signer.verify(
        this.jwtSecret,
        signature,
        'base64url'
      );
      return isValid;
    } catch (e) {
      return false;
    }
  }

  async parseBody(req) {
    return new Promise((resolve) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve({});
        }
      });
    });
  }

  sendResponse(res, statusCode, data) {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data));
  }
}

function randomBytes(size) {
  const crypto = require('crypto');
  return crypto.randomBytes(size);
}

export default AdminAPI;

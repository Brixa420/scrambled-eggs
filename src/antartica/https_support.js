import { createServer as createHttpsServer } from 'https';
import { createServer as createHttpServer } from 'http';
import { readFileSync } from 'fs';
import { join } from 'path';

export function createSecureServer(options, requestListener) {
  const {
    keyPath = join(__dirname, 'certs', 'server.key'),
    certPath = join(__dirname, 'certs', 'server.crt'),
    forceHttps = true,
    httpPort = 80,
    httpsPort = 443
  } = options;

  let httpsServer;
  
  try {
    const httpsOptions = {
      key: readFileSync(keyPath),
      cert: readFileSync(certPath),
      minVersion: 'TLSv1.3',
      ciphers: [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
      ].join(':')
    };

    httpsServer = createHttpsServer(httpsOptions, requestListener);
    
    if (forceHttps) {
      // Create HTTP server to redirect to HTTPS
      const httpServer = createHttpServer((req, res) => {
        const httpsUrl = `https://${req.headers.host}${req.url}`;
        res.writeHead(301, { 'Location': httpsUrl });
        res.end();
      });
      
      httpServer.listen(httpPort, () => {
        console.log(`HTTP redirect server running on port ${httpPort}`);
      });
    }

    httpsServer.listen(httpsPort, () => {
      console.log(`HTTPS server running on port ${httpsPort}`);
    });

    return httpsServer;
  } catch (error) {
    console.error('HTTPS setup failed:', error.message);
    if (process.env.NODE_ENV !== 'production') {
      console.log('Falling back to HTTP for development');
      const httpServer = createHttpServer(requestListener);
      httpServer.listen(httpPort);
      return httpServer;
    }
    throw error;
  }
}

export function setupIPWhitelist(proxy) {
  const whitelist = new Set();
  
  // Add localhost by default
  whitelist.add('127.0.0.1');
  whitelist.add('::1');
  
  return {
    add: (ipOrCIDR) => {
      if (ipOrCIDR.includes('/')) {
        // Handle CIDR notation
        const [base, bits] = ipOrCIDR.split('/');
        whitelist.add({ type: 'cidr', value: ipOrCIDR, base, bits: parseInt(bits) });
      } else {
        whitelist.add(ipOrCIDR);
      }
    },
    
    remove: (ip) => {
      whitelist.delete(ip);
    },
    
    check: (ip) => {
      // Check direct match
      if (whitelist.has(ip)) return true;
      
      // Check CIDR ranges
      for (const entry of whitelist) {
        if (typeof entry === 'object' && entry.type === 'cidr') {
          if (this.isInCIDR(ip, entry.base, entry.bits)) {
            return true;
          }
        }
      }
      
      return false;
    },
    
    list: () => {
      return Array.from(whitelist);
    },
    
    isInCIDR: (ip, cidrBase, maskBits) => {
      // Convert IP to number
      const ipToNum = (ip) => {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
      };
      
      const mask = ~((1 << (32 - maskBits)) - 1) >>> 0;
      const ipNum = ipToNum(ip);
      const cidrNum = ipToNum(cidrBase);
      
      return (ipNum & mask) === (cidrNum & mask);
    }
  };
}

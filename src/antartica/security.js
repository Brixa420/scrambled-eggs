import { createHmac, timingSafeEqual } from 'crypto';

class SecurityManager {
  constructor() {
    this.users = new Map(); // username -> { passwordHash, rateLimit }
    this.rateLimits = new Map(); // ip -> { count, resetAt }
    this.rateLimitWindow = 60 * 1000; // 1 minute window
    this.maxRequestsPerMinute = 100; // Default rate limit
    this.blockedIPs = new Set();
    this.failedAttempts = new Map(); // ip -> count
    this.maxFailedAttempts = 5;
    this.blockDuration = 15 * 60 * 1000; // 15 minutes
  }

  // User Management
  addUser(username, password, options = {}) {
    const salt = randomBytes(16).toString('hex');
    const passwordHash = this.hashPassword(password, salt);
    this.users.set(username, {
      passwordHash,
      salt,
      rateLimit: options.rateLimit || this.maxRequestsPerMinute,
      isAdmin: !!options.isAdmin
    });
  }

  authenticate(authHeader) {
    if (!authHeader) return false;
    
    try {
      const [scheme, credentials] = authHeader.split(' ');
      if (scheme.toLowerCase() !== 'basic') return false;
      
      const [username, password] = Buffer.from(credentials, 'base64')
        .toString('utf-8')
        .split(':');
      
      const user = this.users.get(username);
      if (!user) return false;
      
      const hash = this.hashPassword(password, user.salt);
      return timingSafeEqual(
        Buffer.from(hash, 'hex'),
        Buffer.from(user.passwordHash, 'hex')
      ) ? user : false;
      
    } catch (e) {
      return false;
    }
  }

  // Rate Limiting
  checkRateLimit(ip) {
    if (this.blockedIPs.has(ip)) {
      return { allowed: false, remaining: 0, reset: this.rateLimits.get(ip)?.resetAt };
    }

    const now = Date.now();
    const limit = this.rateLimits.get(ip) || { count: 0, resetAt: now + this.rateLimitWindow };
    
    if (now > limit.resetAt) {
      // Reset the counter
      limit.count = 0;
      limit.resetAt = now + this.rateLimitWindow;
    }

    const user = Array.from(this.users.values())
      .find(u => u.ip === ip);
    
    const maxRequests = user?.rateLimit || this.maxRequestsPerMinute;
    const remaining = Math.max(0, maxRequests - limit.count - 1);
    
    if (limit.count >= maxRequests) {
      this.blockedIPs.add(ip);
      setTimeout(() => this.blockedIPs.delete(ip), this.blockDuration);
      return { allowed: false, remaining: 0, reset: limit.resetAt };
    }

    limit.count++;
    this.rateLimits.set(ip, limit);
    
    return {
      allowed: true,
      remaining,
      reset: limit.resetAt
    };
  }

  // Security Events
  logSecurityEvent(event) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event: event.type,
      ip: event.ip,
      details: event.details || {}
    };
    
    // In production, this would write to a secure log file or database
    console.log('[SECURITY]', JSON.stringify(logEntry));
    
    // Handle failed login attempts
    if (event.type === 'login_failed') {
      const count = (this.failedAttempts.get(event.ip) || 0) + 1;
      this.failedAttempts.set(event.ip, count);
      
      if (count >= this.maxFailedAttempts) {
        this.blockedIPs.add(event.ip);
        setTimeout(() => {
          this.blockedIPs.delete(event.ip);
          this.failedAttempts.delete(event.ip);
        }, this.blockDuration);
      }
    } else if (event.type === 'login_success') {
      this.failedAttempts.delete(event.ip);
    }
  }

  // Utility Methods
  hashPassword(password, salt) {
    return createHmac('sha256', salt)
      .update(password)
      .digest('hex');
  }
}

// Helper function to generate random bytes
function randomBytes(size) {
  const crypto = require('crypto');
  return crypto.randomBytes(size);
}

export default SecurityManager;

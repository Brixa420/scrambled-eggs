import { createWriteStream } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import { createGzip } from 'zlib';
import { createHash } from 'crypto';
import { createGunzip } from 'zlib';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { createHash } from 'crypto';

class SecurityMonitor {
  constructor(options = {}) {
    this.logFile = options.logFile || join(process.cwd(), 'logs', 'security.log');
    this.retentionDays = options.retentionDays || 30;
    this.logStream = null;
    this.metrics = {
      requests: 0,
      blocked: 0,
      authenticated: 0,
      errors: 0,
      bytesTransferred: 0,
      lastAlert: null
    };
    
    this.setupLogRotation();
  }

  async logEvent(event) {
    const timestamp = new Date().toISOString();
    const eventData = {
      timestamp,
      ...event,
      requestId: this.generateRequestId()
    };

    // Update metrics
    this.metrics.requests++;
    if (event.type === 'blocked') this.metrics.blocked++;
    if (event.type === 'authenticated') this.metrics.authenticated++;
    if (event.type === 'error') this.metrics.errors++;
    if (event.bytesTransferred) {
      this.metrics.bytesTransferred += event.bytesTransferred;
    }

    // Write to log file
    await this.writeToLog(JSON.stringify(eventData) + '\n');
    
    // Check for security alerts
    this.checkForAlerts(event);
    
    return eventData;
  }

  async writeToLog(data) {
    if (!this.logStream) {
      await this.ensureLogDirectory();
      this.logStream = createWriteStream(this.logFile, { flags: 'a' });
    }
    
    return new Promise((resolve, reject) => {
      if (!this.logStream.write(data)) {
        this.logStream.once('drain', resolve);
      } else {
        process.nextTick(resolve);
      }
    });
  }

  async ensureLogDirectory() {
    const logDir = join(process.cwd(), 'logs');
    try {
      await fsPromises.mkdir(logDir, { recursive: true });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
  }

  generateRequestId() {
    return createHash('sha256')
      .update(Date.now().toString() + Math.random().toString())
      .digest('hex')
      .substring(0, 16);
  }

  checkForAlerts(event) {
    const now = Date.now();
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    
    // Example alert: Too many failed auth attempts
    if (event.type === 'authentication_failed') {
      const recentFailures = this.getRecentEvents('authentication_failed', fiveMinutesAgo);
      if (recentFailures.length > 5) {
        this.triggerAlert('AUTH_ATTEMPT_LIMIT_EXCEEDED', {
          ip: event.ip,
          attempts: recentFailures.length,
          lastAttempt: event.timestamp
        });
      }
    }
    
    // Add more alert conditions as needed
  }

  async triggerAlert(type, data) {
    const alert = {
      type,
      level: 'high',
      timestamp: new Date().toISOString(),
      data
    };
    
    this.metrics.lastAlert = alert;
    
    // In a real implementation, this could trigger notifications
    console.warn('SECURITY ALERT:', alert);
    
    // Log the alert
    return this.logEvent({
      type: 'security_alert',
      ...alert
    });
  }

  getMetrics() {
    return {
      ...this.metrics,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      timestamp: new Date().toISOString()
    };
  }

  async setupLogRotation() {
    // Rotate logs daily
    const rotateLogs = async () => {
      const now = new Date();
      const yesterday = new Date(now);
      yesterday.setDate(yesterday.getDate() - 1);
      
      const oldLogPath = this.logFile;
      const newLogPath = `${this.logFile}.${yesterday.toISOString().split('T')[0]}.gz`;
      
      try {
        await this.compressFile(oldLogPath, newLogPath);
        // Clear the current log file
        this.logStream = createWriteStream(oldLogPath, { flags: 'w' });
      } catch (err) {
        console.error('Error rotating logs:', err);
      }
    };
    
    // Rotate at midnight every day
    const now = new Date();
    const midnight = new Date(now);
    midnight.setHours(24, 0, 0, 0);
    
    setTimeout(() => {
      rotateLogs();
      // Then rotate every 24 hours
      setInterval(rotateLogs, 24 * 60 * 60 * 1000);
    }, midnight - now);
    
    // Clean up old logs
    this.cleanupOldLogs();
  }

  async compressFile(source, target) {
    const gzip = createGzip();
    const sourceStream = createReadStream(source);
    const targetStream = createWriteStream(target);
    
    await pipeline(sourceStream, gzip, targetStream);
  }

  async cleanupOldLogs() {
    try {
      const files = await fsPromises.readdir(join(process.cwd(), 'logs'));
      const now = new Date();
      
      for (const file of files) {
        if (file.endsWith('.gz')) {
          const filePath = join(process.cwd(), 'logs', file);
          const stats = await fsPromises.stat(filePath);
          const fileAge = (now - stats.mtime) / (1000 * 60 * 60 * 24);
          
          if (fileAge > this.retentionDays) {
            await fsPromises.unlink(filePath);
          }
        }
      }
    } catch (err) {
      console.error('Error cleaning up old logs:', err);
    }
  }

  getRecentEvents(type, since) {
    // In a real implementation, this would query the log storage
    // For this example, we'll return an empty array
    return [];
  }
}

export default SecurityMonitor;

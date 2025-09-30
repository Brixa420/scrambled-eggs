import { performance, PerformanceObserver } from 'perf_hooks';

class EncryptionPerformance {
  constructor() {
    this.metrics = {
      encryption: {
        count: 0,
        totalTime: 0,
        averageTime: 0,
        minTime: Infinity,
        maxTime: 0,
        lastTime: 0
      },
      decryption: {
        count: 0,
        totalTime: 0,
        averageTime: 0,
        minTime: Infinity,
        maxTime: 0,
        lastTime: 0
      },
      keyDerivation: {
        count: 0,
        totalTime: 0,
        averageTime: 0
      },
      lastUpdated: null
    };

    // Set up performance observer for garbage collection monitoring
    this.observer = new PerformanceObserver((list) => {
      const entry = list.getEntries()[0];
      console.log(`GC Event: ${entry.name}, Duration: ${entry.duration.toFixed(2)}ms`);
    });
    
    this.observer.observe({ entryTypes: ['gc'], buffered: true });
  }

  /**
   * Record an encryption operation
   * @param {number} duration - Duration in milliseconds
   * @param {number} dataSize - Size of encrypted data in bytes
   */
  recordEncryption(duration, dataSize) {
    this.metrics.encryption.count++;
    this.metrics.encryption.totalTime += duration;
    this.metrics.encryption.averageTime = 
      this.metrics.encryption.totalTime / this.metrics.encryption.count;
    this.metrics.encryption.minTime = Math.min(this.metrics.encryption.minTime, duration);
    this.metrics.encryption.maxTime = Math.max(this.metrics.encryption.maxTime, duration);
    this.metrics.encryption.lastTime = duration;
    this.metrics.lastUpdated = new Date().toISOString();
    
    // Log performance metrics every 10 operations
    if (this.metrics.encryption.count % 10 === 0) {
      this.logMetrics('encryption');
    }
  }

  /**
   * Record a decryption operation
   * @param {number} duration - Duration in milliseconds
   * @param {number} dataSize - Size of decrypted data in bytes
   */
  recordDecryption(duration, dataSize) {
    this.metrics.decryption.count++;
    this.metrics.decryption.totalTime += duration;
    this.metrics.decryption.averageTime = 
      this.metrics.decryption.totalTime / this.metrics.decryption.count;
    this.metrics.decryption.minTime = Math.min(this.metrics.decryption.minTime, duration);
    this.metrics.decryption.maxTime = Math.max(this.metrics.decryption.maxTime, duration);
    this.metrics.decryption.lastTime = duration;
    this.metrics.lastUpdated = new Date().toISOString();
    
    // Log performance metrics every 10 operations
    if (this.metrics.decryption.count % 10 === 0) {
      this.logMetrics('decryption');
    }
  }

  /**
   * Record a key derivation operation
   * @param {number} duration - Duration in milliseconds
   */
  recordKeyDerivation(duration) {
    this.metrics.keyDerivation.count++;
    this.metrics.keyDerivation.totalTime += duration;
    this.metrics.keyDerivation.averageTime = 
      this.metrics.keyDerivation.totalTime / this.metrics.keyDerivation.count;
    this.metrics.lastUpdated = new Date().toISOString();
  }

  /**
   * Log performance metrics
   * @param {string} [operation] - Specific operation to log
   */
  logMetrics(operation) {
    const metrics = operation ? 
      { [operation]: this.metrics[operation] } : 
      this.metrics;
    
    console.log('\n🔧 Performance Metrics');
    console.log('===================');
    console.log(`Last Updated: ${this.metrics.lastUpdated}\n`);
    
    for (const [op, stats] of Object.entries(metrics)) {
      if (op === 'lastUpdated') continue;
      
      console.log(`📊 ${op.toUpperCase()} STATS`);
      console.log('-------------------');
      console.log(`Total Operations: ${stats.count}`);
      console.log(`Average Time: ${stats.averageTime.toFixed(2)}ms`);
      
      if (stats.minTime !== Infinity) {
        console.log(`Min Time: ${stats.minTime.toFixed(2)}ms`);
        console.log(`Max Time: ${stats.maxTime.toFixed(2)}ms`);
        console.log(`Last Time: ${stats.lastTime.toFixed(2)}ms`);
      }
      
      if (stats.throughput) {
        console.log(`Throughput: ${stats.throughput.toFixed(2)} MB/s`);
      }
      
      console.log('');
    }
  }

  /**
   * Get current performance metrics
   * @returns {Object}
   */
  getMetrics() {
    return JSON.parse(JSON.stringify(this.metrics));
  }

  /**
   * Reset all performance metrics
   */
  reset() {
    this.metrics = {
      encryption: {
        count: 0,
        totalTime: 0,
        averageTime: 0,
        minTime: Infinity,
        maxTime: 0,
        lastTime: 0
      },
      decryption: {
        count: 0,
        totalTime: 0,
        averageTime: 0,
        minTime: Infinity,
        maxTime: 0,
        lastTime: 0
      },
      keyDerivation: {
        count: 0,
        totalTime: 0,
        averageTime: 0
      },
      lastUpdated: null
    };
  }
}

export default new EncryptionPerformance();

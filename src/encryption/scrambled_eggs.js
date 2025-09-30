import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import { performance } from 'perf_hooks';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM
const TAG_LENGTH = 16; // 128-bit authentication tag
const SALT_LENGTH = 32;
const ITERATIONS = 16384; // Reduced from 100000 for better performance
const KEY_LENGTH = 32; // 256 bits
const SCRYPT_PARAMS = {
  N: ITERATIONS, // CPU/memory cost parameter (must be a power of 2)
  r: 8,          // Block size parameter
  p: 1,          // Parallelization parameter
  maxmem: 128 * 1024 * 1024 // Maximum memory to use (128MB)
};

class ScrambledEggs {
  constructor() {
    // Configuration
    this.config = {
      minLayers: 1000,         // Minimum number of encryption layers
      maxLayers: 10000,        // Maximum number of encryption layers
      baseLayers: 1000,        // Default base number of layers
      layerIncrement: 100,     // Number of layers to add when escalating
      threatThreshold: 3,      // Number of failed attempts before escalating
      failedAttempts: 0,       // Counter for failed decryption attempts
      lastThreatDetected: null // Timestamp of last detected threat
    };
    
    // Initialize with base layers
    this.layers = this.config.baseLayers;
    this.breachDetected = false;
    
    // Performance and security metrics
    this.performanceMetrics = {
      lastEncryptionTime: 0,
      lastDecryptionTime: 0,
      totalLayers: this.layers,
      breachCount: 0,
      layerHistory: [],
      threatEvents: []
    };
    
    // Start security monitoring
    this.startSecurityMonitor();
  }

  /**
   * Derive a key from a password and salt
   * @private
   */
  deriveKey(password, salt) {
    try {
      // Convert password to Buffer if it's a string
      const passwordBuffer = typeof password === 'string' 
        ? Buffer.from(password, 'utf8') 
        : password;
      
      // Derive key using scrypt with proper parameter structure
      const key = scryptSync(
        passwordBuffer,
        salt,
        KEY_LENGTH,
        {
          N: SCRYPT_PARAMS.N,
          r: SCRYPT_PARAMS.r,
          p: SCRYPT_PARAMS.p,
          maxmem: SCRYPT_PARAMS.maxmem
        }
      );
      
      return key;
    } catch (error) {
      console.error('Key derivation error:', error);
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }

  /**
   * Generate a random salt
   * @private
   */
  generateSalt() {
    return randomBytes(SALT_LENGTH);
  }

  /**
   * Add more encryption layers in case of breach detection
   * @param {string} reason - Reason for escalation
   * @param {Object} details - Additional details about the threat
   * @returns {number} New total number of layers
   */
  async escalateEncryption(reason = 'suspicious_activity', details = {}) {
    // Calculate new layer count (exponential backoff with jitter)
    const currentLayers = this.layers;
    const maxIncrement = Math.min(
      this.config.maxLayers - currentLayers,
      this.config.layerIncrement * Math.pow(2, this.config.failedAttempts)
    );
    
    // Add random jitter to make timing attacks harder
    const jitter = Math.floor(Math.random() * (maxIncrement * 0.2));
    const additionalLayers = Math.max(10, Math.floor(maxIncrement * 0.8) + jitter);
    
    // Update layer count
    this.layers = Math.min(this.config.maxLayers, currentLayers + additionalLayers);
    this.performanceMetrics.totalLayers = this.layers;
    this.performanceMetrics.breachCount++;
    
    // Log the security event
    const event = {
      timestamp: new Date().toISOString(),
      reason,
      previousLayers: currentLayers,
      additionalLayers,
      totalLayers: this.layers,
      details
    };
    
    this.performanceMetrics.threatEvents.push(event);
    this.performanceMetrics.layerHistory.push({
      timestamp: new Date().toISOString(),
      layers: this.layers,
      reason
    });
    
    console.warn(`\n⚠️  SECURITY ALERT: ${reason}`);
    console.warn(`   - Added ${additionalLayers} encryption layers`);
    console.warn(`   - New total: ${this.layers} layers`);
    
    // Reset failed attempts counter
    this.config.failedAttempts = 0;
    
    return this.layers;
  }
  
  /**
   * Monitor for security threats and adjust encryption as needed
   * @private
   */
  startSecurityMonitor() {
    setInterval(() => {
      // Check for too many failed attempts
      if (this.config.failedAttempts >= this.config.threatThreshold) {
        this.escalateEncryption('multiple_failed_attempts', {
          attempts: this.config.failedAttempts,
          threshold: this.config.threatThreshold
        });
      }
      
      // Gradually reduce layers if no recent threats
      if (this.layers > this.config.baseLayers && 
          (!this.config.lastThreatDetected || 
           Date.now() - new Date(this.config.lastThreatDetected) > 3600000)) { // 1 hour
        const reduction = Math.min(
          Math.floor(this.layers * 0.1), // Reduce by 10% or less
          this.layers - this.config.baseLayers
        );
        
        if (reduction > 0) {
          this.layers -= reduction;
          console.log(`\n🔄 Reducing encryption layers by ${reduction}. Current: ${this.layers}`);
        }
      }
    }, 60000); // Check every minute
  }

  /**
   * Encrypt data with multiple layers of AES-256-GCM
   * @param {Buffer|string} data - Data to encrypt
   * @param {string} password - Encryption password
   * @returns {Promise<{encrypted: Buffer, metadata: Object}>}
   */
  async encrypt(data, password) {
    const startTime = performance.now();
    let currentData = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const metadata = {
      version: '1.0',
      layers: this.layers,
      timestamps: {
        start: new Date().toISOString(),
        end: null
      },
      performance: {}
    };

    try {
      // Initial encryption with the base password
      for (let i = 0; i < this.layers; i++) {
        const layerStart = performance.now();
        const salt = this.generateSalt();
        
        // Create a unique password for each layer by appending the layer index
        const layerPassword = `${password}${i}`;
        
        // Derive key synchronously since scrypt is already blocking
        const key = this.deriveKey(layerPassword, salt);
        const iv = randomBytes(IV_LENGTH);
        
        // Create and configure the cipher
        const cipher = createCipheriv(ALGORITHM, key, iv);
        
        // Encrypt the data
        const encrypted = Buffer.concat([
          cipher.update(currentData),
          cipher.final(),
          cipher.getAuthTag()
        ]);
        
        // Prepend IV and salt for this layer
        currentData = Buffer.concat([
          iv,
          salt,
          encrypted
        ]);

        // Record layer performance
        metadata.performance[`layer_${i}`] = {
          size: currentData.length,
          time: performance.now() - layerStart
        };
      }

      metadata.timestamps.end = new Date().toISOString();
      const totalTime = performance.now() - startTime;
      this.performanceMetrics.lastEncryptionTime = totalTime;
      
      return {
        encrypted: currentData,
        metadata: {
          ...metadata,
          performance: {
            ...metadata.performance,
            totalTime,
            averageTimePerLayer: totalTime / this.layers
          }
        }
      };
    } catch (error) {
      console.error('Encryption error:', error);
      // Attempt to escalate security on error
      if (!this.breachDetected) {
        this.breachDetected = true;
        await this.escalateEncryption();
      }
      throw new Error('Encryption failed: ' + error.message);
    }
  }

  /**
   * Decrypt data with multiple layers of AES-256-GCM
   * @param {Buffer} encryptedData - Encrypted data
   * @param {string} password - Decryption password
   * @returns {Promise<Buffer>}
   */
  async decrypt(encryptedData, password) {
    const startTime = performance.now();
    let currentData = Buffer.from(encryptedData);
    
    try {
      // Decrypt in reverse order (last layer first)
      for (let i = this.layers - 1; i >= 0; i--) {
        // Extract IV and salt for this layer
        const iv = currentData.subarray(0, IV_LENGTH);
        const salt = currentData.subarray(IV_LENGTH, IV_LENGTH + SALT_LENGTH);
        const encrypted = currentData.subarray(IV_LENGTH + SALT_LENGTH);
        
        // The last TAG_LENGTH bytes are the auth tag
        const authTag = encrypted.subarray(encrypted.length - TAG_LENGTH);
        const encryptedContent = encrypted.subarray(0, encrypted.length - TAG_LENGTH);
        
        // Create a unique password for each layer by appending the layer index
        const layerPassword = `${password}${i}`;
        
        try {
          // Derive key synchronously
          const key = this.deriveKey(layerPassword, salt);
          
          // Create and configure the decipher
          const decipher = createDecipheriv(ALGORITHM, key, iv);
          decipher.setAuthTag(authTag);
          
          // Decrypt the data
          let decrypted = decipher.update(encryptedContent);
          decrypted = Buffer.concat([decrypted, decipher.final()]);
          
          // Update current data for next iteration
          currentData = decrypted;
          
        } catch (decryptError) {
          console.error(`Decryption failed at layer ${i}:`, decryptError);
          // If we're not at the first layer, try with the previous layer's password format
          if (i < this.layers - 1) {
            console.log(`Trying with previous layer's password format...`);
            const prevLayerPassword = `${password}${i + 1}`;
            const key = this.deriveKey(prevLayerPassword, salt);
            const decipher = createDecipheriv(ALGORITHM, key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encryptedContent);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            currentData = decrypted;
          } else {
            throw decryptError;
          }
        }
      }
      
      const totalTime = performance.now() - startTime;
      this.performanceMetrics.lastDecryptionTime = totalTime;
      
      return currentData;
    } catch (error) {
      console.error('Decryption error:', error);
      // Attempt to escalate security on error
      if (!this.breachDetected) {
        this.breachDetected = true;
        await this.escalateEncryption();
      }
      throw new Error('Decryption failed: ' + error.message);
    }
  }

  /**
   * Get current encryption statistics and security status
   * @returns {Object}
   */
  getStats() {
    return {
      ...this.performanceMetrics,
      currentLayers: this.layers,
      breachDetected: this.breachDetected,
      security: {
        minLayers: this.config.minLayers,
        maxLayers: this.config.maxLayers,
        failedAttempts: this.config.failedAttempts,
        lastThreatDetected: this.config.lastThreatDetected,
        threatLevel: this.calculateThreatLevel()
      },
      recentLayerChanges: this.performanceMetrics.layerHistory
        .slice(-5) // Last 5 changes
        .map(change => ({
          timestamp: change.timestamp,
          layers: change.layers,
          reason: change.reason
        }))
    };
  }
  
  /**
   * Calculate current threat level based on recent activity
   * @private
   * @returns {string} low/medium/high/critical
   */
  calculateThreatLevel() {
    const recentThreats = this.performanceMetrics.threatEvents.filter(
      event => Date.now() - new Date(event.timestamp) < 3600000 // Last hour
    );
    
    if (recentThreats.length >= 5) return 'critical';
    if (recentThreats.length >= 3) return 'high';
    if (recentThreats.length >= 1) return 'medium';
    return 'low';
  }
  
  /**
   * Manually adjust the number of encryption layers
   * @param {number} layers - New number of layers (will be clamped to min/max)
   * @param {string} reason - Reason for the adjustment
   * @returns {number} New number of layers
   */
  setLayers(layers, reason = 'manual_adjustment') {
    const newLayers = Math.max(
      this.config.minLayers,
      Math.min(this.config.maxLayers, Math.floor(layers))
    );
    
    const change = newLayers - this.layers;
    this.layers = newLayers;
    
    // Log the change
    this.performanceMetrics.layerHistory.push({
      timestamp: new Date().toISOString(),
      previousLayers: this.layers - change,
      newLayers: this.layers,
      change,
      reason
    });
    
    console.log(`\n🔧 Encryption layers adjusted: ${change > 0 ? '+' : ''}${change}`);
    console.log(`   - New total: ${this.layers} layers`);
    console.log(`   - Reason: ${reason}`);
    
    return this.layers;
  }
}

export default ScrambledEggs;

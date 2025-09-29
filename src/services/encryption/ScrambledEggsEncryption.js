import { SHA3 } from 'sha3';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto-browserify';

export class ScrambledEggsEncryption {
  constructor() {
    this.layers = [];
    this.currentLayer = 0;
    this.breachDetected = false;
    this.initializeBaseLayer();
  }

  // Initialize the base encryption layer with quantum-resistant algorithms
  initializeBaseLayer() {
    const baseKey = this.generateQuantumResistantKey();
    this.layers.push({
      id: 'base-layer',
      key: baseKey,
      algorithm: 'aes-256-gcm', // Using authenticated encryption
      nonce: randomBytes(12), // 96-bit nonce for GCM
      active: true,
      created: Date.now(),
      metadata: {
        strength: 'quantum-resistant',
        lastRotated: Date.now()
      }
    });
  }

  // Generate a quantum-resistant key using multiple sources of entropy
  generateQuantumResistantKey() {
    const entropySources = [
      window.crypto.getRandomValues(new Uint8Array(32)),
      new TextEncoder().encode(Date.now().toString() + performance.now().toString()),
      new Uint8Array(32).map(() => Math.floor(Math.random() * 256))
    ];
    
    // Combine entropy sources using SHA-3 (Keccak)
    const hash = new SHA3(512);
    entropySources.forEach(source => hash.update(source));
    return Buffer.from(hash.digest()).slice(0, 32); // 256-bit key
  }

  // Create a new encryption layer with adaptive properties
  async createNewLayer(trigger = 'manual') {
    const newKey = this.generateQuantumResistantKey();
    const newNonce = randomBytes(12);
    
    const newLayer = {
      id: `layer-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      key: newKey,
      algorithm: 'aes-256-gcm',
      nonce: newNonce,
      active: true,
      created: Date.now(),
      metadata: {
        trigger,
        parentLayer: this.currentLayer,
        strength: this.calculateLayerStrength()
      }
    };
    
    // Add the new layer
    this.layers.push(newLayer);
    const newLayerIndex = this.layers.length - 1;
    
    // If this was triggered by a breach, mark old layers
    if (trigger === 'breach') {
      this.breachDetected = true;
      this.layers[this.currentLayer].active = false;
      this.layers[this.currentLayer].metadata.breached = true;
      this.layers[this.currentLayer].metadata.breachTime = Date.now();
    }
    
    this.currentLayer = newLayerIndex;
    
    // If we have Clippy, notify it of the new layer
    if (window.clippy) {
      window.clippy.notifyEncryptionEvent({
        type: 'new_layer_created',
        layerId: newLayer.id,
        trigger,
        timestamp: Date.now()
      });
    }
    
    return newLayer.id;
  }

  // Calculate the strength of a new layer based on previous breaches
  calculateLayerStrength() {
    const breachCount = this.layers.filter(l => l.metadata.breached).length;
    const baseStrength = 100; // Base strength score
    const breachMultiplier = Math.pow(1.5, breachCount); // Exponential increase after breaches
    return Math.min(baseStrength * breachMultiplier, 1000); // Cap at 1000
  }

  // Encrypt data using the current active layer
  async encrypt(data) {
    const activeLayer = this.layers[this.currentLayer];
    if (!activeLayer || !activeLayer.active) {
      throw new Error('No active encryption layer available');
    }

    try {
      const text = JSON.stringify(data);
      const cipher = createCipheriv(
        activeLayer.algorithm,
        activeLayer.key,
        activeLayer.nonce
      );
      
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // In GCM mode, the auth tag is needed for decryption
      const authTag = cipher.getAuthTag();
      
      return {
        encryptedData: encrypted,
        layerId: activeLayer.id,
        nonce: activeLayer.nonce.toString('hex'),
        authTag: authTag.toString('hex'),
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Encryption failed:', error);
      
      // If encryption fails, it might indicate a compromised layer
      await this.handleEncryptionFailure(error);
      throw error;
    }
  }

  // Decrypt data using the specified layer
  async decrypt(encryptedData, layerId, nonce, authTag) {
    const layer = this.layers.find(l => l.id === layerId);
    if (!layer) {
      throw new Error(`Encryption layer ${layerId} not found`);
    }

    try {
      const decipher = createDecipheriv(
        layer.algorithm,
        layer.key,
        Buffer.from(nonce, 'hex')
      );
      
      // Set the auth tag for verification in GCM mode
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Decryption failed:', error);
      
      // If decryption fails with valid credentials, it might indicate a breach
      if (error.message.includes('Unsupported state or unable to authenticate data')) {
        await this.detectPotentialBreach(layerId, error);
      }
      
      throw error;
    }
  }

  // Handle potential encryption failures
  async handleEncryptionFailure(error) {
    console.warn('Encryption failure detected, rotating encryption layer...');
    
    // Create a new layer due to potential compromise
    await this.createNewLayer('error_handling');
    
    // Notify Clippy about the incident
    if (window.clippy) {
      window.clippy.notifySecurityIncident({
        type: 'encryption_failure',
        severity: 'high',
        error: error.message,
        timestamp: Date.now()
      });
    }
  }

  // Detect potential security breaches
  async detectPotentialBreach(layerId, error) {
    console.warn(`Potential security breach detected in layer ${layerId}`);
    
    // Immediately create a new layer if breach is detected
    await this.createNewLayer('breach_detected');
    
    // Notify Clippy about the potential breach
    if (window.clippy) {
      window.clippy.notifySecurityIncident({
        type: 'potential_breach',
        severity: 'critical',
        layerId,
        error: error.message,
        timestamp: Date.now()
      });
    }
  }

  // Get the current encryption status
  getStatus() {
    return {
      currentLayer: this.currentLayer,
      totalLayers: this.layers.length,
      breachDetected: this.breachDetected,
      activeLayer: this.layers[this.currentLayer],
      layerHealth: this.calculateLayerHealth()
    };
  }

  // Calculate the health of encryption layers
  calculateLayerHealth() {
    const now = Date.now();
    const activeLayers = this.layers.filter(l => l.active);
    const health = {
      total: activeLayers.length,
      strong: 0,
      warning: 0,
      critical: 0
    };

    activeLayers.forEach(layer => {
      const ageHours = (now - layer.created) / (1000 * 60 * 60);
      
      if (ageHours < 24) {
        health.strong++;
      } else if (ageHours < 72) {
        health.warning++;
      } else {
        health.critical++;
      }
    });

    return health;
  }

  // Rotate encryption keys on a schedule or event
  async rotateKeys(reason = 'scheduled_rotation') {
    console.log(`Rotating encryption keys: ${reason}`);
    return this.createNewLayer(reason);
  }

  // Clean up resources
  cleanup() {
    // Securely wipe keys from memory
    this.layers.forEach(layer => {
      if (layer.key) {
        layer.key.fill(0);
      }
      if (layer.nonce) {
        layer.nonce.fill(0);
      }
    });
    
    this.layers = [];
    this.currentLayer = -1;
  }
}

// Singleton instance
export const see = new ScrambledEggsEncryption();

// Auto-rotate keys every 24 hours
const ROTATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
setInterval(() => {
  see.rotateKeys('scheduled_rotation');
}, ROTATION_INTERVAL);

import { SHA3 } from 'sha3';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export class ScrambledEggsEncryption {
  constructor() {
    this.layers = [];
    this.currentLayer = 0;
    this.keyDerivationIterations = 100000;
    this.keyLength = 32; // 256 bits
    this.ivLength = 16; // 128 bits
    this.initializeBaseLayer();
  }

  // Initialize the base encryption layer
  initializeBaseLayer() {
    const baseKey = this.generateKeyFromEntropy();
    this.layers.push({
      id: 'base',
      key: baseKey,
      algorithm: 'aes-256-cbc',
      active: true,
      created: Date.now()
    });
  }

  // Generate a new key using system entropy
  generateKeyFromEntropy() {
    return randomBytes(this.keyLength);
  }

  // Derive a key from a passphrase using PBKDF2
  async deriveKey(passphrase, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt || randomBytes(16),
        iterations: this.keyDerivationIterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-CBC', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  }

  // Add a new encryption layer
  async addLayer(passphrase) {
    const newKey = await this.deriveKey(passphrase);
    const newLayer = {
      id: `layer-${Date.now()}`,
      key: newKey,
      algorithm: 'aes-256-cbc',
      active: true,
      created: Date.now()
    };
    
    this.layers.push(newLayer);
    this.currentLayer = this.layers.length - 1;
    return newLayer.id;
  }

  // Rotate to a new encryption layer when a breach is detected
  async rotateLayer() {
    const newKey = this.generateKeyFromEntropy();
    const newLayer = {
      id: `layer-breach-${Date.now()}`,
      key: newKey,
      algorithm: 'aes-256-cbc',
      active: true,
      created: Date.now(),
      breachDetected: true
    };
    
    // Mark all previous layers as inactive
    this.layers.forEach(layer => {
      layer.active = false;
    });
    
    this.layers.push(newLayer);
    this.currentLayer = this.layers.length - 1;
    return newLayer.id;
  }

  // Encrypt data with the current active layer
  async encrypt(data) {
    const activeLayer = this.layers[this.currentLayer];
    if (!activeLayer || !activeLayer.active) {
      throw new Error('No active encryption layer found');
    }

    const iv = randomBytes(this.ivLength);
    const cipher = createCipheriv(
      activeLayer.algorithm,
      activeLayer.key,
      iv
    );

    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      layerId: activeLayer.id,
      timestamp: Date.now()
    };
  }

  // Decrypt data using the specified layer
  async decrypt(encryptedData, iv, layerId) {
    const layer = this.layers.find(l => l.id === layerId);
    if (!layer) {
      throw new Error(`Encryption layer ${layerId} not found`);
    }

    const decipher = createDecipheriv(
      layer.algorithm,
      layer.key,
      Buffer.from(iv, 'hex')
    );

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  // Create a hash of the data for integrity verification
  createHash(data) {
    const hash = new SHA3(256);
    hash.update(JSON.stringify(data));
    return hash.digest('hex');
  }

  // Verify data integrity using the stored hash
  verifyIntegrity(data, expectedHash) {
    const actualHash = this.createHash(data);
    return actualHash === expectedHash;
  }

  // Get the current encryption status
  getStatus() {
    return {
      totalLayers: this.layers.length,
      activeLayer: this.currentLayer,
      activeLayerId: this.layers[this.currentLayer]?.id,
      layers: this.layers.map(layer => ({
        id: layer.id,
        active: layer.active,
        created: new Date(layer.created).toISOString(),
        algorithm: layer.algorithm,
        breachDetected: layer.breachDetected || false
      }))
    };
  }
}

// Singleton instance
export const see = new ScrambledEggsEncryption();

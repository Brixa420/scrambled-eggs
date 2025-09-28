import crypto from 'crypto';

class KeyManager {
  constructor() {
    this.keys = new Map();
    this.keyRotationInterval = 60 * 60 * 1000; // 1 hour in milliseconds
    this.rotationTimers = new Map();
  }

  // Generate a new key pair
  generateKeyPair(type = 'aes') {
    let key, publicKey, privateKey;
    
    switch (type.toLowerCase()) {
      case 'rsa':
        // For RSA, generate a key pair
        const { publicKey: pub, privateKey: priv } = crypto.generateKeyPairSync('rsa', {
          modulusLength: 4096,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: crypto.randomBytes(32).toString('hex')
          }
        });
        
        publicKey = pub;
        privateKey = priv;
        key = { publicKey, privateKey };
        break;
        
      case 'ec':
        // For ECDH
        const ecdh = crypto.createECDH('secp521r1');
        publicKey = ecdh.generateKeys('hex');
        privateKey = ecdh.getPrivateKey('hex');
        key = { publicKey, privateKey };
        break;
        
      case 'aes':
      default:
        // For symmetric encryption
        key = crypto.randomBytes(32); // 256 bits
    }
    
    return {
      id: crypto.randomBytes(16).toString('hex'),
      type,
      key,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.keyRotationInterval)
    };
  }

  // Store a key with automatic rotation
  storeKey(keyData, keyId = null) {
    const key = {
      ...keyData,
      id: keyId || crypto.randomBytes(16).toString('hex'),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.keyRotationInterval)
    };
    
    this.keys.set(key.id, key);
    
    // Set up automatic key rotation
    this.scheduleKeyRotation(key.id);
    
    return key.id;
  }
  
  // Schedule key rotation
  scheduleKeyRotation(keyId) {
    // Clear any existing timer
    if (this.rotationTimers.has(keyId)) {
      clearTimeout(this.rotationTimers.get(keyId));
    }
    
    const key = this.keys.get(keyId);
    if (!key) return;
    
    const timeUntilRotation = key.expiresAt - Date.now();
    
    // Set a timer to rotate the key
    const timer = setTimeout(() => {
      this.rotateKey(keyId);
    }, Math.max(0, timeUntilRotation));
    
    this.rotationTimers.set(keyId, timer);
  }
  
  // Rotate a key
  rotateKey(keyId) {
    const oldKey = this.keys.get(keyId);
    if (!oldKey) return;
    
    // Generate a new key of the same type
    const newKey = this.generateKeyPair(oldKey.type);
    
    // Store the new key
    this.storeKey({
      ...newKey,
      previousKeyId: oldKey.id
    });
    
    // Mark the old key as rotated (but keep it for decryption)
    oldKey.status = 'rotated';
    oldKey.rotatedAt = new Date();
    
    // Schedule cleanup of the old key
    setTimeout(() => {
      this.keys.delete(oldKey.id);
      this.rotationTimers.delete(oldKey.id);
    }, this.keyRotationInterval * 2); // Keep old key for 2 rotation periods
    
    return newKey.id;
  }
  
  // Get a key by ID
  getKey(keyId) {
    return this.keys.get(keyId);
  }
  
  // Get the latest key of a specific type
  getLatestKey(type = 'aes') {
    let latestKey = null;
    
    for (const [id, key] of this.keys.entries()) {
      if (key.type === type && (!latestKey || key.createdAt > latestKey.createdAt)) {
        latestKey = key;
      }
    }
    
    return latestKey;
  }
  
  // Derive a key from a passphrase
  deriveKeyFromPassphrase(passphrase, salt, iterations = 100000, keylen = 32, digest = 'sha256') {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(passphrase, salt, iterations, keylen, digest, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      });
    });
  }
  
  // Generate a secure random salt
  generateSalt(length = 16) {
    return crypto.randomBytes(length);
  }
}

export default new KeyManager();

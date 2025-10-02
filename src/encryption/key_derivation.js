import { scrypt, randomBytes, timingSafeEqual } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

// Use the same parameters as in scrambled_eggs.js
const SCRYPT_PARAMS = {
  N: 16384, // CPU/memory cost parameter (must be a power of 2)
  r: 8,     // Block size parameter
  p: 1,     // Parallelization parameter
  maxmem: 128 * 1024 * 1024 // Maximum memory to use (128MB)
};

class KeyManager {
  constructor() {
    this.keyCache = new Map();
  }

  /**
   * Generate a secure random key
   * @param {number} length - Key length in bytes
   * @returns {Promise<Buffer>}
   */
  async generateKey(length = 32) {
    return randomBytes(length);
  }

  /**
   * Derive a key from a password and salt
   * @param {string|Buffer} password
   * @param {Buffer} salt
   * @param {Object} [options]
   * @param {number} [options.iterations=100000]
   * @param {number} [options.keyLength=32]
   * @returns {Promise<Buffer>}
   */
  async deriveKey(password, salt, keyLength = 32) {
    const passwordBuffer = typeof password === 'string' 
      ? Buffer.from(password, 'utf8')
      : password;
      
    const cacheKey = `${passwordBuffer.toString('hex')}:${salt.toString('hex')}:${keyLength}`;
    
    // Check cache first
    if (this.keyCache.has(cacheKey)) {
      return this.keyCache.get(cacheKey);
    }

    try {
      const key = await scryptAsync(
        passwordBuffer,
        salt,
        keyLength,
        SCRYPT_PARAMS
      );

      // Cache the derived key
      const keyBuffer = Buffer.from(key);
      this.keyCache.set(cacheKey, keyBuffer);
      
      return keyBuffer;
    } catch (error) {
      console.error('Key derivation failed:', error);
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }

  /**
   * Securely compare two buffers/strings
   * @param {Buffer|string} a
   * @param {Buffer|string} b
   * @returns {boolean}
   */
  secureCompare(a, b) {
    const bufA = Buffer.isBuffer(a) ? a : Buffer.from(a);
    const bufB = Buffer.isBuffer(b) ? b : Buffer.from(b);
    
    return bufA.length === bufB.length && 
           timingSafeEqual(bufA, bufB);
  }

  /**
   * Generate a secure random salt
   * @param {number} [length=32] - Salt length in bytes
   * @returns {Buffer}
   */
  generateSalt(length = 32) {
    return randomBytes(length);
  }

  /**
   * Clear the key cache
   */
  clearCache() {
    this.keyCache.clear();
  }
}

export default new KeyManager();

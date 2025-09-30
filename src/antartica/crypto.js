import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM
const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 16;
const ITERATIONS = 100000;

export class TrafficEncryptor {
  constructor(password) {
    if (!password) {
      throw new Error('Encryption password is required');
    }
    this.password = password;
    this.keyCache = new Map();
  }

  async deriveKey(salt) {
    if (this.keyCache.has(salt)) {
      return this.keyCache.get(salt);
    }

    const key = await new Promise((resolve, reject) => {
      scryptSync(
        this.password,
        salt,
        KEY_LENGTH,
        { N: ITERATIONS },
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });

    this.keyCache.set(salt, key);
    return key;
  }

  generateSalt() {
    return randomBytes(SALT_LENGTH);
  }

  async encrypt(data) {
    const salt = this.generateSalt();
    const iv = randomBytes(IV_LENGTH);
    const key = await this.deriveKey(salt);
    
    const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: 16 });
    
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Combine salt + iv + authTag + encrypted data
    return Buffer.concat([salt, iv, authTag, encrypted]);
  }

  async decrypt(encryptedData) {
    try {
      // Extract components
      const salt = encryptedData.subarray(0, SALT_LENGTH);
      const iv = encryptedData.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
      const authTag = encryptedData.subarray(
        SALT_LENGTH + IV_LENGTH,
        SALT_LENGTH + IV_LENGTH + 16
      );
      const encrypted = encryptedData.subarray(SALT_LENGTH + IV_LENGTH + 16);
      
      const key = await this.deriveKey(salt);
      const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: 16 });
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted;
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Failed to decrypt data');
    }
  }
}

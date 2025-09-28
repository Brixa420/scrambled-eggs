import crypto from 'crypto';

class EncryptionEngine {
  constructor() {
    this.methods = new Map();
    this.currentMethod = 'aes-256-gcm';
    this.initializeDefaultMethods();
  }

  // Initialize with default encryption methods
  initializeDefaultMethods() {
    // AES-256-GCM
    this.addMethod('aes-256-gcm', {
      encrypt: async (data, key, iv) => {
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return { encrypted, iv, authTag };
      },
      decrypt: async (encryptedData, key) => {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, encryptedData.iv);
        decipher.setAuthTag(encryptedData.authTag);
        const decrypted = Buffer.concat([
          decipher.update(encryptedData.encrypted),
          decipher.final()
        ]);
        return decrypted.toString('utf8');
      },
      generateKey: () => crypto.randomBytes(32), // 256 bits
      generateIV: () => crypto.randomBytes(12)    // 96 bits for GCM
    });
  }

  // Add a new encryption method
  addMethod(name, { encrypt, decrypt, generateKey, generateIV }) {
    this.methods.set(name, {
      encrypt,
      decrypt,
      generateKey: generateKey || (() => crypto.randomBytes(32)),
      generateIV: generateIV || (() => crypto.randomBytes(16))
    });
  }

  // Set the current encryption method
  setMethod(name) {
    if (!this.methods.has(name)) {
      throw new Error(`Encryption method '${name}' not found`);
    }
    this.currentMethod = name;
    return this.currentMethod;
  }

  // Get current method info
  getCurrentMethod() {
    return {
      name: this.currentMethod,
      ...this.methods.get(this.currentMethod)
    };
  }

  // Encrypt data using current method
  async encrypt(data, key) {
    const method = this.methods.get(this.currentMethod);
    if (!method) {
      throw new Error('No encryption method selected');
    }

    const iv = method.generateIV();
    const result = await method.encrypt(data, key, iv);
    
    return {
      method: this.currentMethod,
      ...result,
      timestamp: Date.now()
    };
  }

  // Decrypt data
  async decrypt(encryptedData, key) {
    const method = this.methods.get(encryptedData.method);
    if (!method) {
      throw new Error(`Unsupported encryption method: ${encryptedData.method}`);
    }

    return method.decrypt(encryptedData, key);
  }
}

export default new EncryptionEngine();

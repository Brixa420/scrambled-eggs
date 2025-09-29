import { randomBytes, createCipheriv, createDecipheriv, createHash, createSign, createVerify, generateKeyPairSync, KeyObject } from 'crypto';
import { promisify } from 'util';

const randomBytesAsync = promisify(randomBytes);

interface EncryptedData {
  iv: string;
  ciphertext: string;
  authTag: string;
  timestamp: number;
  keyId?: string;
  signature?: string;
}

interface KeyPair {
  publicKey: string;
  privateKey: string;
  keyId: string;
}

interface PeerInfo {
  id: string;
  publicKey: string;
  lastSeen: number;
  trustScore: number;
}

export class AICrypto {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly KEY_LENGTH = 32; // 256 bits
  private static readonly IV_LENGTH = 12; // 96 bits for GCM
  private static readonly AUTH_TAG_LENGTH = 16; // 128 bits for GCM
  private static readonly KEY_ROTATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
  
  private static instance: AICrypto;
  private keyPair: KeyPair;
  private peerKeys: Map<string, string> = new Map(); // peerId -> publicKey
  private sessionKeys: Map<string, { key: Buffer; expires: number }> = new Map();
  private peerTrustScores: Map<string, number> = new Map();
  private lastKeyRotation: number = Date.now();

  private constructor() {
    // Initialize with a new key pair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    this.keyPair = {
      publicKey,
      privateKey,
      keyId: createHash('sha256').update(publicKey).digest('hex').slice(0, 16)
    };
    
    // Start key rotation check
    this.scheduleKeyRotation();
  }

  public static getInstance(): AICrypto {
    if (!AICrypto.instance) {
      AICrypto.instance = new AICrypto();
    }
    return AICrypto.instance;
  }

  public getPublicKey(): string {
    return this.keyPair.publicKey;
  }

  public getKeyId(): string {
    return this.keyPair.keyId;
  }

  private scheduleKeyRotation() {
    setInterval(() => {
      if (Date.now() - this.lastKeyRotation >= AICrypto.KEY_ROTATION_INTERVAL) {
        this.rotateKeys();
      }
    }, 3600000); // Check every hour
  }

  private async rotateKeys() {
    console.log('Rotating encryption keys...');
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    this.keyPair = {
      publicKey,
      privateKey,
      keyId: createHash('sha256').update(publicKey).digest('hex').slice(0, 16)
    };
    
    this.lastKeyRotation = Date.now();
    console.log('Key rotation complete. New key ID:', this.keyPair.keyId);
  }

  public async generateSessionKey(peerId: string): Promise<Buffer> {
    const key = await AICrypto.generateKey();
    this.sessionKeys.set(peerId, {
      key,
      expires: Date.now() + 3600000 // 1 hour
    });
    return key;
  }

  public async getSessionKey(peerId: string): Promise<Buffer | null> {
    const session = this.sessionKeys.get(peerId);
    if (!session || session.expires < Date.now()) {
      return null;
    }
    return session.key;
  }

  public async addPeer(peerId: string, publicKey: string, trustScore: number = 50): Promise<void> {
    this.peerKeys.set(peerId, publicKey);
    this.peerTrustScores.set(peerId, trustScore);
  }

  public async updateTrustScore(peerId: string, delta: number): Promise<number> {
    const currentScore = this.peerTrustScores.get(peerId) || 50;
    const newScore = Math.max(0, Math.min(100, currentScore + delta));
    this.peerTrustScores.set(peerId, newScore);
    return newScore;
  }

  public async signData(data: string | Buffer): Promise<string> {
    const sign = createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(this.keyPair.privateKey, 'base64');
  }

  public async verifySignature(data: string | Buffer, signature: string, publicKey: string): Promise<boolean> {
    const verify = createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
  }

  public async encryptForPeer(peerId: string, plaintext: string | Buffer): Promise<EncryptedData> {
    const peerPublicKey = this.peerKeys.get(peerId);
    if (!peerPublicKey) {
      throw new Error(`No public key found for peer ${peerId}`);
    }

    // Get or create session key
    let sessionKey = await this.getSessionKey(peerId);
    if (!sessionKey) {
      sessionKey = await this.generateSessionKey(peerId);
      // Encrypt session key with peer's public key
      // In a real implementation, this would use RSA-OAEP or similar
    }

    // Encrypt the data
    const iv = await randomBytesAsync(AICrypto.IV_LENGTH);
    const cipher = createCipheriv(AICrypto.ALGORITHM, sessionKey, iv, {
      authTagLength: AICrypto.AUTH_TAG_LENGTH
    });

    const plaintextBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
    const encrypted = Buffer.concat([
      cipher.update(plaintextBuffer),
      cipher.final()
    ]);

    const authTag = cipher.getAuthTag();
    
    // Create the encrypted data package
    const encryptedData: EncryptedData = {
      iv: iv.toString('base64'),
      ciphertext: encrypted.toString('base64'),
      authTag: authTag.toString('base64'),
      timestamp: Date.now(),
      keyId: this.keyPair.keyId
    };

    // Sign the encrypted data
    const signature = await this.signData(JSON.stringify({
      iv: encryptedData.iv,
      ciphertext: encryptedData.ciphertext,
      authTag: encryptedData.authTag,
      timestamp: encryptedData.timestamp,
      keyId: encryptedData.keyId
    }));

    encryptedData.signature = signature;
    return encryptedData;
  }

  public async decryptFromPeer(peerId: string, encryptedData: EncryptedData): Promise<Buffer> {
    // Verify the signature
    const peerPublicKey = this.peerKeys.get(peerId);
    if (!peerPublicKey) {
      throw new Error(`No public key found for peer ${peerId}`);
    }

    // Verify the signature
    const signature = encryptedData.signature;
    if (!signature) {
      throw new Error('No signature provided');
    }

    const { signature: _, ...dataToVerify } = encryptedData;
    const isVerified = await this.verifySignature(
      JSON.stringify(dataToVerify),
      signature,
      peerPublicKey
    );

    if (!isVerified) {
      throw new Error('Invalid signature');
    }

    // Get session key
    const sessionKey = await this.getSessionKey(peerId);
    if (!sessionKey) {
      throw new Error('No active session with this peer');
    }

    // Decrypt the data
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const encryptedText = Buffer.from(encryptedData.ciphertext, 'base64');
    const authTag = Buffer.from(encryptedData.authTag, 'base64');
    
    const decipher = createDecipheriv(AICrypto.ALGORITHM, sessionKey, iv, {
      authTagLength: AICrypto.AUTH_TAG_LENGTH
    });
    
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final()
    ]);
    
    return decrypted;
  }

  // AI-powered anomaly detection
  public async detectAnomalies(data: any, peerId: string): Promise<{ isAnomaly: boolean; score: number; reason?: string }> {
    const trustScore = this.peerTrustScores.get(peerId) || 50;
    
    // Simple anomaly detection based on data size and frequency
    // In a real implementation, this would use machine learning
    const dataSize = Buffer.byteLength(JSON.stringify(data));
    const currentTime = Date.now();
    
    // Check for unusually large messages
    if (dataSize > 1024 * 1024) { // 1MB
      await this.updateTrustScore(peerId, -10);
      return { 
        isAnomaly: true, 
        score: trustScore - 10,
        reason: 'Message size exceeds limit'
      };
    }
    
    // Check for rapid message frequency (simplified)
    // In a real implementation, this would track message timestamps
    
    return { isAnomaly: false, score: trustScore };
  }

  // AI-powered traffic analysis
  public async analyzeTraffic(peerId: string, messageCount: number, byteCount: number): Promise<void> {
    // In a real implementation, this would analyze traffic patterns
    // and adjust trust scores accordingly
    const trustDelta = this.calculateTrustDelta(messageCount, byteCount);
    await this.updateTrustScore(peerId, trustDelta);
  }

  private calculateTrustDelta(messageCount: number, byteCount: number): number {
    // Simple heuristic - in a real implementation, this would be more sophisticated
    const avgMessageSize = byteCount / Math.max(1, messageCount);
    
    if (avgMessageSize > 1024 * 10) { // 10KB
      return -5;
    } else if (avgMessageSize < 100) { // 100B
      return -2;
    }
    
    return 1; // Slight positive for normal traffic
  }

  // Static helper methods
  static async generateKey(): Promise<Buffer> {
    return randomBytesAsync(this.KEY_LENGTH);
  }

  static async deriveKey(
    password: string,
    salt: Buffer = randomBytes(16),
    iterations: number = 100000,
    keylen: number = 32,
    digest: string = 'sha256'
  ): Promise<{ key: Buffer; salt: Buffer }> {
    return new Promise((resolve, reject) => {
      const derivedKey = createHash(digest)
        .update(password + salt.toString('hex'))
        .digest();
      
      resolve({
        key: derivedKey,
        salt
      });
    });
  }
}

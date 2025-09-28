/**
 * Crypto utilities for end-to-end encryption
 * Uses Web Crypto API for cryptographic operations
 */

export const generateKeyPair = async () => {
  try {
    // Generate ECDH key pair for key exchange
    const ecdhKeyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );

    // Generate signing key pair
    const signingKeyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    );

    // Generate AES key for message encryption
    const aesKey = await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );

    // Export public keys for sharing
    const [ecdhPublicKey, signingPublicKey, aesKeyData] = await Promise.all([
      window.crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey),
      window.crypto.subtle.exportKey('jwk', signingKeyPair.publicKey),
      window.crypto.subtle.exportKey('raw', aesKey)
    ]);

    return {
      privateKey: { ecdh: ecdhKeyPair.privateKey, signing: signingKeyPair.privateKey, aesKey },
      publicKey: { ecdh: ecdhKeyPair.publicKey, signing: signingKeyPair.publicKey },
      publicKeyData: {
        ecdh: ecdhPublicKey,
        signing: signingPublicKey,
        aesKey: Array.from(new Uint8Array(aesKeyData))
      }
    };
  } catch (error) {
    console.error('Error generating key pair:', error);
    throw error;
  }
};

export const deriveSharedSecret = async (privateKey, publicKey) => {
  try {
    return await window.crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: publicKey,
      },
      privateKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    console.error('Error deriving shared secret:', error);
    throw error;
  }
};

export const encryptMessage = async (message, privateKey, recipientPublicKey) => {
  try {
    // Convert message to ArrayBuffer
    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(message));

    // Generate IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Import recipient's public key
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      recipientPublicKey,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      []
    );

    // Derive shared secret
    const sharedSecret = await deriveSharedSecret(privateKey.ecdh, publicKey);

    // Encrypt the message
    const encryptedData = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      sharedSecret,
      data
    );

    // Combine IV and encrypted data
    const result = new Uint8Array(iv.length + encryptedData.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encryptedData), iv.length);

    return result;
  } catch (error) {
    console.error('Error encrypting message:', error);
    throw error;
  }
};

export const decryptMessage = async (encryptedData, privateKey, senderPublicKey) => {
  try {
    // Extract IV and encrypted data
    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);

    // Import sender's public key
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      senderPublicKey,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      []
    );

    // Derive shared secret
    const sharedSecret = await deriveSharedSecret(privateKey.ecdh, publicKey);

    // Decrypt the message
    const decryptedData = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128,
      },
      sharedSecret,
      data
    );

    // Convert back to string
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedData));
  } catch (error) {
    console.error('Error decrypting message:', error);
    throw error;
  }
};

export const signMessage = async (message, privateKey) => {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(message));
    
    const signature = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      privateKey.signing,
      data
    );

    return Array.from(new Uint8Array(signature));
  } catch (error) {
    console.error('Error signing message:', error);
    throw error;
  }
};

export const verifySignature = async (message, signature, publicKey) => {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(message));
    
    const key = await window.crypto.subtle.importKey(
      'jwk',
      publicKey.signing,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['verify']
    );

    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      key,
      new Uint8Array(signature),
      data
    );
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
};

// Helper function to convert between string and ArrayBuffer
const toBuffer = (str) => {
  const encoder = new TextEncoder();
  return encoder.encode(str);
};

const fromBuffer = (buffer) => {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
};

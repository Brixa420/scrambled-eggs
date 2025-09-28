import { kem, sign } from 'liboqs-node';

class PostQuantum {
  constructor() {
    this.supportedKEMs = [
      'Kyber512', 'Kyber768', 'Kyber1024',
      'FrodoKEM-640-AES', 'FrodoKEM-976-AES', 'FrodoKEM-1344-AES'
    ];
    
    this.supportedSignatures = [
      'Dilithium2', 'Dilithium3', 'Dilithium5',
      'Falcon-512', 'Falcon-1024'
    ];
    
    this.defaultKEM = 'Kyber768';
    this.defaultSig = 'Dilithium3';
  }
  
  async generateKeyPair(algorithm = this.defaultKEM) {
    if (!this.supportedKEMs.includes(algorithm)) {
      throw new Error(`Unsupported KEM algorithm: ${algorithm}`);
    }
    
    try {
      const kemInstance = new kem.Kyber(algorithm);
      const keyPair = await kemInstance.keypair();
      
      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        algorithm,
        created: new Date()
      };
    } catch (error) {
      console.error('Error generating PQ keypair:', error);
      throw error;
    }
  }
  
  async generateSignatureKeyPair(algorithm = this.defaultSig) {
    if (!this.supportedSignatures.includes(algorithm)) {
      throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
    
    try {
      const signer = new sign.Dilithium(algorithm);
      const keyPair = await signer.keypair();
      
      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        algorithm,
        created: new Date()
      };
    } catch (error) {
      console.error('Error generating signature keypair:', error);
      throw error;
    }
  }
  
  async encapsulate(publicKey, algorithm = this.defaultKEM) {
    try {
      const kemInstance = new kem.Kyber(algorithm);
      const result = await kemInstance.encapsulate(publicKey);
      
      return {
        ciphertext: result.ciphertext,
        sharedSecret: result.sharedSecret
      };
    } catch (error) {
      console.error('Error in key encapsulation:', error);
      throw error;
    }
  }
  
  async decapsulate(ciphertext, privateKey, algorithm = this.defaultKEM) {
    try {
      const kemInstance = new kem.Kyber(algorithm);
      return await kemInstance.decapsulate(ciphertext, privateKey);
    } catch (error) {
      console.error('Error in key decapsulation:', error);
      throw error;
    }
  }
  
  async sign(message, privateKey, algorithm = this.defaultSig) {
    try {
      const signer = new sign.Dilithium(algorithm);
      return await signer.sign(message, privateKey);
    } catch (error) {
      console.error('Error signing message:', error);
      throw error;
    }
  }
  
  async verify(message, signature, publicKey, algorithm = this.defaultSig) {
    try {
      const signer = new sign.Dilithium(algorithm);
      return await signer.verify(message, signature, publicKey);
    } catch (error) {
      console.error('Error verifying signature:', error);
      return false;
    }
  }
}

export const postQuantum = new PostQuantum();

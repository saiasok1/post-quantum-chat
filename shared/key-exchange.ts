import { CryptoService, KEMAlgorithm, SignatureService, SignatureAlgorithm } from "./crypto-service";

export interface KeyExchangeSession {
  id: string;
  kemAlgorithm: KEMAlgorithm;
  signatureAlgorithm: SignatureAlgorithm;
  ourKeyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  theirPublicKey?: Uint8Array;
  sharedSecret?: Uint8Array;
  status: "initiated" | "key-sent" | "key-received" | "completed";
  timestamp: number;
}

export class KeyExchangeManager {
  private sessions: Map<string, KeyExchangeSession> = new Map();

  // Initiate a key exchange with specified algorithms
  initiateKeyExchange(
    sessionId: string,
    kemAlgorithm: KEMAlgorithm = KEMAlgorithm.ML_KEM_768,
    signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65
  ): KeyExchangeSession {
    const provider = CryptoService.getProvider(kemAlgorithm);
    const keyPair = provider.generateKeyPair();

    const session: KeyExchangeSession = {
      id: sessionId,
      kemAlgorithm,
      signatureAlgorithm,
      ourKeyPair: keyPair,
      status: "initiated",
      timestamp: Date.now()
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  // Send our public key to peer
  sendPublicKey(sessionId: string): {
    publicKey: string;
    kemAlgorithm: string;
    signatureAlgorithm: string;
  } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    session.status = "key-sent";
    
    return {
      publicKey: Buffer.from(session.ourKeyPair.publicKey).toString('base64'),
      kemAlgorithm: session.kemAlgorithm,
      signatureAlgorithm: session.signatureAlgorithm
    };
  }

  // Receive peer's public key and complete key exchange
  receivePublicKey(
    sessionId: string,
    theirPublicKeyB64: string,
    theirKemAlgorithm: string,
    theirSignatureAlgorithm: string
  ): {
    ciphertext: string;
    sharedSecret: Uint8Array;
  } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    // Verify algorithm compatibility
    if (theirKemAlgorithm !== session.kemAlgorithm) {
      throw new Error(`KEM algorithm mismatch: ${theirKemAlgorithm} vs ${session.kemAlgorithm}`);
    }

    const theirPublicKey = Buffer.from(theirPublicKeyB64, 'base64');
    session.theirPublicKey = theirPublicKey;

    // Encapsulate to create shared secret
    const provider = CryptoService.getProvider(session.kemAlgorithm);
    const encapsulation = provider.encapsulate(theirPublicKey);
    
    session.sharedSecret = encapsulation.sharedSecret;
    session.status = "completed";

    return {
      ciphertext: Buffer.from(encapsulation.ciphertext).toString('base64'),
      sharedSecret: encapsulation.sharedSecret
    };
  }

  // Receive ciphertext and derive shared secret (for the key sender)
  receiveCiphertext(sessionId: string, ciphertextB64: string): Uint8Array {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    const ciphertext = Buffer.from(ciphertextB64, 'base64');
    const provider = CryptoService.getProvider(session.kemAlgorithm);
    
    session.sharedSecret = provider.decapsulate(ciphertext, session.ourKeyPair.privateKey);
    session.status = "completed";

    return session.sharedSecret;
  }

  // Get session info
  getSession(sessionId: string): KeyExchangeSession | undefined {
    return this.sessions.get(sessionId);
  }

  // List all sessions
  getAllSessions(): KeyExchangeSession[] {
    return Array.from(this.sessions.values());
  }

  // Clean up old sessions
  cleanupOldSessions(maxAgeMs: number = 24 * 60 * 60 * 1000): void {
    const now = Date.now();
    for (const [id, session] of Array.from(this.sessions.entries())) {
      if (now - session.timestamp > maxAgeMs) {
        this.sessions.delete(id);
      }
    }
  }

  // Get supported algorithms
  static getSupportedKEMAlgorithms(): KEMAlgorithm[] {
    return CryptoService.getSupportedAlgorithms();
  }

  static getAlgorithmInfo(algorithm: KEMAlgorithm) {
    return CryptoService.getAlgorithmInfo(algorithm);
  }
}

// Utility functions for message encryption using derived shared secrets
export class MessageCrypto {
  static async encryptMessage(message: string, sharedSecret: Uint8Array): Promise<string> {
    // Simple XOR encryption for demo - in production use AES-GCM
    const messageBytes = new TextEncoder().encode(message);
    const encrypted = new Uint8Array(messageBytes.length);
    
    for (let i = 0; i < messageBytes.length; i++) {
      encrypted[i] = messageBytes[i] ^ sharedSecret[i % sharedSecret.length];
    }
    
    return Buffer.from(encrypted).toString('base64');
  }

  static async decryptMessage(encryptedB64: string, sharedSecret: Uint8Array): Promise<string> {
    const encrypted = Buffer.from(encryptedB64, 'base64');
    const decrypted = new Uint8Array(encrypted.length);
    
    for (let i = 0; i < encrypted.length; i++) {
      decrypted[i] = encrypted[i] ^ sharedSecret[i % sharedSecret.length];
    }
    
    return new TextDecoder().decode(decrypted);
  }
}
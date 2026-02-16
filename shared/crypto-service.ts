import { ml_kem768, ml_kem512, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65, ml_dsa44, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

// Supported KEM algorithms
export enum KEMAlgorithm {
  ML_KEM_512 = "ml-kem-512",
  ML_KEM_768 = "ml-kem-768", 
  ML_KEM_1024 = "ml-kem-1024"
}

// Supported signature algorithms
export enum SignatureAlgorithm {
  ML_DSA_44 = "ml-dsa-44",
  ML_DSA_65 = "ml-dsa-65",
  ML_DSA_87 = "ml-dsa-87"
}

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export interface CryptoProvider {
  generateKeyPair(): KeyPair;
  encapsulate(publicKey: Uint8Array): EncapsulationResult;
  decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Uint8Array;
  getPublicKeySize(): number;
  getPrivateKeySize(): number;
  getCiphertextSize(): number;
  getSharedSecretSize(): number;
}

// Noble ML-KEM implementations
class NobleMLKEM512Provider implements CryptoProvider {
  generateKeyPair(): KeyPair {
    const keyPair = ml_kem512.keygen();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey
    };
  }

  encapsulate(publicKey: Uint8Array): EncapsulationResult {
    const result = ml_kem512.encapsulate(publicKey);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  }

  decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return ml_kem512.decapsulate(ciphertext, privateKey);
  }

  getPublicKeySize(): number { return 800; }
  getPrivateKeySize(): number { return 1632; }
  getCiphertextSize(): number { return 768; }
  getSharedSecretSize(): number { return 32; }
}

class NobleMLKEM768Provider implements CryptoProvider {
  generateKeyPair(): KeyPair {
    const keyPair = ml_kem768.keygen();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey
    };
  }

  encapsulate(publicKey: Uint8Array): EncapsulationResult {
    const result = ml_kem768.encapsulate(publicKey);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  }

  decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return ml_kem768.decapsulate(ciphertext, privateKey);
  }

  getPublicKeySize(): number { return 1184; }
  getPrivateKeySize(): number { return 2400; }
  getCiphertextSize(): number { return 1088; }
  getSharedSecretSize(): number { return 32; }
}

class NobleMLKEM1024Provider implements CryptoProvider {
  generateKeyPair(): KeyPair {
    const keyPair = ml_kem1024.keygen();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey
    };
  }

  encapsulate(publicKey: Uint8Array): EncapsulationResult {
    const result = ml_kem1024.encapsulate(publicKey);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  }

  decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return ml_kem1024.decapsulate(ciphertext, privateKey);
  }

  getPublicKeySize(): number { return 1568; }
  getPrivateKeySize(): number { return 3168; }
  getCiphertextSize(): number { return 1568; }
  getSharedSecretSize(): number { return 32; }
}



// Factory for creating crypto providers
export class CryptoService {
  private static providers: Map<KEMAlgorithm, () => CryptoProvider> = new Map([
    [KEMAlgorithm.ML_KEM_512, () => new NobleMLKEM512Provider()],
    [KEMAlgorithm.ML_KEM_768, () => new NobleMLKEM768Provider()],
    [KEMAlgorithm.ML_KEM_1024, () => new NobleMLKEM1024Provider()]
  ]);

  static getProvider(algorithm: KEMAlgorithm): CryptoProvider {
    const providerFactory = this.providers.get(algorithm);
    if (!providerFactory) {
      throw new Error(`Unsupported KEM algorithm: ${algorithm}`);
    }
    return providerFactory();
  }

  static getSupportedAlgorithms(): KEMAlgorithm[] {
    return Array.from(this.providers.keys());
  }

  static getAlgorithmInfo(algorithm: KEMAlgorithm): {
    name: string;
    securityLevel: number;
    description: string;
  } {
    const info = {
      [KEMAlgorithm.ML_KEM_512]: {
        name: "ML-KEM-512",
        securityLevel: 128,
        description: "NIST standardized Kyber-512 (128-bit security)"
      },
      [KEMAlgorithm.ML_KEM_768]: {
        name: "ML-KEM-768", 
        securityLevel: 192,
        description: "NIST standardized Kyber-768 (192-bit security)"
      },
      [KEMAlgorithm.ML_KEM_1024]: {
        name: "ML-KEM-1024",
        securityLevel: 256, 
        description: "NIST standardized Kyber-1024 (256-bit security)"
      },

    };

    return info[algorithm];
  }
}

// Signature service with multiple ML-DSA variants
export class SignatureService {
  static sign(message: Uint8Array, privateKey: Uint8Array, algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65): Uint8Array {
    switch (algorithm) {
      case SignatureAlgorithm.ML_DSA_44:
        return ml_dsa44.sign(privateKey, message);
      case SignatureAlgorithm.ML_DSA_65:
        return ml_dsa65.sign(privateKey, message);
      case SignatureAlgorithm.ML_DSA_87:
        return ml_dsa87.sign(privateKey, message);
      default:
        throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
  }

  static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array, algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65): boolean {
    switch (algorithm) {
      case SignatureAlgorithm.ML_DSA_44:
        return ml_dsa44.verify(publicKey, message, signature);
      case SignatureAlgorithm.ML_DSA_65:
        return ml_dsa65.verify(publicKey, message, signature);
      case SignatureAlgorithm.ML_DSA_87:
        return ml_dsa87.verify(publicKey, message, signature);
      default:
        throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
  }

  static generateKeyPair(algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65): { publicKey: Uint8Array; privateKey: Uint8Array } {
    let keyPair;
    switch (algorithm) {
      case SignatureAlgorithm.ML_DSA_44:
        keyPair = ml_dsa44.keygen();
        break;
      case SignatureAlgorithm.ML_DSA_65:
        keyPair = ml_dsa65.keygen();
        break;
      case SignatureAlgorithm.ML_DSA_87:
        keyPair = ml_dsa87.keygen();
        break;
      default:
        throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
    
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey
    };
  }
}
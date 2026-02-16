import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import type { PQCKeyPair } from '@shared/schema';

// Helper to handle both WebCrypto (ArrayBuffer) and PQC (Uint8Array)
function toUint8Array(data: BufferSource): Uint8Array {
    if (data instanceof Uint8Array) return data;
    return new Uint8Array(data as ArrayBuffer);
}

export type KemAlgorithm =
    | "ml-kem-512" | "ml-kem-768" | "ml-kem-1024"
    | "kyber-512" | "kyber-768" | "kyber-1024"
    | "rsa-2048" | "rsa-4096"
    | "ecdh-p256" | "ecdh-p384";

export type SignatureAlgorithm =
    | "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87"
    | "rsa-pss-2048" | "rsa-pss-4096"
    | "ecdsa-p256" | "ecdsa-p384";

export class CryptoEngine {
    // PQC State
    private pqcKemKey: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private pqcDsaKey: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;

    // Classical State (WebCrypto)
    private webCryptoKemKey: CryptoKeyPair | null = null; // RSA or ECDH
    private webCryptoSignKey: CryptoKeyPair | null = null; // RSA-PSS or ECDSA

    // Shared Secret State
    private sharedSecret: Uint8Array | null = null;
    private keyExchangeInProgress: boolean = false;

    // Configuration
    private currentKemAlgorithm: KemAlgorithm = "ml-kem-768";
    private currentSignatureAlgorithm: SignatureAlgorithm = "ml-dsa-65";

    constructor() { }

    // --- Core Methods ---

    async generateKEMKeyPair(algorithm: KemAlgorithm): Promise<PQCKeyPair> {
        this.currentKemAlgorithm = algorithm;
        console.log(`🔑 Generating KEM keypair: ${algorithm}`);

        // Post-Quantum
        if (algorithm.startsWith("ml-kem") || algorithm.startsWith("kyber")) {
            switch (algorithm) {
                case "ml-kem-512": case "kyber-512": this.pqcKemKey = ml_kem512.keygen(); break;
                case "ml-kem-768": case "kyber-768": this.pqcKemKey = ml_kem768.keygen(); break;
                case "ml-kem-1024": case "kyber-1024": this.pqcKemKey = ml_kem1024.keygen(); break;
            }
            this.webCryptoKemKey = null;

            return {
                publicKey: this.arrayToHex(this.pqcKemKey!.publicKey),
                privateKey: this.arrayToHex(this.pqcKemKey!.secretKey),
                kemAlgorithm: algorithm,
                signatureAlgorithm: this.currentSignatureAlgorithm,
                timestamp: Date.now(),
            };
        }

        // RSA
        if (algorithm.startsWith("rsa")) {
            const modulusLength = algorithm.includes("4096") ? 4096 : 2048;
            this.webCryptoKemKey = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength,
                    publicExponent: new Uint8Array([1, 0, 1]) as any,
                    hash: "SHA-256",
                },
                true,
                ["encrypt", "decrypt"]
            );
            this.pqcKemKey = null;

            const pubExport = await window.crypto.subtle.exportKey("spki", this.webCryptoKemKey.publicKey);
            const privExport = await window.crypto.subtle.exportKey("pkcs8", this.webCryptoKemKey.privateKey);

            return {
                publicKey: this.arrayToHex(new Uint8Array(pubExport)),
                privateKey: this.arrayToHex(new Uint8Array(privExport)),
                kemAlgorithm: algorithm,
                signatureAlgorithm: this.currentSignatureAlgorithm,
                timestamp: Date.now(),
            };
        }

        // ECDH
        if (algorithm.startsWith("ecdh")) {
            const namedCurve = algorithm.includes("p384") ? "P-384" : "P-256";
            this.webCryptoKemKey = await window.crypto.subtle.generateKey(
                { name: "ECDH", namedCurve },
                true,
                ["deriveKey", "deriveBits"]
            );
            this.pqcKemKey = null;

            const pubExport = await window.crypto.subtle.exportKey("raw", this.webCryptoKemKey.publicKey);
            const privExport = await window.crypto.subtle.exportKey("pkcs8", this.webCryptoKemKey.privateKey);

            return {
                publicKey: this.arrayToHex(new Uint8Array(pubExport)),
                privateKey: this.arrayToHex(new Uint8Array(privExport)),
                kemAlgorithm: algorithm,
                signatureAlgorithm: this.currentSignatureAlgorithm,
                timestamp: Date.now(),
            };
        }

        throw new Error(`Unsupported KEM algorithm: ${algorithm}`);
    }

    async generateDSAKeyPair(algorithm: SignatureAlgorithm): Promise<PQCKeyPair> {
        this.currentSignatureAlgorithm = algorithm;
        console.log(`🔑 Generating DSA keypair: ${algorithm}`);

        // Post-Quantum
        if (algorithm.startsWith("ml-dsa")) {
            switch (algorithm) {
                case "ml-dsa-44": this.pqcDsaKey = ml_dsa44.keygen(); break;
                case "ml-dsa-65": this.pqcDsaKey = ml_dsa65.keygen(); break;
                case "ml-dsa-87": this.pqcDsaKey = ml_dsa87.keygen(); break;
            }
            this.webCryptoSignKey = null;

            return {
                publicKey: this.arrayToHex(this.pqcDsaKey!.publicKey),
                privateKey: this.arrayToHex(this.pqcDsaKey!.secretKey),
                kemAlgorithm: this.currentKemAlgorithm,
                signatureAlgorithm: algorithm,
                timestamp: Date.now(),
            };
        }

        // RSA-PSS
        if (algorithm.startsWith("rsa-pss")) {
            const modulusLength = algorithm.includes("4096") ? 4096 : 2048;
            this.webCryptoSignKey = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength,
                    publicExponent: new Uint8Array([1, 0, 1]) as any,
                    hash: "SHA-256",
                },
                true,
                ["sign", "verify"]
            );
            this.pqcDsaKey = null;

            const pubExport = await window.crypto.subtle.exportKey("spki", this.webCryptoSignKey.publicKey);
            const privExport = await window.crypto.subtle.exportKey("pkcs8", this.webCryptoSignKey.privateKey);

            return {
                publicKey: this.arrayToHex(new Uint8Array(pubExport)),
                privateKey: this.arrayToHex(new Uint8Array(privExport)),
                kemAlgorithm: this.currentKemAlgorithm,
                signatureAlgorithm: algorithm,
                timestamp: Date.now(),
            };
        }

        // ECDSA
        if (algorithm.startsWith("ecdsa")) {
            const namedCurve = algorithm.includes("p384") ? "P-384" : "P-256";
            this.webCryptoSignKey = await window.crypto.subtle.generateKey(
                { name: "ECDSA", namedCurve },
                true,
                ["sign", "verify"]
            );
            this.pqcDsaKey = null;

            const pubExport = await window.crypto.subtle.exportKey("spki", this.webCryptoSignKey.publicKey); // ECDSA uses SPKI not Raw usually for storage, but raw is easier for keys. sticking to SPKI for standard.
            // Actually raw p256 is 65 bytes. SPKI is larger. Let's use SPKI to be safe and consistent with RSA.
            const privExport = await window.crypto.subtle.exportKey("pkcs8", this.webCryptoSignKey.privateKey);

            return {
                publicKey: this.arrayToHex(new Uint8Array(pubExport)),
                privateKey: this.arrayToHex(new Uint8Array(privExport)),
                kemAlgorithm: this.currentKemAlgorithm,
                signatureAlgorithm: algorithm,
                timestamp: Date.now(),
            };
        }

        throw new Error(`Unsupported Signature algorithm: ${algorithm}`);
    }

    // --- KEM (Encapsulate / Decapsulate) ---

    async encapsulate(peerPublicKeyHex: string, algOverride?: KemAlgorithm): Promise<{ ciphertext: string; sharedSecret: Uint8Array }> {
        if (this.keyExchangeInProgress) throw new Error('Key exchange already in progress');
        this.keyExchangeInProgress = true;

        const algorithm = algOverride || this.currentKemAlgorithm;
        console.log(`🔒 Encapsulating for ${algorithm}, key len: ${peerPublicKeyHex.length / 2}`);

        const publicKeyBytes = this.hexToArray(peerPublicKeyHex);

        try {
            // PQC
            if (algorithm.startsWith("ml-kem") || algorithm.startsWith("kyber")) {
                let result;
                switch (algorithm) {
                    case "ml-kem-512": case "kyber-512": result = ml_kem512.encapsulate(publicKeyBytes); break;
                    case "ml-kem-768": case "kyber-768": result = ml_kem768.encapsulate(publicKeyBytes); break;
                    case "ml-kem-1024": case "kyber-1024": result = ml_kem1024.encapsulate(publicKeyBytes); break;
                    default: throw new Error("Unknown PQC algo");
                }
                // noble-post-quantum v0.2.0 uses 'ciphertext' (lowercase) or 'cipherText' depending on specific build/version nuances.
                // We cast to any to safe-check both.
                const res = result as any;
                const ct = res.cipherText || res.ciphertext;
                if (!ct) {
                    console.error("PQC Encapsulate result missing ciphertext:", res);
                    throw new Error("PQC Encapsulation failed or returned unexpected format");
                }

                this.sharedSecret = result.sharedSecret;
                return { ciphertext: this.arrayToHex(ct), sharedSecret: result.sharedSecret };
            }

            // RSA-OAEP
            if (algorithm.startsWith("rsa")) {
                // Import peer key
                const peerKey = await window.crypto.subtle.importKey(
                    "spki", publicKeyBytes as any,
                    { name: "RSA-OAEP", hash: "SHA-256" },
                    false, ["encrypt"]
                );

                // Generate Random Shared Secret (32 bytes for AES-256)
                const secret = window.crypto.getRandomValues(new Uint8Array(32));
                this.sharedSecret = secret;

                // Encrypt secret with peer key
                const ciphertextBuf = await window.crypto.subtle.encrypt(
                    { name: "RSA-OAEP" },
                    peerKey,
                    secret
                );

                return {
                    ciphertext: this.arrayToHex(new Uint8Array(ciphertextBuf)),
                    sharedSecret: secret
                };
            }

            // ECDH
            if (algorithm.startsWith("ecdh")) {
                const namedCurve = algorithm.includes("p384") ? "P-384" : "P-256";

                // Import Peer Key
                // Note: For ECDH 'raw' format is often used for compact keys, but I used spki/raw above.
                // Let's assume 'raw' for ECDH public keys if they are 65 bytes (P256) or 97 (P384), 
                // but 'spki' is safer generic.
                const peerKey = await window.crypto.subtle.importKey(
                    "raw", publicKeyBytes as any,
                    { name: "ECDH", namedCurve },
                    false, []
                );

                // Generate Ephemeral Key Pair for "Encapsulation"
                const ephemeralKeyPair = await window.crypto.subtle.generateKey(
                    { name: "ECDH", namedCurve },
                    false, ["deriveBits"]
                );

                // Derive Shared Bits
                const sharedBits = await window.crypto.subtle.deriveBits(
                    { name: "ECDH", public: peerKey },
                    ephemeralKeyPair.privateKey,
                    256
                );

                this.sharedSecret = new Uint8Array(sharedBits);

                // Ciphertext is the Ephemeral Public Key
                const ephPubExport = await window.crypto.subtle.exportKey("raw", ephemeralKeyPair.publicKey);

                return {
                    ciphertext: this.arrayToHex(new Uint8Array(ephPubExport)),
                    sharedSecret: this.sharedSecret
                };
            }

            throw new Error(`Unknown KEM algo for encapsulation: ${algorithm}`);
        } finally {
            this.keyExchangeInProgress = false;
        }
    }

    async decapsulate(ciphertextHex: string): Promise<Uint8Array> {
        if (this.keyExchangeInProgress) throw new Error('Key exchange already in progress');
        this.keyExchangeInProgress = true;
        const ciphertextBytes = this.hexToArray(ciphertextHex);

        try {
            // PQC
            if (this.pqcKemKey) { // Implies a PQC algo is active and keys generated
                let result;
                // We must use the key's algo, but currentKemAlgorithm tracks it.
                switch (this.currentKemAlgorithm) {
                    case "ml-kem-512": case "kyber-512": result = ml_kem512.decapsulate(ciphertextBytes, this.pqcKemKey.secretKey); break;
                    case "ml-kem-768": case "kyber-768": result = ml_kem768.decapsulate(ciphertextBytes, this.pqcKemKey.secretKey); break;
                    case "ml-kem-1024": case "kyber-1024": result = ml_kem1024.decapsulate(ciphertextBytes, this.pqcKemKey.secretKey); break;
                    default: throw new Error("Mismatch or unknown PQC algo");
                }
                this.sharedSecret = result;
                return result;
            }

            // WebCrypto
            if (this.webCryptoKemKey) {
                if (this.currentKemAlgorithm.startsWith("rsa")) {
                    // Decrypt ciphertext to get secret
                    const secretBuf = await window.crypto.subtle.decrypt(
                        { name: "RSA-OAEP" },
                        this.webCryptoKemKey.privateKey,
                        ciphertextBytes as any
                    );
                    this.sharedSecret = new Uint8Array(secretBuf);
                    return this.sharedSecret;
                }

                if (this.currentKemAlgorithm.startsWith("ecdh")) {
                    const namedCurve = this.currentKemAlgorithm.includes("p384") ? "P-384" : "P-256";
                    // Ciphertext IS the peer's ephemeral public key
                    const peerEphKey = await window.crypto.subtle.importKey(
                        "raw", ciphertextBytes as any,
                        { name: "ECDH", namedCurve },
                        false, []
                    );

                    const sharedBits = await window.crypto.subtle.deriveBits(
                        { name: "ECDH", public: peerEphKey },
                        this.webCryptoKemKey.privateKey,
                        256
                    );
                    this.sharedSecret = new Uint8Array(sharedBits);
                    return this.sharedSecret;
                }
            }

            throw new Error("No private key available for decapsulation");
        } finally {
            this.keyExchangeInProgress = false;
        }
    }

    // --- Sign / Verify ---

    async sign(message: string): Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);

        // PQC
        if (this.pqcDsaKey) {
            // Note: noble/post-quantum sign returns Uint8Array
            let signature;
            switch (this.currentSignatureAlgorithm) {
                case "ml-dsa-44": signature = ml_dsa44.sign(data, this.pqcDsaKey.secretKey); break;
                case "ml-dsa-65": signature = ml_dsa65.sign(data, this.pqcDsaKey.secretKey); break;
                case "ml-dsa-87": signature = ml_dsa87.sign(data, this.pqcDsaKey.secretKey); break;
                default: throw new Error("Unknown PQC Sign algo");
            }
            return this.arrayToHex(signature);
        }

        // WebCrypto
        if (this.webCryptoSignKey) {
            let algo: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
            if (this.currentSignatureAlgorithm.startsWith("rsa-pss")) {
                algo = { name: "RSA-PSS", saltLength: 32 };
            } else {
                algo = { name: "ECDSA", hash: { name: "SHA-256" } };
            }

            const signatureBuf = await window.crypto.subtle.sign(
                algo,
                this.webCryptoSignKey.privateKey,
                data
            );
            return this.arrayToHex(new Uint8Array(signatureBuf));
        }

        throw new Error("No signing key generated");
    }

    async verify(message: string, signatureHex: string, publicKeyHex: string): Promise<boolean> {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const signature = this.hexToArray(signatureHex);
        const publicKeyBytes = this.hexToArray(publicKeyHex);
        const alg = this.currentSignatureAlgorithm;

        // PQC
        if (alg.startsWith("ml-dsa")) {
            switch (alg) {
                case "ml-dsa-44": return ml_dsa44.verify(signature, data, publicKeyBytes);
                case "ml-dsa-65": return ml_dsa65.verify(signature, data, publicKeyBytes);
                case "ml-dsa-87": return ml_dsa87.verify(signature, data, publicKeyBytes);
            }
        }

        // WebCrypto
        if (alg.startsWith("rsa-pss")) {
            const key = await window.crypto.subtle.importKey(
                "spki", publicKeyBytes as any,
                { name: "RSA-PSS", hash: "SHA-256" },
                false, ["verify"]
            );
            return window.crypto.subtle.verify(
                { name: "RSA-PSS", saltLength: 32 },
                key,
                signature as any,
                data
            );
        }

        if (alg.startsWith("ecdsa")) {
            const namedCurve = alg.includes("p384") ? "P-384" : "P-256";
            const key = await window.crypto.subtle.importKey(
                "spki", publicKeyBytes as any, // We exported as SPKI for ECDSA
                { name: "ECDSA", namedCurve },
                false, ["verify"]
            );
            return window.crypto.subtle.verify(
                { name: "ECDSA", hash: { name: "SHA-256" } },
                key,
                signature as any,
                data
            );
        }

        return false;
    }

    // --- Symmetric Encryption (AES-GCM) ---

    async encrypt(message: string): Promise<string> {
        if (!this.sharedSecret) {
            console.error("❌ Encrypt called without shared secret");
            throw new Error('No shared secret established');
        }
        console.log(`🔒 Encrypting: Secret len=${this.sharedSecret.length}, Fingerprint=${this.arrayToHex(this.sharedSecret.slice(0, 4))}`);

        // Ensure 32 bytes for AES-256
        const keyMaterial = this.sharedSecret.slice(0, 32);
        const key = await window.crypto.subtle.importKey(
            'raw', keyMaterial as any, { name: 'AES-GCM' }, false, ['encrypt']
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        console.log(`🔒 IV: ${this.arrayToHex(iv)}`);

        const encoded = new TextEncoder().encode(message);

        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv as any }, key, encoded
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);

        const result = this.arrayToHex(combined);
        console.log(`🔒 Encrypted Result: ${result.substring(0, 20)}...`);
        return result;
    }

    async decrypt(encryptedHex: string): Promise<string> {
        if (!this.sharedSecret) {
            console.error("❌ Decrypt called without shared secret");
            throw new Error('No shared secret established');
        }
        console.log(`🔓 Decrypting: Input len=${encryptedHex.length}, Secret Fingerprint=${this.arrayToHex(this.sharedSecret.slice(0, 4))}`);

        const combined = this.hexToArray(encryptedHex);
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);

        console.log(`🔓 Extracted IV: ${this.arrayToHex(iv)}`);

        try {
            const keyMaterial = this.sharedSecret.slice(0, 32);
            const key = await window.crypto.subtle.importKey(
                'raw', keyMaterial as any, { name: 'AES-GCM' }, false, ['decrypt']
            );

            const decrypted = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv as any }, key, data as any
            );

            const result = new TextDecoder().decode(decrypted);
            console.log(`✅ Decrypted successfully: ${result.substring(0, 20)}...`);
            return result;
        } catch (e) {
            console.error("❌ Decryption internal failure:", e);
            throw e;
        }
    }

    // --- Utils & State ---

    reset(): void {
        console.log("🔄 Resetting Crypto Engine state");
        this.pqcKemKey = null;
        this.pqcDsaKey = null;
        this.webCryptoKemKey = null;
        this.webCryptoSignKey = null;
        this.sharedSecret = null;
        this.keyExchangeInProgress = false;
    }

    hasKeyPair(): boolean {
        return (this.pqcKemKey !== null || this.webCryptoKemKey !== null);
    }

    hasSharedSecret(): boolean {
        return this.sharedSecret !== null;
    }

    getKeyFingerprint(publicKeyHex: string): string {
        // Simple visual fingerprint
        if (!publicKeyHex) return "";
        const bytes = this.hexToArray(publicKeyHex);
        // Hash the key first to keep fingerprint short and uniformly distributed
        // We can't use async SHA-256 here easily in a sync method, so we'll just slice the bits if long,
        // or doing a sync cheap hash if needed.
        // For now, let's just show the first 16 bytes as hex groupings.
        const slice = bytes.slice(0, 16);
        const hash = Array.from(slice)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        return hash.match(/.{1,4}/g)?.join(':') || '';
    }

    private arrayToHex(arr: Uint8Array): string {
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    private hexToArray(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }
}

export const cryptoEngine = new CryptoEngine();

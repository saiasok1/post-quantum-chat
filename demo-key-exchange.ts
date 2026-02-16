import { KeyExchangeManager, MessageCrypto } from "./shared/key-exchange";
import { KEMAlgorithm, CryptoService } from "./shared/crypto-service";

async function demonstrateKeyExchange() {
  console.log("🔐 Post-Quantum Key Exchange Demo\n");

  // Show supported algorithms
  const supportedAlgorithms = KeyExchangeManager.getSupportedKEMAlgorithms();
  console.log("Supported KEM Algorithms:");
  supportedAlgorithms.forEach(alg => {
    const info = KeyExchangeManager.getAlgorithmInfo(alg);
    console.log(`  • ${info.name} (${info.securityLevel}-bit) - ${info.description}`);
  });
  console.log();

  // Test each supported algorithm
  for (const algorithm of supportedAlgorithms) {
    console.log(`\n--- Testing ${algorithm} ---`);

    try {
      // Alice initiates key exchange
      const alice = new KeyExchangeManager();
      const bob = new KeyExchangeManager();

      const sessionId = `session-${Date.now()}`;

      // Alice initiates with chosen algorithm
      const aliceSession = alice.initiateKeyExchange(sessionId, algorithm);
      console.log(`✓ Alice initiated session with ${algorithm}`);

      // Alice sends her public key
      const alicePublicKeyData = alice.sendPublicKey(sessionId);
      console.log(`✓ Alice sent public key (${alicePublicKeyData.publicKey.length} chars)`);

      // Bob receives Alice's public key and responds
      const bobSession = bob.initiateKeyExchange(sessionId, algorithm);
      const bobResponse = bob.receivePublicKey(
        sessionId,
        alicePublicKeyData.publicKey,
        alicePublicKeyData.kemAlgorithm,
        alicePublicKeyData.signatureAlgorithm
      );
      console.log(`✓ Bob received Alice's key and generated ciphertext`);

      // Alice receives Bob's ciphertext and derives shared secret
      const aliceSharedSecret = alice.receiveCiphertext(sessionId, bobResponse.ciphertext);
      console.log(`✓ Alice derived shared secret: ${Buffer.from(aliceSharedSecret).toString('hex').substring(0, 16)}...`);

      // Verify both have the same shared secret
      const bobSharedSecret = bobResponse.sharedSecret;
      const secretsMatch = Buffer.from(aliceSharedSecret).equals(Buffer.from(bobSharedSecret));
      console.log(`✓ Shared secrets match: ${secretsMatch}`);

      if (secretsMatch) {
        // Test message encryption
        const message = "Hello from Alice! This is encrypted with post-quantum crypto.";
        const encrypted = await MessageCrypto.encryptMessage(message, aliceSharedSecret);
        const decrypted = await MessageCrypto.decryptMessage(encrypted, bobSharedSecret);

        console.log(`✓ Message encryption test: ${message === decrypted ? 'PASSED' : 'FAILED'}`);
        console.log(`  Original: "${message}"`);
        console.log(`  Decrypted: "${decrypted}"`);
      }

      // Show algorithm performance info
      const provider = CryptoService.getProvider(algorithm);
      console.log(`  Key sizes: PK=${provider.getPublicKeySize()}B, SK=${provider.getPrivateKeySize()}B`);
      console.log(`  Ciphertext: ${provider.getCiphertextSize()}B, Secret: ${provider.getSharedSecretSize()}B`);

    } catch (error) {
      console.error(`❌ Error testing ${algorithm}:`, error.message);
    }
  }

  console.log("\n🎉 Key exchange demonstration complete!");
}

// Run the demo
demonstrateKeyExchange().catch(console.error);
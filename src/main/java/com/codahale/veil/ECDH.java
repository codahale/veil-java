package com.codahale.veil;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

class ECDH {

  static final String DH_ALG = "X448";
  private static final byte[] KDF_INFO = "veil".getBytes(StandardCharsets.UTF_8);

  static KeyPair generate() {
    try {
      var generator = KeyPairGenerator.getInstance(DH_ALG);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static byte[] sharedSecret(PrivateKey privateKey, PublicKey publicKey) {
    try {
      // calculate X448 secret
      var agreement = KeyAgreement.getInstance(DH_ALG);
      agreement.init(privateKey);
      agreement.doPhase(publicKey, true);
      var ikm = agreement.generateSecret();

      // use HKDF-SHA-512/256 to derive a key
      var hkdf = new HKDFBytesGenerator(new SHA512tDigest(256));
      hkdf.init(new HKDFParameters(ikm,null, KDF_INFO));
      var secret = new byte[AEAD.KEY_LEN];
      hkdf.generateBytes(secret, 0, AEAD.KEY_LEN);
      return secret;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException(e);
    }
  }
}

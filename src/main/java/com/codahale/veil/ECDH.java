package com.codahale.veil;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;

class ECDH {

  static final String DH_ALG = "X448";

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
      var agreement = KeyAgreement.getInstance(DH_ALG);
      agreement.init(privateKey);
      agreement.doPhase(publicKey, true);
      return agreement.generateSecret();
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException(e);
    }
  }
}

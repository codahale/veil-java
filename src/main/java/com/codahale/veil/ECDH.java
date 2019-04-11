package com.codahale.veil;

import com.google.common.io.ByteStreams;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
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
      generator.initialize(NamedParameterSpec.X448);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static byte[] sharedSecret(KeyPair keyPair, PublicKey publicKey, boolean sending) {
    // encode the sender and recipient's public keys as X.509
    var salt = ByteStreams.newDataOutput();
    if (sending) {
      salt.write(keyPair.getPublic().getEncoded());
      salt.write(publicKey.getEncoded());
    } else {
      salt.write(publicKey.getEncoded());
      salt.write(keyPair.getPublic().getEncoded());
    }

    try {
      // calculate X448 secret
      var agreement = KeyAgreement.getInstance(DH_ALG);
      agreement.init(keyPair.getPrivate());
      agreement.doPhase(publicKey, true);
      var ikm = agreement.generateSecret();

      // use HKDF-SHA-512/256 to derive a key, using the public keys as a salt
      var hkdf = new HKDFBytesGenerator(new SHA512tDigest(256));
      hkdf.init(new HKDFParameters(ikm, salt.toByteArray(), KDF_INFO));
      var secret = new byte[AEAD.KEY_LEN];
      hkdf.generateBytes(secret, 0, AEAD.KEY_LEN);
      return secret;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException(e);
    }
  }
}

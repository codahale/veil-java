/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.codahale.veil;

import com.google.common.io.ByteStreams;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class X448 {
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

  static byte[] sharedSecret(KeyPair keyPair, PublicKey publicKey, boolean sending) {
    try {
      // Calculate the X448 shared secret between the key pair's secret key and the given public
      // key. Per the security considerations of RFC 7748:
      //
      //   Protocol designers using Diffie-Hellman over the curves defined in
      //   this document must not assume "contributory behaviour".  Specially,
      //   contributory behaviour means that both parties' private keys
      //   contribute to the resulting shared key.  Since curve25519 and
      //   curve448 have cofactors of 8 and 4 (respectively), an input point of
      //   small order will eliminate any contribution from the other party's
      //   private key.  This situation can be detected by checking for the all-
      //   zero output, which implementations MAY do, as specified in Section 6.
      //   However, a large number of existing implementations do not do this.
      //
      // In this case, sun.security.ec.XDHKeyAgreement checks for an all-zero output and throws an
      // exception.
      var agreement = KeyAgreement.getInstance(DH_ALG);
      agreement.init(keyPair.getPrivate());
      agreement.doPhase(publicKey, true);
      var ikm = agreement.generateSecret();

      // Per security considerations of RFC 7748:
      //
      //    Designers using these curves should be aware that for each public
      //    key, there are several publicly computable public keys that are
      //    equivalent to it, i.e., they produce the same shared secrets.  Thus
      //    using a public key as an identifier and knowledge of a shared secret
      //    as proof of ownership (without including the public keys in the key
      //    derivation) might lead to subtle vulnerabilities.
      //
      // Here, we encode the sender and recipient's public keys as X.509 EC keys and use them as the
      // salt for HKDF, ensuring that the shared secret is unique to the sender/recipient pair.
      var salt = ByteStreams.newDataOutput();
      if (sending) {
        salt.write(keyPair.getPublic().getEncoded());
        salt.write(publicKey.getEncoded());
      } else {
        salt.write(publicKey.getEncoded());
        salt.write(keyPair.getPublic().getEncoded());
      }

      // Use HKDF-SHA-512/256 to derive a secret. HKDF was selected for its use of cryptographic
      // primitives already in use in Veil (HMAC, SHA-512/256) and for the fact that its design is
      // specific to key derivation from key material vs. passwords.
      return hkdf(ikm, salt.toByteArray());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  // an incredibly stripped-down implementation of HKDF per 5869, generating exactly 64 bytes of key
  static byte[] hkdf(byte[] ikm, byte[] salt) {
    try {
      var mac = Mac.getInstance(EtM.MAC_ALG);
      mac.init(new SecretKeySpec(salt, EtM.MAC_ALG));
      var prk = mac.doFinal(ikm);
      var okm = ByteStreams.newDataOutput();
      mac.init(new SecretKeySpec(prk, EtM.MAC_ALG));
      var digest = new byte[0];
      for (int i = 1; i <= 2; i++) {
        mac.update(digest);
        mac.update(KDF_INFO);
        mac.update((byte) i);
        digest = mac.doFinal();
        okm.write(digest);
      }
      return okm.toByteArray();
    } catch (GeneralSecurityException e) {
      throw new UnsupportedOperationException(e);
    }
  }
}

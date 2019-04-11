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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class Veil {

  static final int DIGEST_LEN = 32;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String DIGEST_ALG = "SHA-512/256";
  private final PrivateKey privateKey;

  public Veil(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public static KeyPair generate() {
    return ECDH.generate();
  }

  public static PrivateKey parsePrivateKey(byte[] pkcs8) throws InvalidKeySpecException {
    try {
      var spec = new PKCS8EncodedKeySpec(pkcs8, ECDH.DH_ALG);
      var factory = KeyFactory.getInstance(ECDH.DH_ALG);
      return factory.generatePrivate(spec);
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  public static PublicKey parsePublicKey(byte[] x509) throws InvalidKeySpecException {
    try {
      var spec = new X509EncodedKeySpec(x509, ECDH.DH_ALG);
      var factory = KeyFactory.getInstance(ECDH.DH_ALG);
      return factory.generatePublic(spec);
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  public byte[] encrypt(List<PublicKey> publicKeys, byte[] plaintext, int padding, int fakes) {
    // generate a random session key
    var sessionKey = random(AEAD.KEY_LEN);

    // generate random padding
    var pad = random(padding);

    // calculate a digest of the plaintext
    var digest = digest(plaintext);

    // create output buffer
    var out =
        ByteStreams.newDataOutput(
            publicKeys.size() * (Header.LEN + AEAD.OVERHEAD)
                + plaintext.length
                + padding
                + AEAD.OVERHEAD);

    // calculate where the message will end up in the ciphertext
    var messageOffset = (fakes + publicKeys.size()) * (Header.LEN + AEAD.OVERHEAD);

    // write headers
    for (var publicKey : addFakes(publicKeys, fakes)) {
      if (publicKey == null) {
        // just write a random header-length block for fake recipients
        out.write(random(Header.LEN + AEAD.OVERHEAD));
      } else {
        // generate, encrypt, and write header
        var sharedKey = ECDH.sharedSecret(privateKey, publicKey);
        var packet = new Header(sessionKey, messageOffset, plaintext.length, digest);
        out.write(AEAD.encrypt(sharedKey, packet.toByteArray(), null));
      }
    }
    var headers = out.toByteArray();

    // pad plaintext
    var padded = Arrays.copyOf(plaintext, plaintext.length + padding);
    System.arraycopy(pad, 0, padded, plaintext.length, pad.length);

    // encrypt with session key, using encrypted headers as data
    out.write(AEAD.encrypt(sessionKey, padded, headers));

    // headers + encrypted message
    return out.toByteArray();
  }

  public Optional<byte[]> decrypt(PublicKey publicKey, byte[] ciphertext) {
    // generate shared secret
    var sharedKey = ECDH.sharedSecret(privateKey, publicKey);

    // iterate through headers looking for one we can decrypt
    var header = findHeader(sharedKey, ciphertext);
    if (header == null) {
      return Optional.empty();
    }

    // read whole headers and encrypted message
    var headers = Arrays.copyOf(ciphertext, header.messageOffset());
    var encrypted = Arrays.copyOfRange(ciphertext, headers.length, ciphertext.length);

    // decrypt message using encrypted headers as authenticated data
    var padded = AEAD.decrypt(header.sessionKey(), encrypted, headers);
    if (padded == null) {
      return Optional.empty();
    }

    // remove padding
    var plaintext = Arrays.copyOf(padded, header.messageLen());

    // check digest
    if (!MessageDigest.isEqual(header.digest(), digest(plaintext))) {
      return Optional.empty();
    }

    // return authenticated plaintext
    return Optional.of(plaintext);
  }

  public Optional<Map.Entry<PublicKey, byte[]>> decrypt(
      List<PublicKey> publicKeys, byte[] ciphertext) {
    for (PublicKey publicKey : publicKeys) {
      var plaintext = decrypt(publicKey, ciphertext);
      if (plaintext.isPresent()) {
        return plaintext.map(b -> Map.entry(publicKey, b));
      }
    }
    return Optional.empty();
  }

  // create a list of real and fake recipients, shuffled with a SecureRandom
  private List<PublicKey> addFakes(List<PublicKey> publicKeys, int fakes) {
    var withFakes = new ArrayList<>(publicKeys);
    for (int i = 0; i < fakes; i++) {
      withFakes.add(null);
    }
    Collections.shuffle(withFakes, RANDOM);
    return withFakes;
  }

  private Header findHeader(byte[] key, byte[] ciphertext) {
    var buf = new byte[Header.LEN + AEAD.OVERHEAD];
    for (int i = 0; i < ciphertext.length - buf.length; i += buf.length) {
      System.arraycopy(ciphertext, i, buf, 0, buf.length);
      var decrypted = AEAD.decrypt(key, buf, null);
      if (decrypted != null) {
        return Header.parse(decrypted);
      }
    }
    return null;
  }

  static byte[] random(int size) {
    var buf = new byte[size];
    RANDOM.nextBytes(buf);
    return buf;
  }

  private static byte[] digest(byte[] message) {
    try {
      return MessageDigest.getInstance(DIGEST_ALG).digest(message);
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }
}

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
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
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

  static byte[] random(int size) {
    var buf = new byte[size];
    RANDOM.nextBytes(buf);
    return buf;
  }

  private static byte[] digest(byte[] message) {
    try {
      var digest = MessageDigest.getInstance(DIGEST_ALG);
      return digest.digest(message);
    } catch (NoSuchAlgorithmException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  public byte[] encrypt(List<PublicKey> publicKeys, byte[] plaintext, int padding) {
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

    // create encrypted header packets
    for (var publicKey : publicKeys) {
      var sharedKey = ECDH.sharedSecret(privateKey, publicKey);
      var packet = new Header(sessionKey, publicKeys.size(), plaintext.length, digest);
      out.write(AEAD.encrypt(sharedKey, packet.toByteArray(), new byte[0]));
    }
    var encryptedPackets = out.toByteArray();

    // pad plaintext
    var message = Arrays.copyOf(plaintext, plaintext.length + padding);
    System.arraycopy(pad, 0, message, plaintext.length, pad.length);

    // encrypt with session key, using encrypted header packets as data
    out.write(AEAD.encrypt(sessionKey, message, encryptedPackets));

    // header packets + encrypted message
    return out.toByteArray();
  }

  public Optional<byte[]> decrypt(PublicKey publicKey, byte[] ciphertext) {
    var in = ByteStreams.newDataInput(ciphertext);
    var sharedKey = ECDH.sharedSecret(privateKey, publicKey);

    // iterate through header packet-shaped things
    var headerBuf = new byte[Header.LEN + AEAD.OVERHEAD];
    Header header = null;
    while (header == null) {
      try {
        in.readFully(headerBuf);
      } catch (IllegalStateException e) {
        return Optional.empty();
      }

      var buf = AEAD.decrypt(sharedKey, headerBuf, new byte[0]);
      if (buf != null) {
        header = Header.parse(buf);
      }
    }

    // rewind to beginning of file
    in = ByteStreams.newDataInput(ciphertext);

    // read headers and encrypted message
    var headers = new byte[headerBuf.length * header.headerCount()];
    var encMessage = new byte[ciphertext.length - headers.length];
    in.readFully(headers);
    in.readFully(encMessage);

    // decrypt message
    var padded = AEAD.decrypt(header.sessionKey(), encMessage, headers);
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
}

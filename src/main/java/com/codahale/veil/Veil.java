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

import com.codahale.xsalsa20poly1305.SimpleBox;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Optional;
import okio.Buffer;
import okio.ByteString;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;

public class Veil {

  private static final int OVERHEAD = 40;
  private static final int HEADER_LEN = 8;
  private static final int KEY_LEN = 32;
  private static final int HASH_LEN = 32;

  private final ByteString privateKey;

  public Veil(ByteString privateKey) {
    this.privateKey = privateKey;
  }

  public ByteString encrypt(Collection<ByteString> publicKeys, ByteString plaintext, int padding) {
    final ByteString sk = SimpleBox.generateSecretKey();
    final SimpleBox session = new SimpleBox(sk);

    // hash the plaintext
    final ByteString hash = hash(plaintext);

    // encode and encrypt header
    final int dataOffset = publicKeys.size() * (KEY_LEN + HASH_LEN + OVERHEAD);
    final int dataLength = plaintext.size();
    final ByteString header =
        session.seal(new Buffer().writeInt(dataOffset).writeInt(dataLength).readByteString());

    // encrypt a copy of the session key and plaintext hash with each public key
    final Buffer keysBuf = new Buffer();
    for (ByteString pk : publicKeys) {
      final SimpleBox shared = new SimpleBox(pk, privateKey);
      keysBuf.write(shared.seal(new Buffer().write(sk).write(hash).readByteString()));
    }
    final ByteString keys = keysBuf.readByteString();

    // encrypt the plaintext
    final ByteString encData = session.seal(plaintext);

    // generate random padding
    final byte[] pad = new byte[padding];
    if (padding > 0) {
      final SecureRandom r = new SecureRandom();
      r.nextBytes(pad);
    }

    // return the encrypted header, the encrypted keys, and the encrypted plaintext and signature
    return new Buffer().write(header).write(keys).write(encData).write(pad).readByteString();
  }

  public Optional<ByteString> decrypt( ByteString publicKey, ByteString ciphertext) {
    try {
      final SimpleBox shared = new SimpleBox(publicKey, privateKey);
      final Buffer in = new Buffer().write(ciphertext);

      // copy the fixed-length header
      final ByteString encHeader = in.readByteString(HEADER_LEN + OVERHEAD);

      // iterate through key+hash-sized chunks, trying to decrypt them
      ByteString packet = null;
      while (in.size() > KEY_LEN + OVERHEAD) {
        final ByteString encPacket = in.readByteString(KEY_LEN + HASH_LEN + OVERHEAD);
        final Optional<ByteString> p = shared.open(encPacket);
        if (p.isPresent()) {
          packet = p.get();
          break;
        }
      }
      if (packet == null) {
        return Optional.empty();
      }
      final ByteString sk = packet.substring(0, KEY_LEN);
      final ByteString hash = packet.substring(KEY_LEN);

      // decrypt the header
      final SimpleBox session = new SimpleBox(sk);
      final Optional<ByteString> header = session.open(encHeader);
      if (!header.isPresent()) {
        return Optional.empty();
      }
      final Buffer headerBuffer = new Buffer().write(header.get());
      final int dataOffset = headerBuffer.readInt();
      final int dataLength = headerBuffer.readInt();

      // skip the other keys
      in.skip((dataOffset + HEADER_LEN + OVERHEAD) - (ciphertext.size() - in.size()));

      // decrypt the data
      final ByteString encData = in.readByteString(dataLength + OVERHEAD);
      final Optional<ByteString> plaintext = session.open(encData);
      if (!plaintext.isPresent()) {
        return Optional.empty();
      }

      // check the hash
      if (!MessageDigest.isEqual(hash.toByteArray(), hash(plaintext.get()).toByteArray())) {
        throw new IllegalArgumentException();
      }

      // return the plaintext
      return plaintext;
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  private static ByteString hash(ByteString m) {
    final byte[] h = new byte[HASH_LEN];
    final Digest d = DigestFactory.createSHA512_256();
    d.update(m.toByteArray(), 0, m.size());
    d.doFinal(h, 0);
    return ByteString.of(h);
  }
}

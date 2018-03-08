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

import com.codahale.xsalsa20poly1305.SecretBox;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Optional;
import okio.Buffer;
import okio.ByteString;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

public class Veil {

  private static final int OVERHEAD = 40;
  private static final int HEADER_LEN = 8;
  private static final int KEY_LEN = 32;
  private static final int MAC_LEN = 32;

  private final ByteString privateKey;

  public Veil(ByteString privateKey) {
    this.privateKey = privateKey;
  }

  public ByteString encrypt(Collection<ByteString> publicKeys, ByteString plaintext, int padding) {
    final ByteString sk = SimpleBox.generateSecretKey();
    final SimpleBox session = new SimpleBox(sk);

    // encode and encrypt header
    final int dataOffset = publicKeys.size() * (KEY_LEN + MAC_LEN + OVERHEAD);
    final int dataLength = plaintext.size();
    final ByteString header =
        session.seal(new Buffer().writeInt(dataOffset).writeInt(dataLength).readByteString());

    // encrypt a copy of the session key and plaintext mac with each public key
    final Buffer keysBuf = new Buffer();
    for (ByteString pk : publicKeys) {
      final ByteString sharedKey = SecretBox.sharedSecret(pk, privateKey);
      final SimpleBox shared = new SimpleBox(sharedKey);
      final ByteString mac = hmac(sharedKey, plaintext);
      keysBuf.write(shared.seal(new Buffer().write(sk).write(mac).readByteString()));
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
      final ByteString sharedKey = SecretBox.sharedSecret(publicKey, privateKey);
      final SimpleBox shared = new SimpleBox(sharedKey);
      final Buffer in = new Buffer().write(ciphertext);

      // copy the fixed-length header
      final ByteString encHeader = in.readByteString(HEADER_LEN + OVERHEAD);

      // iterate through key+mac-sized chunks, trying to decrypt them
      ByteString packet = null;
      while (in.size() > KEY_LEN + OVERHEAD) {
        final ByteString encPacket = in.readByteString(KEY_LEN + MAC_LEN + OVERHEAD);
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
      final ByteString mac = packet.substring(KEY_LEN);

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

      // check the mac
      final ByteString candidateMac = hmac(sharedKey, plaintext.get());
      if (!MessageDigest.isEqual(mac.toByteArray(), candidateMac.toByteArray())) {
        throw new IllegalArgumentException();
      }

      // return the plaintext
      return plaintext;
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  private static ByteString hmac(ByteString k, ByteString m) {
    final HMac hmac = new HMac(DigestFactory.createSHA512_256());
    hmac.init(new KeyParameter(k.toByteArray()));
    hmac.update(m.toByteArray(), 0, m.size());
    final byte[] h = new byte[MAC_LEN];
    hmac.doFinal(h, 0);
    return ByteString.of(h);
  }
}

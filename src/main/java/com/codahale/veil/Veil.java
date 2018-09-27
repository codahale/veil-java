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

import com.codahale.xsalsa20poly1305.Keys;
import com.codahale.xsalsa20poly1305.SimpleBox;
import com.google.common.io.ByteStreams;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Optional;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

public class Veil {

  private static final int OVERHEAD = 40;
  private static final int HEADER_LEN = 8;
  private static final int KEY_LEN = 32;
  private static final int SIG_LEN = 64;

  private final PrivateKey privateKey;

  public Veil(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public byte[] encrypt(Collection<PublicKey> publicKeys, byte[] plaintext, int padding) {
    var sk = Keys.generateSecretKey();
    var session = new SimpleBox(sk);

    // generate random padding
    var pad = new byte[padding];
    if (padding > 0) {
      var r = new SecureRandom();
      r.nextBytes(pad);
    }

    // encode and encrypt header
    var dataOffset = publicKeys.size() * (KEY_LEN + OVERHEAD);
    var dataLength = plaintext.length + SIG_LEN;
    var headerBuf = ByteStreams.newDataOutput(8);
    headerBuf.writeInt(dataOffset);
    headerBuf.writeInt(dataLength);
    var header = session.seal(headerBuf.toByteArray());

    // encrypt a copy of the session key with each public key
    var keysBuf = ByteStreams.newDataOutput(dataOffset);
    for (var pk : publicKeys) {
      var shared = new SimpleBox(pk.encryptionKey(), privateKey.decryptionKey());
      keysBuf.write(shared.seal(sk));
    }
    var keys = keysBuf.toByteArray();

    // sign the encrypted header, the encrypted keys, and the unencrypted plaintext
    var signed =
        ByteStreams.newDataOutput(header.length + keys.length + plaintext.length + padding);
    signed.write(header);
    signed.write(keys);
    signed.write(plaintext);
    signed.write(pad);
    var sig = sign(signed.toByteArray());

    // encrypt the plaintext and the signature
    var data = ByteStreams.newDataOutput();
    data.write(sig);
    data.write(plaintext);
    var encData = session.seal(data.toByteArray());

    // return the encrypted header, the encrypted keys, and the encrypted plaintext and signature
    var out = ByteStreams.newDataOutput(header.length + keys.length + encData.length + padding);
    out.write(header);
    out.write(keys);
    out.write(encData);
    out.write(pad);
    return out.toByteArray();
  }

  public Optional<byte[]> decrypt(PublicKey publicKey, byte[] ciphertext) {
    var shared = new SimpleBox(publicKey.encryptionKey(), privateKey.decryptionKey());
    var in = ByteStreams.newDataInput(ciphertext);
    var rem = ciphertext.length;

    // copy the fixed-length header
    var encHeader = new byte[HEADER_LEN + OVERHEAD];
    in.readFully(encHeader);
    rem -= encHeader.length;

    // iterate through key-sized chunks looking for our session key
    SimpleBox session = null;
    var key = new byte[KEY_LEN + OVERHEAD];
    while (rem > key.length) {
      in.readFully(key);
      rem -= key.length;

      final Optional<byte[]> result = shared.open(key);
      if (result.isPresent()) {
        session = new SimpleBox(result.get());
        break;
      }
    }
    if (session == null) {
      return Optional.empty();
    }

    // decrypt the header
    var hdr = session.open(encHeader);
    if (!hdr.isPresent()) {
      return Optional.empty();
    }
    var header = ByteStreams.newDataInput(hdr.get());
    var dataOffset = header.readInt();
    var dataLength = header.readInt();

    // skip the other keys
    int keyLen = (dataOffset + HEADER_LEN + OVERHEAD) - (ciphertext.length - rem);
    while (keyLen > 0) {
      var x = in.skipBytes(keyLen);
      keyLen -= x;
      rem -= x;
    }

    // decrypt the data and signature
    var encData = new byte[dataLength + OVERHEAD];
    in.readFully(encData);
    rem -= encData.length;

    var padding = new byte[rem];
    in.readFully(padding);
    var data = session.open(encData);
    if (!data.isPresent()) {
      return Optional.empty();
    }
    var dataBuf = ByteStreams.newDataInput(data.get());
    var sig = new byte[SIG_LEN];
    dataBuf.readFully(sig);
    var plaintext = new byte[dataLength - SIG_LEN];
    dataBuf.readFully(plaintext);

    // rebuild the signed data and verify the signature
    var signed = ByteStreams.newDataOutput(ciphertext.length + plaintext.length + padding.length);
    signed.write(ciphertext, 0, HEADER_LEN + OVERHEAD + dataOffset);
    signed.write(plaintext);
    signed.write(padding);
    if (!verify(publicKey, signed.toByteArray(), sig)) {
      return Optional.empty();
    }

    // return the plaintext
    return Optional.of(plaintext);
  }

  private byte[] sign(byte[] signed) {
    var signature = new byte[Ed25519.SIGNATURE_SIZE];
    Ed25519.sign(privateKey.signingKey(), 0, signed, 0, signed.length, signature, 0);
    return signature;
  }

  private boolean verify(PublicKey publicKey, byte[] signed, byte[] sig) {
    return Ed25519.verify(sig, 0, publicKey.verificationKey(), 0, signed, 0, signed.length);
  }
}

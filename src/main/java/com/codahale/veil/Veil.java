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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Optional;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import okio.Buffer;
import okio.ByteString;

public abstract class Veil {

  private static final int OVERHEAD = 40;
  private static final int HEADER_LEN = 8;
  private static final int KEY_LEN = 32;
  private static final int SIG_LEN = 64;
  private static final EdDSANamedCurveSpec ED_25519 = EdDSANamedCurveTable.getByName("Ed25519");

  public static ByteString encrypt(
      PrivateKey privateKey, Collection<PublicKey> publicKeys, ByteString plaintext, int padding)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    final ByteString sk = SimpleBox.generateSecretKey();
    final SimpleBox session = new SimpleBox(sk);

    // generate random padding
    final byte[] pad = new byte[padding];
    if (padding > 0) {
      final SecureRandom r = new SecureRandom();
      r.nextBytes(pad);
    }

    // encode and encrypt header
    final int dataOffset = publicKeys.size() * (KEY_LEN + OVERHEAD);
    final int dataLength = plaintext.size() + SIG_LEN;
    final ByteString header =
        session.seal(new Buffer().writeInt(dataOffset).writeInt(dataLength).readByteString());

    // encrypt a copy of the session key with each public key
    final Buffer keysBuf = new Buffer();
    for (PublicKey pk : publicKeys) {
      final SimpleBox shared = new SimpleBox(pk.encryptionKey(), privateKey.decryptionKey());
      keysBuf.write(shared.seal(sk));
    }
    final ByteString keys = keysBuf.readByteString();

    // sign the encrypted header, the encrypted keys, and the unencrypted plaintext
    final ByteString signed =
        new Buffer().write(header).write(keys).write(plaintext).write(pad).readByteString();
    final byte[] sig = sign(privateKey, signed);

    // encrypt the plaintext and the signature
    final ByteString data = new Buffer().write(sig).write(plaintext).readByteString();
    final ByteString encData = session.seal(data);

    // return the encrypted header, the encrypted keys, and the encrypted plaintext and signature
    return new Buffer().write(header).write(keys).write(encData).write(pad).readByteString();
  }

  public static ByteString decrypt(
      PrivateKey privateKey, PublicKey publicKey, ByteString ciphertext)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    try {
      final SimpleBox shared = new SimpleBox(publicKey.encryptionKey(), privateKey.decryptionKey());
      final Buffer in = new Buffer().write(ciphertext);

      // copy the fixed-length header
      final ByteString encHeader = in.readByteString(HEADER_LEN + OVERHEAD);

      // iterate through key-sized chunks, trying to decrypt them
      Optional<ByteString> sk = Optional.empty();
      while (in.size() > KEY_LEN + OVERHEAD) {
        final Optional<ByteString> result = shared.open(in.readByteString(KEY_LEN + OVERHEAD));
        if (result.isPresent()) {
          sk = result;
          break;
        }
      }
      final SimpleBox session = new SimpleBox(sk.orElseThrow(IllegalArgumentException::new));

      // decrypt the header
      final Buffer header =
          new Buffer().write(session.open(encHeader).orElseThrow(IllegalArgumentException::new));
      final int dataOffset = header.readInt();
      final int dataLength = header.readInt();

      // skip the other keys
      in.skip((dataOffset + HEADER_LEN + OVERHEAD) - (ciphertext.size() - in.size()));

      // decrypt the data and signature
      final ByteString encData = in.readByteString(dataLength + OVERHEAD);
      final ByteString padding = in.readByteString();
      final Buffer data =
          new Buffer().write(session.open(encData).orElseThrow(IllegalArgumentException::new));
      final ByteString sig = data.readByteString(SIG_LEN);
      final ByteString plaintext = data.readByteString();

      // rebuild the signed data and verify the signature
      final ByteString signed =
          new Buffer()
              .write(ciphertext.substring(0, HEADER_LEN + OVERHEAD + dataOffset))
              .write(plaintext)
              .write(padding)
              .readByteString();
      if (!verify(publicKey, signed, sig)) {
        throw new IllegalArgumentException();
      }

      // return the plaintext
      return plaintext;
    } catch (IOException e) {
      throw new IllegalArgumentException();
    }
  }

  private static byte[] sign(PrivateKey privateKey, ByteString signed)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    final EdDSAEngine signature =
        new EdDSAEngine(MessageDigest.getInstance(ED_25519.getHashAlgorithm()));
    signature.initSign(
        new EdDSAPrivateKey(
            new EdDSAPrivateKeySpec(ED_25519, privateKey.signingKey().toByteArray())));
    signature.update(signed.toByteArray());
    return signature.sign();
  }

  private static boolean verify(PublicKey publicKey, ByteString signed, ByteString sig)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    final EdDSAEngine signature =
        new EdDSAEngine(MessageDigest.getInstance(ED_25519.getHashAlgorithm()));
    signature.initVerify(
        new EdDSAPublicKey(
            new EdDSAPublicKeySpec(publicKey.verificationKey().toByteArray(), ED_25519)));
    signature.update(signed.toByteArray());
    return signature.verify(sig.toByteArray());
  }
}

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.veil;

import com.codahale.xsalsa20poly1305.SimpleBox;
import java.security.SecureRandom;
import java.util.Optional;
import org.bouncycastle.util.Pack;
import org.whispersystems.curve25519.Curve25519;

public abstract class Veil {

  private static final int OVERHEAD = 40;
  private static final int HEADER_LEN = 8;
  private static final int KEY_LEN = 32;
  private static final int SIG_LEN = 64;

  public static byte[] encrypt(byte[] privateKey, byte[][] publicKeys, byte[] plaintext,
      int padding) {
    final byte[] sk = SimpleBox.generateSecretKey();
    final SimpleBox session = new SimpleBox(sk);

    // encode and encrypt header
    final byte[] header = new byte[HEADER_LEN];
    final int dataOffset = publicKeys.length * (KEY_LEN + OVERHEAD);
    final int dataLength = plaintext.length + SIG_LEN;
    Pack.intToLittleEndian(dataOffset, header, 0);
    Pack.intToLittleEndian(dataLength, header, 4);
    final byte[] encHeader = session.seal(header);

    // encrypt a copy of the session key with each public key
    final byte[] keys = new byte[dataOffset];
    int offset = 0;
    for (byte[] pk : publicKeys) {
      final SimpleBox shared = new SimpleBox(pk, privateKey);
      final byte[] encPK = shared.seal(sk);
      System.arraycopy(encPK, 0, keys, offset, encPK.length);
      offset += encPK.length;
    }

    // sign the encrypted header, the encrypted keys, and the unencrypted plaintext
    final byte[] signed = new byte[encHeader.length + dataOffset + plaintext.length];
    System.arraycopy(encHeader, 0, signed, 0, encHeader.length);
    System.arraycopy(keys, 0, signed, encHeader.length, keys.length);
    System.arraycopy(plaintext, 0, signed, encHeader.length + keys.length, plaintext.length);
    final byte[] sig = Curve25519.getInstance(Curve25519.BEST)
                                 .calculateSignature(privateKey, signed);

    // encrypt the plaintext and the signature
    final byte[] data = new byte[dataLength];
    System.arraycopy(plaintext, 0, data, 0, plaintext.length);
    System.arraycopy(sig, 0, data, plaintext.length, sig.length);
    final byte[] encData = session.seal(data);

    // return the encrypted header, the encrypted keys, and the encrypted plaintext and signature
    final byte[] out = new byte[encHeader.length + keys.length + encData.length + padding];
    System.arraycopy(encHeader, 0, out, 0, encHeader.length);
    System.arraycopy(keys, 0, out, encHeader.length, keys.length);
    System.arraycopy(encData, 0, out, encHeader.length + keys.length, encData.length);

    if (padding > 0) {
      final byte[] pad = new byte[padding];
      final SecureRandom r = new SecureRandom();
      r.nextBytes(pad);
      System.arraycopy(pad, 0, out, encHeader.length + keys.length + encData.length, padding);
    }

    return out;
  }

  public static byte[] decrypt(byte[] publicKey, byte[] privateKey, byte[] ciphertext) {
    final SimpleBox shared = new SimpleBox(publicKey, privateKey);

    // copy the fixed-length header
    final byte[] encHeader = new byte[HEADER_LEN + OVERHEAD];
    System.arraycopy(ciphertext, 0, encHeader, 0, encHeader.length);

    // iterate through key-sized chunks, trying to decrypt them
    final byte[] encKey = new byte[KEY_LEN + OVERHEAD];
    Optional<byte[]> sessionKey = Optional.empty();
    for (int i = encHeader.length; i < ciphertext.length - encKey.length; i += encKey.length) {
      System.arraycopy(ciphertext, i, encKey, 0, encKey.length);
      final Optional<byte[]> result = shared.open(encKey);
      if (result.isPresent()) {
        sessionKey = result;
        break;
      }
    }
    final SimpleBox session = new SimpleBox(sessionKey.orElseThrow(IllegalArgumentException::new));

    // decrypt the header
    final byte[] header = session.open(encHeader).orElseThrow(IllegalArgumentException::new);
    final int dataOffset = Pack.littleEndianToInt(header, 0);
    final int dataLength = Pack.littleEndianToInt(header, 4);

    // decrypt the data and signature
    final byte[] encData = new byte[dataLength + OVERHEAD];
    System.arraycopy(ciphertext, dataOffset + encHeader.length, encData, 0, encData.length);
    final byte[] data = session.open(encData).orElseThrow(IllegalArgumentException::new);
    final byte[] sig = new byte[SIG_LEN];
    final byte[] plaintext = new byte[data.length - sig.length];
    System.arraycopy(data, 0, plaintext, 0, plaintext.length);
    System.arraycopy(data, plaintext.length, sig, 0, sig.length);

    // rebuild the signed data and verify the signature
    final byte[] signed = new byte[encHeader.length + dataOffset + plaintext.length];
    System.arraycopy(ciphertext, 0, signed, 0, encHeader.length + dataOffset);
    System.arraycopy(plaintext, 0, signed, encHeader.length + dataOffset, plaintext.length);
    if (!Curve25519.getInstance(Curve25519.BEST).verifySignature(publicKey, signed, sig)) {
      throw new IllegalArgumentException();
    }

    // return the plaintext
    return plaintext;
  }
}

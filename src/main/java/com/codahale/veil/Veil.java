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
import java.util.List;
import java.util.Optional;

public class Veil {

  private static final int HEADER_LEN = 8;

  private final PrivateKeyPair privateKeys;

  public Veil(PrivateKeyPair privateKeys) {
    this.privateKeys = privateKeys;
  }

  public byte[] encrypt(List<PublicKeyPair> publicKeys, byte[] plaintext, int padding) {
    var sk = Crypto.random(Crypto.KEY_LENGTH);

    // generate random padding
    var pad = Crypto.random(padding);

    // encode and encrypt header
    var dataOffset = publicKeys.size() * (Crypto.KEY_LENGTH + Crypto.OVERHEAD);
    var dataLength = plaintext.length + Crypto.SIG_LENGTH;
    var headerBuf = ByteStreams.newDataOutput(8);
    headerBuf.writeInt(dataOffset);
    headerBuf.writeInt(dataLength);
    var header = Crypto.encrypt(sk, headerBuf.toByteArray(), new byte[0]);

    // encrypt a copy of the session key with the shared secret for each public key
    var keysBuf = ByteStreams.newDataOutput(dataOffset);
    var sharedKeys = new byte[publicKeys.size()][];
    for (int i = 0; i < publicKeys.size(); i++) {
      var publicKey = publicKeys.get(i).encryptionKey();
      var sharedKey = Crypto.sharedSecret(privateKeys.decryptionKey(), publicKey);
      keysBuf.write(Crypto.encrypt(sharedKey, sk, new byte[0]));
      sharedKeys[i] = sharedKey;
    }
    var keys = keysBuf.toByteArray();

    // sign the encrypted header, the encrypted keys, and the unencrypted plaintext
    var signed =
        ByteStreams.newDataOutput(header.length + keys.length + plaintext.length + padding);
    signed.write(header);
    signed.write(keys);
    signed.write(plaintext);
    signed.write(pad);
    var sig = Crypto.sign(privateKeys.signingKey(), signed.toByteArray());

    // encrypt the plaintext and the signature
    var data = ByteStreams.newDataOutput();
    data.write(sig);
    data.write(plaintext);
    var encData = Crypto.encrypt(sk, data.toByteArray(), new byte[0]);

    // return the encrypted header, the encrypted keys, and the encrypted plaintext and signature
    var out = ByteStreams.newDataOutput(header.length + keys.length + encData.length + padding);
    out.write(header);
    out.write(keys);
    out.write(encData);
    out.write(pad);
    return out.toByteArray();
  }

  public Optional<byte[]> decrypt(PublicKeyPair publicKey, byte[] ciphertext) {
    var shared = Crypto.sharedSecret(privateKeys.decryptionKey(), publicKey.encryptionKey());
    var in = ByteStreams.newDataInput(ciphertext);
    var rem = ciphertext.length;

    // copy the fixed-length header
    var encHeader = new byte[HEADER_LEN + Crypto.OVERHEAD];
    in.readFully(encHeader);
    rem -= encHeader.length;

    // iterate through key-sized chunks looking for our session key
    byte[] session = null;
    var key = new byte[Crypto.KEY_LENGTH + Crypto.OVERHEAD];
    while (rem > key.length) {
      in.readFully(key);
      rem -= key.length;

      var result = Crypto.decrypt(shared, key, new byte[0]);
      if (result != null) {
        session = result;
        break;
      }
    }
    if (session == null) {
      return Optional.empty();
    }

    // decrypt the header
    var hdr = Crypto.decrypt(session, encHeader, new byte[0]);
    if (hdr == null) {
      return Optional.empty();
    }
    var header = ByteStreams.newDataInput(hdr);
    var dataOffset = header.readInt();
    var dataLength = header.readInt();

    // skip the other keys
    int keyLen = (dataOffset + HEADER_LEN + Crypto.OVERHEAD) - (ciphertext.length - rem);
    while (keyLen > 0) {
      var x = in.skipBytes(keyLen);
      keyLen -= x;
      rem -= x;
    }

    // decrypt the data and signature
    var encData = new byte[dataLength + Crypto.OVERHEAD];
    in.readFully(encData);
    rem -= encData.length;

    var padding = new byte[rem];
    in.readFully(padding);
    var data = Crypto.decrypt(session, encData, new byte[0]);
    if (data == null) {
      return Optional.empty();
    }
    var dataBuf = ByteStreams.newDataInput(data);
    var sig = new byte[Crypto.SIG_LENGTH];
    dataBuf.readFully(sig);
    var plaintext = new byte[dataLength - Crypto.SIG_LENGTH];
    dataBuf.readFully(plaintext);

    // rebuild the signed data and verify the signature
    var signed = ByteStreams.newDataOutput(ciphertext.length + plaintext.length + padding.length);
    signed.write(ciphertext, 0, HEADER_LEN + Crypto.OVERHEAD + dataOffset);
    signed.write(plaintext);
    signed.write(padding);
    if (!Crypto.verify(publicKey.verificationKey(), signed.toByteArray(), sig)) {
      return Optional.empty();
    }

    // return the plaintext
    return Optional.of(plaintext);
  }
}

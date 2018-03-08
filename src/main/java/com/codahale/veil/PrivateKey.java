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
import com.google.auto.value.AutoValue;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import okio.ByteString;

@AutoValue
public abstract class PrivateKey {
  public static PrivateKey generate() {
    final ByteString decryptionKey = SimpleBox.generatePrivateKey();
    final ByteString encryptionKey = SimpleBox.generatePublicKey(decryptionKey);

    final EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
    final KeyPairGenerator generator = new KeyPairGenerator();
    final SecureRandom random = new SecureRandom();
    try {
      generator.initialize(spec, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
    final KeyPair keyPair = generator.generateKeyPair();

    final EdDSAPrivateKey signingKey = (EdDSAPrivateKey) keyPair.getPrivate();
    final EdDSAPublicKey verifyingKey = (EdDSAPublicKey) keyPair.getPublic();

    final PublicKey pk = PublicKey.of(encryptionKey, ByteString.of(verifyingKey.getAbyte()));

    return of(pk, decryptionKey, ByteString.of(signingKey.getH()));
  }

  public static PrivateKey of(
      PublicKey publicKey, ByteString decryptionKey, ByteString signingKey) {
    return new AutoValue_PrivateKey(publicKey, decryptionKey, signingKey);
  }

  public abstract PublicKey publicKey();

  public abstract ByteString decryptionKey();

  public abstract ByteString signingKey();
}

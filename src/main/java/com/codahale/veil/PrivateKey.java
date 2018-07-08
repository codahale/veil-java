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
import com.google.auto.value.AutoValue;
import java.security.SecureRandom;
import okio.ByteString;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

@AutoValue
public abstract class PrivateKey {
  public static PrivateKey generate() {
    final ByteString decryptionKey = Keys.generatePrivateKey();

    final SecureRandom random = new SecureRandom();
    final byte[] signingKey = new byte[Ed25519.SECRET_KEY_SIZE];
    random.nextBytes(signingKey);

    return of(decryptionKey, ByteString.of(signingKey));
  }

  public static PrivateKey of(ByteString decryptionKey, ByteString signingKey) {
    final ByteString encryptionKey = Keys.generatePublicKey(decryptionKey);
    final byte[] verifyingKey = new byte[Ed25519.PUBLIC_KEY_SIZE];
    Ed25519.generatePublicKey(signingKey.toByteArray(), 0, verifyingKey, 0);

    return new AutoValue_PrivateKey(
        PublicKey.of(encryptionKey, ByteString.of(verifyingKey)), decryptionKey, signingKey);
  }

  public abstract PublicKey publicKey();

  public abstract ByteString decryptionKey();

  public abstract ByteString signingKey();
}

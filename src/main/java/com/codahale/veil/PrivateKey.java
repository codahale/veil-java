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
import com.google.common.io.BaseEncoding;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.StringJoiner;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

public class PrivateKey {

  private final PublicKey publicKey;
  private final byte[] decryptionKey;
  private final byte[] signingKey;

  public PrivateKey(byte[] decryptionKey, byte[] signingKey) {
    this.decryptionKey = Arrays.copyOf(decryptionKey, decryptionKey.length);
    this.signingKey = Arrays.copyOf(signingKey, signingKey.length);
    var encryptionKey = Keys.generatePublicKey(decryptionKey);
    var verifyingKey = new byte[Ed25519.PUBLIC_KEY_SIZE];
    Ed25519.generatePublicKey(signingKey, 0, verifyingKey, 0);
    this.publicKey = new PublicKey(encryptionKey, verifyingKey);
  }

  public static PrivateKey generate() {
    var decryptionKey = Keys.generatePrivateKey();

    var random = new SecureRandom();
    var signingKey = new byte[Ed25519.SECRET_KEY_SIZE];
    random.nextBytes(signingKey);

    return new PrivateKey(decryptionKey, signingKey);
  }

  public PublicKey publicKey() {
    return publicKey;
  }

  public byte[] decryptionKey() {
    return Arrays.copyOf(decryptionKey, decryptionKey.length);
  }

  public byte[] signingKey() {
    return Arrays.copyOf(signingKey, signingKey.length);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PrivateKey)) {
      return false;
    }
    PrivateKey that = (PrivateKey) o;
    return Objects.equals(publicKey, that.publicKey)
        && Arrays.equals(decryptionKey, that.decryptionKey)
        && Arrays.equals(signingKey, that.signingKey);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(publicKey);
    result = 31 * result + Arrays.hashCode(decryptionKey);
    result = 31 * result + Arrays.hashCode(signingKey);
    return result;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", PrivateKey.class.getSimpleName() + "[", "]")
        .add("publicKey=" + publicKey)
        .add("decryptionKey=" + BaseEncoding.base16().encode(decryptionKey))
        .add("signingKey=" + BaseEncoding.base16().encode(signingKey))
        .toString();
  }
}

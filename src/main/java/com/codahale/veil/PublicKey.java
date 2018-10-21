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

import com.google.common.io.BaseEncoding;
import java.util.Arrays;
import java.util.StringJoiner;

public class PublicKey {

  private final byte[] encryptionKey;
  private final byte[] verificationKey;

  public PublicKey(byte[] encryptionKey, byte[] verificationKey) {
    this.encryptionKey = Arrays.copyOf(encryptionKey, encryptionKey.length);
    this.verificationKey = Arrays.copyOf(verificationKey, verificationKey.length);
  }

  public byte[] encryptionKey() {
    return Arrays.copyOf(encryptionKey, encryptionKey.length);
  }

  public byte[] verificationKey() {
    return Arrays.copyOf(verificationKey, verificationKey.length);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PublicKey)) {
      return false;
    }
    PublicKey publicKey = (PublicKey) o;
    return Arrays.equals(encryptionKey, publicKey.encryptionKey)
        && Arrays.equals(verificationKey, publicKey.verificationKey);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(encryptionKey);
    result = 31 * result + Arrays.hashCode(verificationKey);
    return result;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", PublicKey.class.getSimpleName() + "[", "]")
        .add("encryptionKey=" + BaseEncoding.base16().encode(encryptionKey))
        .add("verificationKey=" + BaseEncoding.base16().encode(verificationKey))
        .toString();
  }
}

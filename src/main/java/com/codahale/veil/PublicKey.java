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

import com.google.auto.value.AutoValue;
import okio.ByteString;

@AutoValue
public abstract class PublicKey {
  public static PublicKey of(ByteString encryptionKey, ByteString verificationKey) {
    return new AutoValue_PublicKey(encryptionKey, verificationKey);
  }

  public abstract ByteString encryptionKey();

  public abstract ByteString verificationKey();
}

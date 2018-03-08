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
package com.codahale.veil.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.codahale.veil.PrivateKey;
import com.codahale.veil.PublicKey;
import com.codahale.veil.Veil;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import okio.ByteString;
import org.junit.Test;

public class VeilTest {

  @Test
  public void roundTrip() {
    final PrivateKey a = PrivateKey.generate();
    final PrivateKey b = PrivateKey.generate();
    final PrivateKey c = PrivateKey.generate();

    final ByteString plaintext = ByteString.encodeUtf8("this is super cool");

    final List<PublicKey> keys = Arrays.asList(a.publicKey(), b.publicKey(), c.publicKey());
    final ByteString c1 = new Veil(a).encrypt(keys, plaintext, 1000);
    final ByteString c2 = new Veil(a).encrypt(keys, plaintext, 2000);

    assertThat(c2.size() - c1.size()).isEqualTo(1000);

    final Optional<ByteString> p1 = new Veil(a).decrypt(a.publicKey(), c1);
    assertThat(p1).contains(plaintext);

    final Optional<ByteString> p2 = new Veil(b).decrypt(a.publicKey(), c1);
    assertThat(p2).contains(plaintext);

    final Optional<ByteString> p3 = new Veil(c).decrypt(a.publicKey(), c1);
    assertThat(p3).contains(plaintext);
  }
}

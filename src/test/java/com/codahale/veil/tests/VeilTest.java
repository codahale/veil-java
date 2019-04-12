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

import static com.codahale.veil.EtMTest.corrupt;
import static org.assertj.core.api.Assertions.assertThat;

import com.codahale.veil.Veil;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.Test;

class VeilTest {

  @Test
  void roundTrip() {
    var a = Veil.generate();
    var b = Veil.generate();
    var c = Veil.generate();

    var plaintext = "this is super cool".getBytes(StandardCharsets.UTF_8);

    var keys = Arrays.asList(a.getPublic(), b.getPublic(), c.getPublic());
    var c1 = new Veil(a).encrypt(keys, plaintext, 1000, 5);
    var c2 = new Veil(a).encrypt(keys, plaintext, 2000, 5);

    assertThat(c2.length - c1.length).isEqualTo(1000);

    var p1 = new Veil(a).decrypt(a.getPublic(), c1);
    assertThat(p1).contains(plaintext);

    var p2 = new Veil(b).decrypt(a.getPublic(), c1);
    assertThat(p2).contains(plaintext);

    var p3 = new Veil(c).decrypt(a.getPublic(), c1);
    assertThat(p3).contains(plaintext);

    var v = new Veil(b);
    for (int i = 0; i < 1_000; i++) {
      assertThat(v.decrypt(a.getPublic(), corrupt(c1))).isEmpty();
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void multidecrypt() {
    var a = Veil.generate();
    var b = Veil.generate();
    var c = Veil.generate();
    var plaintext = "this is super cool".getBytes(StandardCharsets.UTF_8);
    var keys = Arrays.asList(a.getPublic(), b.getPublic(), c.getPublic());
    var ciphertext = new Veil(a).encrypt(keys, plaintext, 1000, 5);

    var recovered = new Veil(b).decrypt(keys, ciphertext);
    assertThat(recovered)
        .isPresent()
        .get()
        .extracting(Map.Entry::getKey, Map.Entry::getValue)
        .containsExactly(a.getPublic(), plaintext);
  }

  @Test
  void parsingKeys() throws InvalidKeySpecException {
    var a = Veil.generate();

    assertThat(Veil.parsePrivateKey(a.getPrivate().getEncoded())).isEqualTo(a.getPrivate());
    assertThat(Veil.parsePublicKey(a.getPublic().getEncoded())).isEqualTo(a.getPublic());
  }
}

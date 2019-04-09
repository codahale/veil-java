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

import static com.codahale.veil.AEADTest.corrupt;
import static org.assertj.core.api.Assertions.assertThat;

import com.codahale.veil.Veil;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class VeilTest {

  @Test
  void roundTrip() {
    var a = Veil.generate();
    var b = Veil.generate();
    var c = Veil.generate();

    var plaintext = "this is super cool".getBytes(StandardCharsets.UTF_8);

    var keys = Arrays.asList(a.getPublic(), b.getPublic(), c.getPublic());
    var c1 = new Veil(a.getPrivate()).encrypt(keys, plaintext, 1000);
    var c2 = new Veil(a.getPrivate()).encrypt(keys, plaintext, 2000);

    assertThat(c2.length - c1.length).isEqualTo(1000);

    var p1 = new Veil(a.getPrivate()).decrypt(a.getPublic(), c1);
    assertThat(p1).contains(plaintext);

    var p2 = new Veil(b.getPrivate()).decrypt(a.getPublic(), c1);
    assertThat(p2).contains(plaintext);

    var p3 = new Veil(c.getPrivate()).decrypt(a.getPublic(), c1);
    assertThat(p3).contains(plaintext);

    var v = new Veil(b.getPrivate());
    for (int i = 0; i < 1_000; i++) {
      assertThat(v.decrypt(a.getPublic(), corrupt(c1))).isEmpty();
    }
  }
}

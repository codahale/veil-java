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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class X448Test {

  @Test
  void keyExchange() {
    var a = X448.generate();
    var b = X448.generate();

    var keyA = X448.sharedSecret(a, b.getPublic(), true);
    var keyB = X448.sharedSecret(b, a.getPublic(), false);

    assertThat(keyA).isEqualTo(keyB).hasSize(EtM.KEY_LEN);
  }

  @Test
  void hkdf() {
    assertThat(X448.hkdf(new byte[] {1, 2, 3}, new byte[] {5, 6, 7}))
        .containsExactly(
            -37, -20, 31, 31, 76, -30, 67, -46, 108, 118, 97, -103, 13, 74, -64, -11, 62, 53, -109,
            103, -91, 111, -44, 80, -103, -89, 33, -45, 45, 31, -19, -86, -22, 52, -83, 16, -114,
            46, -67, 71, 60, 126, 72, -71, 13, -39, -110, -22, 9, 72, 67, 118, 65, 2, -53, 108,
            -106, -89, 89, -24, -16, 71, -54, 5);
  }
}

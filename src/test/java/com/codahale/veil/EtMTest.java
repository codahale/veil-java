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

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class EtMTest {

  public static byte[] corrupt(byte[] m) {
    final Random random = new Random();
    var bad = Arrays.copyOf(m, m.length);
    // flip a random bit
    bad[random.nextInt(bad.length)] ^= (1 << (random.nextInt(6) + 1));
    return bad;
  }

  @Test
  void symmetricEncryption() {
    var key = Veil.random(EtM.KEY_LEN);
    var plaintext = Veil.random(1024);
    var data = Veil.random(1024);
    var ciphertext = EtM.encrypt(key, plaintext, data);
    assertThat(EtM.decrypt(key, ciphertext, data)).isEqualTo(plaintext);
    assertThat(EtM.decrypt(key, corrupt(ciphertext), data)).isNull();
    assertThat(EtM.decrypt(key, ciphertext, corrupt(data))).isNull();
  }
}

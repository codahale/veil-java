/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.veil.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.codahale.veil.Veil;
import com.codahale.xsalsa20poly1305.SimpleBox;
import org.junit.Test;

public class VeilTest {

  @Test
  public void roundTrip() throws Exception {
    final byte[] privateKeyA = SimpleBox.generatePrivateKey();
    final byte[] publicKeyA = SimpleBox.generatePublicKey(privateKeyA);
    final byte[] privateKeyB = SimpleBox.generatePrivateKey();
    final byte[] publicKeyB = SimpleBox.generatePublicKey(privateKeyB);
    final byte[] privateKeyC = SimpleBox.generatePrivateKey();
    final byte[] publicKeyC = SimpleBox.generatePublicKey(privateKeyC);

    final byte[] plaintext = "this is super cool".getBytes();

    final byte[][] keys = {publicKeyA, publicKeyB, publicKeyC};
    final byte[] c1 = Veil.encrypt(privateKeyA, keys, plaintext, 1000);
    final byte[] c2 = Veil.encrypt(privateKeyA, keys, plaintext, 2000);

    assertThat(c1)
        .hasSize(1386);
    assertThat(c2)
        .hasSize(2386);

    final byte[] p1 = Veil.decrypt(publicKeyA, privateKeyA, c1);
    final byte[] p2 = Veil.decrypt(publicKeyA, privateKeyB, c1);
    final byte[] p3 = Veil.decrypt(publicKeyA, privateKeyC, c1);

    assertThat(p1)
        .isEqualTo(p2)
        .isEqualTo(p3);
  }
}
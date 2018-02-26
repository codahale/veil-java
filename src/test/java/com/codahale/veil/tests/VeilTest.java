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

import com.codahale.veil.Veil;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.Arrays;
import java.util.List;
import okio.ByteString;
import org.junit.Test;

public class VeilTest {

  @Test
  public void roundTrip() {
    final ByteString privateKeyA = SimpleBox.generatePrivateKey();
    final ByteString publicKeyA = SimpleBox.generatePublicKey(privateKeyA);
    final ByteString privateKeyB = SimpleBox.generatePrivateKey();
    final ByteString publicKeyB = SimpleBox.generatePublicKey(privateKeyB);
    final ByteString privateKeyC = SimpleBox.generatePrivateKey();
    final ByteString publicKeyC = SimpleBox.generatePublicKey(privateKeyC);

    final ByteString plaintext = ByteString.encodeUtf8("this is super cool");

    final List<ByteString> keys = Arrays.asList(publicKeyA, publicKeyB, publicKeyC);
    final ByteString c1 = Veil.encrypt(privateKeyA, keys, plaintext, 1000);
    final ByteString c2 = Veil.encrypt(privateKeyA, keys, plaintext, 2000);

    assertThat(c1.size()).isEqualTo(1386);
    assertThat(c2.size()).isEqualTo(2386);

    final ByteString p1 = Veil.decrypt(publicKeyA, privateKeyA, c1);
    assertThat(p1).isEqualTo(plaintext);

    final ByteString p2 = Veil.decrypt(publicKeyA, privateKeyB, c1);
    assertThat(p2).isEqualTo(plaintext);

    final ByteString p3 = Veil.decrypt(publicKeyA, privateKeyC, c1);
    assertThat(p3).isEqualTo(plaintext);
  }
}

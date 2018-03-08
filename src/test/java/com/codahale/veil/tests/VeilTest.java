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
    final ByteString A = SimpleBox.generatePrivateKey();
    final ByteString a = SimpleBox.generatePublicKey(A);

    final ByteString B = SimpleBox.generatePrivateKey();
    final ByteString b = SimpleBox.generatePublicKey(B);

    final ByteString C = SimpleBox.generatePrivateKey();
    final ByteString c = SimpleBox.generatePublicKey(C);

    final ByteString plaintext = ByteString.encodeUtf8("this is super cool");

    final List<ByteString> keys = Arrays.asList(a, b, c);
    final ByteString c1 = Veil.encrypt(A, keys, plaintext, 1000);
    final ByteString c2 = Veil.encrypt(B, keys, plaintext, 2000);

    assertThat(c2.size() - c1.size()).isEqualTo(1000);

    final ByteString p1 = Veil.decrypt(A, a, c1);
    assertThat(p1).isEqualTo(plaintext);

    final ByteString p2 = Veil.decrypt(B, a, c1);
    assertThat(p2).isEqualTo(plaintext);

    final ByteString p3 = Veil.decrypt(C, a, c1);
    assertThat(p3).isEqualTo(plaintext);
  }
}

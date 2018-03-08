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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import okio.ByteString;
import org.junit.Test;

public class VeilTest {

  @Test
  public void roundTrip()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException,
          SignatureException {
    final PrivateKey a = PrivateKey.generate();
    final PrivateKey b = PrivateKey.generate();
    final PrivateKey c = PrivateKey.generate();

    final ByteString plaintext = ByteString.encodeUtf8("this is super cool");

    final List<PublicKey> keys = Arrays.asList(a.publicKey(), b.publicKey(), c.publicKey());
    final ByteString c1 = Veil.encrypt(a, keys, plaintext, 1000);
    final ByteString c2 = Veil.encrypt(b, keys, plaintext, 2000);

    assertThat(c1.size()).isEqualTo(1386);
    assertThat(c2.size()).isEqualTo(2386);

    final ByteString p1 = Veil.decrypt(a, a.publicKey(), c1);
    assertThat(p1).isEqualTo(plaintext);

    final ByteString p2 = Veil.decrypt(b, a.publicKey(), c1);
    assertThat(p2).isEqualTo(plaintext);

    final ByteString p3 = Veil.decrypt(c, a.publicKey(), c1);
    assertThat(p3).isEqualTo(plaintext);
  }
}

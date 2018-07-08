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
import org.junit.jupiter.api.Test;

class VeilTest {

  @Test
  void roundTrip() {
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

  @Test
  void fixedRoundTrip() {
    final PrivateKey privA =
        PrivateKey.of(
            ByteString.decodeHex(
                "486263b5e4364720a7e38e96c007857d0f1018b98a797d2f985be60d32c23b6b"),
            ByteString.decodeHex(
                "118f567d9b2dddf85f5faf20a979e5dcf5cab2acc3f7762cfcc1c802d421a812"));
    final PublicKey pubA =
        PublicKey.of(
            ByteString.decodeHex(
                "9ead227b3474240ca194a7861babe84c53b44592ab795244ece3e3f468e88107"),
            ByteString.decodeHex(
                "853f360a2423d49424ec199e6f081cc85b0582319e100452949e2fb66b5a3916"));
    final PrivateKey privB =
        PrivateKey.of(
            ByteString.decodeHex(
                "9882e2ca165682c0baad06433f8e14881777e76dbd4ce10c47b998488a2f0862"),
            ByteString.decodeHex(
                "2454a84d1ad2861e7d1ce154a26fe8d699ae9398e66b8a52e2dc72f2af83505d"));
    final PublicKey pubB =
        PublicKey.of(
            ByteString.decodeHex(
                "16214fcf7f4fa2752bb227570bc8ce7ef886ee8f2d6115c230d8cdb2a609041c"),
            ByteString.decodeHex(
                "3c98e6f31d764e6cb79fafef16af585f1d99483a99c57663a3c4b6f1cdb4384a"));
    final PrivateKey privC =
        PrivateKey.of(
            ByteString.decodeHex(
                "c00484773cbc61115f3ff623766453cd82cf4f89b1d1181272ec86c519acc677"),
            ByteString.decodeHex(
                "a1bfc67d55fa102076c220cf4e74ffd5e8bcd283fc9ae0e98c2dcb8d02bc5304"));
    final PublicKey pubC =
        PublicKey.of(
            ByteString.decodeHex(
                "2889754d85c31f779f61ead80890e750ce7962ac75576f32fcca700b241eeb08"),
            ByteString.decodeHex(
                "fdc6acac627798a18a60dc52ea1df66d10f3ebd5fdb9440f8f31cce7af7e264c"));

    final ByteString plaintext = ByteString.encodeUtf8("this is super cool");

    final List<PublicKey> keys = Arrays.asList(pubA, pubB, pubC);
    final ByteString c1 = new Veil(privA).encrypt(keys, plaintext, 1000);
    final ByteString c2 = new Veil(privA).encrypt(keys, plaintext, 2000);

    assertThat(c2.size() - c1.size()).isEqualTo(1000);

    final Optional<ByteString> p1 = new Veil(privA).decrypt(pubA, c1);
    assertThat(p1).contains(plaintext);

    final Optional<ByteString> p2 = new Veil(privB).decrypt(pubA, c1);
    assertThat(p2).contains(plaintext);

    final Optional<ByteString> p3 = new Veil(privC).decrypt(pubA, c1);
    assertThat(p3).contains(plaintext);
  }
}

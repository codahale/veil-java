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
import com.google.common.io.BaseEncoding;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class VeilTest {

  @Test
  void roundTrip() {
    final PrivateKey a = PrivateKey.generate();
    final PrivateKey b = PrivateKey.generate();
    final PrivateKey c = PrivateKey.generate();

    final byte[] plaintext = "this is super cool".getBytes(StandardCharsets.UTF_8);

    final List<PublicKey> keys = Arrays.asList(a.publicKey(), b.publicKey(), c.publicKey());
    final byte[] c1 = new Veil(a).encrypt(keys, plaintext, 1000);
    final byte[] c2 = new Veil(a).encrypt(keys, plaintext, 2000);

    assertThat(c2.length - c1.length).isEqualTo(1000);

    final Optional<byte[]> p1 = new Veil(a).decrypt(a.publicKey(), c1);
    assertThat(p1).contains(plaintext);

    final Optional<byte[]> p2 = new Veil(b).decrypt(a.publicKey(), c1);
    assertThat(p2).contains(plaintext);

    final Optional<byte[]> p3 = new Veil(c).decrypt(a.publicKey(), c1);
    assertThat(p3).contains(plaintext);
  }

  @Test
  void fixedRoundTrip() {
    final PrivateKey privA =
        new PrivateKey(
            BaseEncoding.base16()
                .decode("486263B5E4364720A7E38E96C007857D0F1018B98A797D2F985BE60D32C23B6B"),
            BaseEncoding.base16()
                .decode("118F567D9B2DDDF85F5FAF20A979E5DCF5CAB2ACC3F7762CFCC1C802D421A812"));
    final PublicKey pubA =
        new PublicKey(
            BaseEncoding.base16()
                .decode("9EAD227B3474240CA194A7861BABE84C53B44592AB795244ECE3E3F468E88107"),
            BaseEncoding.base16()
                .decode("853F360A2423D49424EC199E6F081CC85B0582319E100452949E2FB66B5A3916"));
    final PrivateKey privB =
        new PrivateKey(
            BaseEncoding.base16()
                .decode("9882E2CA165682C0BAAD06433F8E14881777E76DBD4CE10C47B998488A2F0862"),
            BaseEncoding.base16()
                .decode("2454A84D1AD2861E7D1CE154A26FE8D699AE9398E66B8A52E2DC72F2AF83505D"));
    final PublicKey pubB =
        new PublicKey(
            BaseEncoding.base16()
                .decode("16214FCF7F4FA2752BB227570BC8CE7EF886EE8F2D6115C230D8CDB2A609041C"),
            BaseEncoding.base16()
                .decode("3C98E6F31D764E6CB79FAFEF16AF585F1D99483A99C57663A3C4B6F1CDB4384A"));
    final PrivateKey privC =
        new PrivateKey(
            BaseEncoding.base16()
                .decode("C00484773CBC61115F3FF623766453CD82CF4F89B1D1181272EC86C519ACC677"),
            BaseEncoding.base16()
                .decode("A1BFC67D55FA102076C220CF4E74FFD5E8BCD283FC9AE0E98C2DCB8D02BC5304"));
    final PublicKey pubC =
        new PublicKey(
            BaseEncoding.base16()
                .decode("2889754D85C31F779F61EAD80890E750CE7962AC75576F32FCCA700B241EEB08"),
            BaseEncoding.base16()
                .decode("FDC6ACAC627798A18A60DC52EA1DF66D10F3EBD5FDB9440F8F31CCE7AF7E264C"));

    final byte[] plaintext = "this is super cool".getBytes(StandardCharsets.UTF_8);

    final List<PublicKey> keys = Arrays.asList(pubA, pubB, pubC);
    final byte[] c1 = new Veil(privA).encrypt(keys, plaintext, 1000);
    final byte[] c2 = new Veil(privA).encrypt(keys, plaintext, 2000);

    assertThat(c2.length - c1.length).isEqualTo(1000);

    final Optional<byte[]> p1 = new Veil(privA).decrypt(pubA, c1);
    assertThat(p1).contains(plaintext);

    final Optional<byte[]> p2 = new Veil(privB).decrypt(pubA, c1);
    assertThat(p2).contains(plaintext);

    final Optional<byte[]> p3 = new Veil(privC).decrypt(pubA, c1);
    assertThat(p3).contains(plaintext);
  }
}

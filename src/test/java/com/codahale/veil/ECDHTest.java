package com.codahale.veil;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ECDHTest {

  @Test
  void keyExchange() {
    var a = ECDH.generate();
    var b = ECDH.generate();

    var keyA = ECDH.sharedSecret(a.getPrivate(), b.getPublic());
    var keyB = ECDH.sharedSecret(b.getPrivate(), a.getPublic());

    assertThat(keyA).isEqualTo(keyB).hasSize(AEAD.KEY_LEN);
  }
}

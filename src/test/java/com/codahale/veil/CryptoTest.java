package com.codahale.veil;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class CryptoTest {
  @Test
  void symmetricEncryption() {
    var key = "blorp".getBytes(StandardCharsets.UTF_8);
    var plaintext = "blah".getBytes(StandardCharsets.UTF_8);
    var data = new byte[]{1, 2, 3};
    var ciphertext = Crypto.encrypt(key, plaintext, data);
    var morePlaintext = Crypto.decrypt(key, ciphertext, data);
    assertThat(morePlaintext).isEqualTo(plaintext);
  }

  @Test
  void keyExchange() {
    var a = Crypto.generateEncryptionKeys();
    var b = Crypto.generateEncryptionKeys();

    var keyA = Crypto.sharedSecret(a.getPrivate(), b.getPublic());
    var keyB = Crypto.sharedSecret(b.getPrivate(), a.getPublic());

    assertThat(keyA).isEqualTo(keyB).hasSize(56);
  }

  @Test
  void signatures() {
    var a = Crypto.generateSigningKeys();
    var b = Crypto.generateSigningKeys();
    var message = "blorp".getBytes(StandardCharsets.UTF_8);
    var sig = Crypto.sign(a.getPrivate(), message);
    assertThat(Crypto.verify(a.getPublic(), message, sig)).isTrue();
    assertThat(Crypto.verify(a.getPublic(), message, corrupt(sig))).isFalse();
    assertThat(Crypto.verify(a.getPublic(), corrupt(message), sig)).isFalse();
    assertThat(Crypto.verify(b.getPublic(), message, sig)).isFalse();

    for (int i = 0; i < 10; i++) {
      System.out.println(Arrays.toString(Crypto.sign(a.getPrivate(), String.valueOf(i).getBytes())));
    }
  }

  private byte[] corrupt(byte[] m) {
    var badSig = Arrays.copyOf(m, m.length);
    badSig[0] ^= 0x01;
    return badSig;
  }
}

package com.codahale.veil;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class AEADTest {

  public static byte[] corrupt(byte[] m) {
    final Random random = new Random();
    var bad = Arrays.copyOf(m, m.length);
    // flip a random bit
    bad[random.nextInt(bad.length)] ^= (1 << (random.nextInt(6) + 1));
    return bad;
  }

  @Test
  void symmetricEncryption() {
    var key = "blorp".getBytes(StandardCharsets.UTF_8);
    var plaintext = "blah".getBytes(StandardCharsets.UTF_8);
    var data = new byte[] {1, 2, 3};
    var ciphertext = AEAD.encrypt(key, plaintext, data);
    assertThat(AEAD.decrypt(key, ciphertext, data)).isEqualTo(plaintext);
    assertThat(AEAD.decrypt(corrupt(key), ciphertext, data)).isNull();
    assertThat(AEAD.decrypt(key, corrupt(ciphertext), data)).isNull();
    assertThat(AEAD.decrypt(key, ciphertext, corrupt(data))).isNull();
  }
}

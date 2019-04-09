package com.codahale.veil;

import java.security.PublicKey;
import java.util.Objects;
import java.util.StringJoiner;

public class PublicKeyPair {
  private final PublicKey encryptionKey;
  private final PublicKey verificationKey;

  public PublicKeyPair(PublicKey encryptionKey, PublicKey verificationKey) {
    this.encryptionKey = Objects.requireNonNull(encryptionKey);
    this.verificationKey = Objects.requireNonNull(verificationKey);
  }

  PublicKey encryptionKey() {
    return encryptionKey;
  }

  PublicKey verificationKey() {
    return verificationKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PublicKeyPair)) {
      return false;
    }
    PublicKeyPair that = (PublicKeyPair) o;
    return encryptionKey.equals(that.encryptionKey) && verificationKey.equals(that.verificationKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(encryptionKey, verificationKey);
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", PublicKeyPair.class.getSimpleName() + "[", "]")
        .add("encryptionKey=" + encryptionKey)
        .add("verificationKey=" + verificationKey)
        .toString();
  }
}

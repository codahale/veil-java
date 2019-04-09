package com.codahale.veil;

import java.security.PrivateKey;
import java.util.Objects;
import java.util.StringJoiner;

public class PrivateKeyPair {
  private final PublicKeyPair publicKeys;
  private final PrivateKey decryptionKey;
  private final PrivateKey signingKey;

  public PrivateKeyPair(PublicKeyPair publicKeys, PrivateKey decryptionKey, PrivateKey signingKey) {
    this.publicKeys = Objects.requireNonNull(publicKeys);
    this.decryptionKey = Objects.requireNonNull(decryptionKey);
    this.signingKey = Objects.requireNonNull(signingKey);
  }

  public static PrivateKeyPair generate() {
    var encryptionKeys = Crypto.generateEncryptionKeys();
    var signingKeys = Crypto.generateSigningKeys();
    return new PrivateKeyPair(
        new PublicKeyPair(encryptionKeys.getPublic(), signingKeys.getPublic()),
        encryptionKeys.getPrivate(),
        signingKeys.getPrivate());
  }

  public PublicKeyPair publicKeys() {
    return publicKeys;
  }

  PrivateKey decryptionKey() {
    return decryptionKey;
  }

  PrivateKey signingKey() {
    return signingKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof PrivateKeyPair)) {
      return false;
    }
    PrivateKeyPair that = (PrivateKeyPair) o;
    return publicKeys.equals(that.publicKeys)
        && decryptionKey.equals(that.decryptionKey)
        && signingKey.equals(that.signingKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(publicKeys, decryptionKey, signingKey);
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", PrivateKeyPair.class.getSimpleName() + "[", "]")
        .add("publicKeys=" + publicKeys)
        .add("decryptionKey=" + decryptionKey)
        .add("signingKey=" + signingKey)
        .toString();
  }
}

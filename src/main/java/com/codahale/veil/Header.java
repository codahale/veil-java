package com.codahale.veil;

import com.google.common.io.ByteStreams;

class Header {
  static final int LEN = AEAD.KEY_LEN + 4 + 4 + Veil.DIGEST_LEN;
  private final byte[] sessionKey;
  private final int headerCount;
  private final int messageLen;
  private final byte[] digest;

  Header(byte[] sessionKey, int headerCount, int messageLen, byte[] digest) {
    this.sessionKey = sessionKey;
    this.headerCount = headerCount;
    this.messageLen = messageLen;
    this.digest = digest;
  }

  static Header parse(byte[] input) {
    var in = ByteStreams.newDataInput(input);
    var sessionKey = new byte[AEAD.KEY_LEN];
    in.readFully(sessionKey);
    var headerCount = in.readInt();
    var paddingLen = in.readInt();
    var digest = new byte[Veil.DIGEST_LEN];
    in.readFully(digest);

    return new Header(sessionKey, headerCount, paddingLen, digest);
  }

  byte[] sessionKey() {
    return sessionKey;
  }

  int headerCount() {
    return headerCount;
  }

  int messageLen() {
    return messageLen;
  }

  byte[] digest() {
    return digest;
  }

  byte[] toByteArray() {
    var out = ByteStreams.newDataOutput();
    out.write(sessionKey);
    out.writeInt(headerCount);
    out.writeInt(messageLen);
    out.write(digest);
    return out.toByteArray();
  }
}

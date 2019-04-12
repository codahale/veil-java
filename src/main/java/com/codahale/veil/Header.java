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
package com.codahale.veil;

import com.google.common.io.ByteStreams;

class Header {
  static final int LEN = EtM.KEY_LEN + 4 + 4 + Veil.DIGEST_LEN;
  private final byte[] sessionKey;
  private final int messageOffset;
  private final int messageLen;
  private final byte[] digest;

  Header(byte[] sessionKey, int messageOffset, int messageLen, byte[] digest) {
    this.sessionKey = sessionKey;
    this.messageOffset = messageOffset;
    this.messageLen = messageLen;
    this.digest = digest;
  }

  static Header parse(byte[] input) {
    var in = ByteStreams.newDataInput(input);
    var sessionKey = new byte[EtM.KEY_LEN];
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

  int messageOffset() {
    return messageOffset;
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
    out.writeInt(messageOffset);
    out.writeInt(messageLen);
    out.write(digest);
    return out.toByteArray();
  }
}

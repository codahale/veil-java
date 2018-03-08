# veil

_Stupid crypto tricks._

**You should, under no circumstances, use this.**

Veil is an experiment with building a format for confidential, authentic multi-recipient messages
which is indistinguishable from random noise by an attacker. Unlike e.g. GPG messages, Veil messages
contain no metadata or format details which are not encrypted. As a result, a global passive
adversary would be unable to gain any information from a Veil message beyond traffic analysis.
Messages can be padded with random bytes to disguise their true length. It uses XSalsa20Poly1305
with misuse-resistant nonces for authenticated encryption, X25519/HSalsa20 ECDH for key agreement,
and HMAC-SHA-512/256 for integrity checking.

All encrypted packets consist of a 24-byte nonce, an arbitrary number of bytes of data, and a
16-byte Poly1305 authenticator.

A Veil message begins with an 8-byte header, encrypted with the message's session key. The header
consists of two big-endian 32-bit integers. The first is the offset of the data packet inside the
Veil message, the second is the length of the data packet. Following the header are an arbitrary
number of copies of the message's session key and a HMAC-SHA-512/256 digest of the plaintext (using
the sender and recipient's X25519/HSalsa20 shared secret), encrypted with the X25519/HSalsa20 shared
secret between the public keys of the recipients and the private key of the sender. After the
encrypted keys comes the data packet, encrypted with the message's session key. The data packet
consists of an arbitrary number of bytes. Finally, an arbitrary number of random bytes may be added
to the end of the message as padding.

## What's the point

1. Veil messages can be read by all of the intended recipients. None of the recipients can modify
   the message or forge additional messages.
2. Veil messages are tamper-proof. If a single bit of the message is changed, all of the recipients 
   will know.
3. Veil messages are non-repudiable.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.   

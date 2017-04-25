# veil

_Stupid crypto tricks._

**You should, under no circumstances, use this.**

Veil is an experiment with building a format for confidential, authentic multi-recipient messages
which is indistinguishable from random noise by an attacker. Unlike e.g. GPG messages, Veil messages
contain no metadata or format details which are not encrypted. As a result, a global passive
adversary would be unable to gain any information from a Veil message beyond traffic analysis.
Messages can be padded with random bytes to disguise their true length. It uses XSalsa20Poly1305
with misuse-resistant nonces for authenticated encryption, Curve25519 ECDH for key agreement, and
Ed25519 for signing.

All encrypted packets consist of a 24-byte nonce, an arbitrary number of bytes of data, and a
16-byte Poly1305 authenticator.

A Veil message begins with an 8-byte header, encrypted with the message's session key. The header
consists of two little-endian 32-bit integers. The first is the offset of the data packet inside the
Veil message, the second is the length of the data packet. Following the header are an arbitrary
number of copies of the message's session key, encrypted with the ECDH shared secret between the
public keys of the recipients and the private key of the sender. After the encrypted keys comes the
data packet, encrypted with the message's session key. The data packet consists of an arbitrary
number of bytes followed by a 64-byte Ed25516 signature of the encrypted header, encrypted keys, and
plaintext. Finally, an arbitrary number of random bytes may be added to the end of the message as 
padding.

# veil

_Stupid crypto tricks._

**You should, under no circumstances, use this.**

Veil is an experiment with building a format for confidential, authentic multi-recipient messages
which is indistinguishable from random noise by an attacker. Unlike e.g. GPG messages, Veil messages
contain no metadata or format details which are not encrypted. As a result, a global passive
adversary would be unable to gain any information from a Veil message beyond traffic analysis.
Messages can be padded with random bytes to disguise their true length. It uses HKDF-SHA-512/256 for
key derivation, AES-256-CTR for confidentiality, HMAC-SHA512/256 for authentication, X448 for key
agreement, and SHA-512/256 for integrity.

All encrypted packets consist of a 16-byte salt, a 16-byte nonce, an arbitrary number of bytes of
data encrypted with AES-256-CTR, and a 32-byte HMAC-SHA512/256 digest of the length of any
authenticated data as a 32-bit big-endian integer, any authenticated data, and the ciphertext.
HKDF-SHA-512/256 is used with the salt, the key, and 1024 iterations to produce 64 bytes of derived
data, the first 32 bytes of which are used as the AES key and the second 32 bytes of which are used
as the HMAC key.

AES-CTR and HMAC were selected for their indistinguishability from random noise. Polynomial
authenticators like GCM and Poly1305 have internal biases.

A Veil message begins with a series of fixed-length encrypted headers, each of which contains a copy
of the 32-byte session key, the number of total headers, the length of the plaintext message, and a
SHA-512/256 digest of the plaintext message. Following the headers is an encrypted packet containing
the message plus an arbitrary number of random padding bytes, using the full set of encrypted
headers as authenticated data.

To decrypt a message, the recipient traverses the message, searching for a decryptable header using
the shared secret between sender and recipient. When a header is decrypted, the session key is used
to decrypt the encrypted message, padding is removed, and the digest of the recovered plaintext is
compared to the digest contained in the header.

## What's the point

1. Veil messages can be read by all of the intended recipients. None of the recipients can modify
   the message or forge additional messages without being able to forge an encrypted header.
2. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
3. Veil messages are non-repudiable.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.

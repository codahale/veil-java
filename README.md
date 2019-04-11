# veil

_Stupid crypto tricks._

**You should, under no circumstances, use this.**

## What is Veil?

Veil is an experiment with building a format for confidential, authentic multi-recipient messages
which are indistinguishable from random noise by an attacker. Unlike e.g. GPG messages, Veil
messages contain no metadata or format details which are not encrypted. As a result, a global
passive adversary would be unable to gain any information from a Veil message beyond traffic
analysis. Messages can be padded with random bytes to disguise their true length. It uses
AES-256-CTR for confidentiality, HMAC-SHA-512/256 for authentication, X448 for key agreement,
HKDF-SHA-512/256 for key derivation, and SHA-512/256 for integrity.

## Key Agreement

Shared secrets are generated using X448 ECDH, then HKDF-SHA-512/256 is used to derive a 64-byte key.
The sender and recipient's public keys are encoded as X.509 public keys, concatenated, and used as
the salt for HKDF. The static value `{0x76, 0x65, 0x69, 0x6C}` is used as the information input for
HKDF. As a result, the derived key is unique to the two parties using Veil.

## AEAD Construction

A 64-byte key is split into subkeys: the first 32 bytes as used as the AES key; the second 32 bytes
are used as the HMAC key. The plaintext is encrypted with AES-256-CTR using a random, 16-byte nonce.
HMAC-SHA-512/256 is used to hash the authenticated data, the nonce, the ciphertext, and the number
of bits of authenticated data encoded as a 64-bit big-endian value. The nonce, ciphertext, and HMAC
digest are concatenated and returned.

This is essentially the same as the construction in
[draft-mcgrew-aead-aes-cbc-hmac-sha2-05](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt)
the [encrypt-then-authenticate
construction](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/subtle/EncryptThenAuthenticate.java)
in Tink.

AES-CTR and HMAC were selected for their indistinguishability from random noise. Unlike polynomial
authenticators like GCM and Poly1305, the outputs of AES-CTR and HMAC are uniformly distributed.

## Message Construction

A Veil message begins with a series of fixed-length encrypted headers, each of which contains a copy
of the 32-byte session key, the offset in bytes where the message begins, the length of the
plaintext message in bytes, and a SHA-512/256 digest of the plaintext message. Following the headers
is an encrypted packet containing the message plus an arbitrary number of random padding bytes,
using the full set of encrypted headers as authenticated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between sender and recipient. When a header is successfully decrypted, the
session key is used to decrypt the encrypted message, the padding is removed, and the digest of the
recovered plaintext is compared to the digest contained in the header.

## What's the point

1. Veil messages can be read by all of the intended recipients. None of the recipients can modify
   the message or forge additional messages without being able to forge encrypted headers for the
   other recipients (i.e., break X448) or find a message with the same SHA-512/256 digest (i.e. 
   break SHA2).
2. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
3. Veil messages are non-repudiable.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.
6. The number of recipients in a Veil message can be obscured from recipients by adding blocks of 
   random noise instead of encrypted headers.

# veil

_Stupid crypto tricks._

**You should, under no circumstances, use this.**

## What is Veil?

Veil is an experiment with building a format for confidential, authentic multi-recipient messages
which are indistinguishable from random noise by an attacker. Unlike e.g. GPG messages, Veil
messages contain no metadata or format details which are not encrypted. As a result, a global
passive adversary would be unable to gain any information from a Veil message beyond traffic
analysis. Messages can be padded with random bytes to disguise their true length. It uses
HKDF-SHA-512/256 for key derivation, AES-256-CTR for confidentiality, HMAC-SHA512/256 for
authentication, X448 for key agreement, and SHA-512/256 for integrity.

AES-CTR and HMAC were selected for their indistinguishability from random noise. Polynomial
authenticators like GCM and Poly1305 have internal biases.

## AEAD Construction

Given a secret of arbitrary length, HKDF-SHA-512/256 and a 32-byte random nonce are used to generate
64 bytes of derived data. The first 32 bytes are used as an AES-256-CTR key; the last 32 bytes are
used as an HMAC-SHA-512/256 key. The plaintext is encrypted with AES-256-CTR with an all-zero IV.
HMAC-SHA-512/256 is used to hash the authenticated data, the ciphertext, and the number of bits of
authenticated data encoded as a 64-bit big-endian value. The nonce, ciphertext, and HMAC digest are
concatenated and returned.

This is similar to the
[draft-mcgrew-aead-aes-cbc-hmac-sha2-05](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt)
construction or the [encrypt-then-authenticate
construction](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/subtle/EncryptThenAuthenticate.java)
in Tink, with the exception that the two subkeys are derived via HKDF from the initial key using a
nonce. As a result, no two ciphertexts will share the same AES or HMAC keys.

## Message Construction

A Veil message begins with a series of fixed-length encrypted headers, each of which contains a copy
of the 32-byte session key, the number of total headers, the length of the plaintext message, and a
SHA-512/256 digest of the plaintext message. Following the headers is an encrypted packet containing
the message plus an arbitrary number of random padding bytes, using the full set of encrypted
headers as authenticated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between sender and recipient. When a header is successfully decrypted, the
session key is used to decrypt the encrypted message, the padding is removed, and the digest of the
recovered plaintext is compared to the digest contained in the header.

## What's the point

1. Veil messages can be read by all of the intended recipients. None of the recipients can modify
   the message or forge additional messages without being able to forge an encrypted header.
2. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
3. Veil messages are non-repudiable.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.

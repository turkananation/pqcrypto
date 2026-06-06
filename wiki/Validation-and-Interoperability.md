# Validation & Interoperability

`pqcrypto`'s correctness rests on two complementary kinds of evidence:
**Known-Answer Tests (KATs)** prove it reproduces NIST's reference byte outputs,
and **OpenSSL interoperability** proves a real independent implementation accepts
its keys and ciphertexts and derives the same shared secret.

## Known-Answer Tests (KATs)

Checked-in NIST vectors are reproduced byte-for-byte in the repository's test
suite.

- **ML-KEM:** 1000 vectors per parameter set — 3000 total (512/768/1024).
- **ML-DSA:** byte-exact across the full matrix — 3 parameter sets × {det,
  hedged} × {raw, pure, hashed} — totalling 300 key generations and 1800
  signatures that all verify.

Canonical details, file hashes, and gate commands:
[MLKEM_TESTING.md](https://github.com/turkananation/pqcrypto/blob/main/doc/MLKEM_TESTING.md).

## OpenSSL interoperability (ML-KEM)

The interop harness runs a suite (tests A–G) for **all three** ML-KEM parameter
sets against OpenSSL's native ML-KEM (via `libcrypto`).

| Test  | What it proves                                             |
| ----- | ---------------------------------------------------------- |
| A / B | Each implementation is internally self-consistent.         |
| C     | OpenSSL decapsulates a `pqcrypto` ciphertext (×fuzz).      |
| D     | `pqcrypto` decapsulates an OpenSSL ciphertext (×fuzz).     |
| E     | Same 64-byte seed ⇒ byte-identical public keys.            |
| F     | Public-key wire round-trip is byte-identical.              |
| G     | Implicit-rejection secret agrees on an invalid ciphertext. |

Only **public keys, ciphertexts, and 64-byte seeds** cross the boundary — never
expanded private keys — mirroring how ML-KEM is actually deployed. Verified
against OpenSSL 3.5.x and, in CI, 4.0.0.

Canonical matrix, versions, and reproduction steps:
[OPENSSL_INTEROP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/OPENSSL_INTEROP.md).

## Why interop matters

KATs prove conformance to the standard's reference outputs. Interop proves the
complementary real-world property: a key or ciphertext produced by one
conformant implementation is accepted by another, and both derive the **same**
shared secret. That is the property that decides whether a Dart client can talk
to an OpenSSL-based server. It unlocks hybrid TLS components, Dart ↔ C/Python/
Node/Go exchange, and dual-stack migration — see the
[Cookbook](Cookbook) interop ideas.

## Run it yourself

```bash
dart test                                  # full unit + KAT suite (VM)
dart test -p chrome                        # dart2js web gate
dart test -p chrome --compiler dart2wasm   # dart2wasm web gate
```

The OpenSSL interop harness lives in
[`tool/openssl_interop/`](https://github.com/turkananation/pqcrypto/tree/main/tool/openssl_interop)
and needs OpenSSL ≥ 3.5. See
[OPENSSL_INTEROP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/OPENSSL_INTEROP.md)
for setup.

## Caveat

This is *functional* conformance and wire compatibility — not a constant-time,
side-channel, or CMVP/FIPS 140 claim. See [Security Posture](Security-Posture)
and [FIPS Compliance](FIPS-Compliance).

# Validation & Interoperability

`pqcrypto`'s correctness rests on two complementary kinds of evidence:
**Known-Answer / ACVP tests** prove it reproduces NIST's reference byte outputs,
and **native-provider interoperability** (OpenSSL and liboqs) proves real
independent implementations accept its keys, ciphertexts, and signatures and
agree on the result.

## Known-Answer / ACVP tests

Checked-in NIST vectors are reproduced byte-for-byte in the repository's test
suite.

- **ML-KEM:** 1000 vectors per parameter set — 3000 total (512/768/1024).
- **ML-DSA:** byte-exact across the full matrix — 3 parameter sets × {det,
  hedged} × {raw, pure, hashed} — totalling 300 key generations and 1800
  signatures that all verify.
- **SLH-DSA:** byte-exact across all 12 parameter sets (both the SHAKE and SHA-2
  hash families) on the 1,248-case official NIST ACVP sample corpus
  (keyGen / sigGen / sigVer).

Canonical details, file hashes, and gate commands:
[MLKEM_TESTING.md](https://github.com/turkananation/pqcrypto/blob/main/doc/MLKEM_TESTING.md).

## Native-provider interoperability

Every standardized family is cross-checked against **two** independent native
implementations — OpenSSL `libcrypto` and **liboqs** — on each CI run, across
all parameter sets of all three families:

| Provider | ML-KEM (512/768/1024) | ML-DSA (44/65/87) | SLH-DSA (all 12 sets) |
| -------- | --------------------- | ----------------- | --------------------- |
| OpenSSL  | Full A–G matrix: byte-exact keys/ciphertexts, bidirectional decapsulation, implicit rejection | Seeded keys + hedged context signatures byte-exact; cross-verify both directions | Seeded keys + internal and external context signatures byte-exact; OpenSSL verifies |
| liboqs   | Deterministic keygen/encaps byte-exact; random exchange both directions; implicit rejection agrees | Context signatures verify both directions; tampering rejected | Context signatures verify both directions |

The two providers are complementary: **OpenSSL** uses seeded key generation, so
it proves the *wire output is byte-identical*; **liboqs** uses random keys and
proves *functional interoperability in both directions*. OpenSSL pins **4.0.1**
in CI (and works against 3.5.x); liboqs pins **0.15.0** at an exact commit with
its OpenSSL acceleration disabled, so it stays a genuinely independent backend.
Per-signature tamper/negative rejection for SLH-DSA is covered by the main test
suite rather than the cross-provider harness.

### ML-KEM A–G detail

The ML-KEM OpenSSL suite is the most exhaustively staged:

| Test  | What it proves                                             |
| ----- | ---------------------------------------------------------- |
| A / B | Each implementation is internally self-consistent.         |
| C     | OpenSSL decapsulates a `pqcrypto` ciphertext (×fuzz).      |
| D     | `pqcrypto` decapsulates an OpenSSL ciphertext (×fuzz).     |
| E     | Same 64-byte seed ⇒ byte-identical public keys.            |
| F     | Public-key wire round-trip is byte-identical.              |
| G     | Implicit-rejection secret agrees on an invalid ciphertext. |

Only **public keys, ciphertexts, and 64-byte seeds** cross the boundary — never
expanded private keys — mirroring how ML-KEM is actually deployed.

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

The interop harnesses live in
[`tool/openssl_interop/`](https://github.com/turkananation/pqcrypto/tree/main/tool/openssl_interop)
(needs OpenSSL ≥ 3.5) and
[`tool/liboqs_interop/`](https://github.com/turkananation/pqcrypto/tree/main/tool/liboqs_interop)
(needs liboqs 0.15.0). See
[OPENSSL_INTEROP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/OPENSSL_INTEROP.md)
for setup of both.

## Caveat

This is *functional* conformance and wire compatibility — not a constant-time,
side-channel, or CMVP/FIPS 140 claim. See [Security Posture](Security-Posture)
and [FIPS Compliance](FIPS-Compliance).

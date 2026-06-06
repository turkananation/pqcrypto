# FIPS Compliance

`pqcrypto` implements NIST Federal Information Processing Standards and
demonstrates conformance through checked-in test vectors and interoperability —
but it is **not** a CMVP/FIPS 140 validated module. This page explains the
distinction precisely; the canonical sources are
[FIPS_COMPLIANCE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_COMPLIANCE.md)
and
[FIPS_140_BOUNDARY.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_140_BOUNDARY.md).

## Standards implemented

| Standard   | Scope in pqcrypto                              | State                                                |
| ---------- | ---------------------------------------------- | ---------------------------------------------------- |
| FIPS 203   | ML-KEM-512/768/1024                            | Byte-exact KATs + OpenSSL interop                    |
| FIPS 204   | ML-DSA-44/65/87 (incl. HashML-DSA)             | Byte-exact KATs (raw/pure/hashed × det/hedged)       |
| FIPS 180-4 | SHA-256/384/512 (vendored, for HashML-DSA)     | Used internally                                      |
| FIPS 202   | SHA3-256/512, SHAKE128/256 (vendored, partial) | Internal; full FIPS 202 + SP 800-185 planned (0.7.0) |

## Algorithm conformance vs. module validation

- **What is demonstrated.** Each algorithm reproduces the official NIST
  Known-Answer-Test outputs byte-for-byte, and ML-KEM additionally interoperates
  with OpenSSL (see [Validation & Interoperability](Validation-and-Interoperability)).
  This is strong evidence that the *algorithms* are implemented correctly.
- **What is NOT claimed.** CMVP (Cryptographic Module Validation Program)
  validates a specific compiled boundary under controlled conditions. Because
  pure Dart compiles to many disparate targets (AOT ARM64, `dart2js`,
  `dart2wasm`), a source-level package cannot claim "FIPS 140 validated." If your
  regime requires a certificate, use a validated module (e.g. via FFI).

## Wording to use (and avoid)

When you describe a system built on `pqcrypto`, keep claims accurate:

- **Allowed:** "FIPS 203-aligned ML-KEM with checked-in KAT evidence",
  "FIPS 204-aligned ML-DSA, byte-exact on the checked-in KAT corpus",
  "OpenSSL interop A–G passes for ML-KEM-512/768/1024",
  "best-effort zeroization in Dart".
- **Not allowed:** "FIPS validated", "CMVP validated", "certified",
  "constant-time guarantee", "memory is securely erased".

## See also

- [Security Posture](Security-Posture) — threat model and side-channel stance.
- [Validation & Interoperability](Validation-and-Interoperability) — the
  evidence.
- Canonical:
  [FIPS_COMPLIANCE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_COMPLIANCE.md)
  ·
  [FIPS_140_BOUNDARY.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_140_BOUNDARY.md)

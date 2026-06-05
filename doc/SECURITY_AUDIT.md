# Security Audit and Risk Register

Last updated: 2026-06-05

This document tracks security-relevant findings against the current repository
state. It is evidence-scoped: when a finding is not directly verified in this
pass, it is marked as open or needs verification.

## Executive Summary

| Component | Current security posture                                                                 |
| --------- | ---------------------------------------------------------------------------------------- |
| ML-KEM    | Supported surface with KAT, input-validation, Keccak, web, and OpenSSL interop evidence. |
| ML-DSA    | FIPS 204-aligned surface, byte-exact on the checked-in KAT corpus; best-effort side-channel hardening. |
| Common    | Vendored FIPS 202 + FIPS 180-4 SHA-2; no runtime dependencies.                            |
| Package   | Not FIPS 140/CMVP validated.                                                             |

## Current Verification Snapshot

- `dart analyze`: exits 0, with three info-level `avoid_print` notes in
  `test/kat_evaluator_test.dart`.
- `dart test`: **green** (160 tests). Completes the ML-KEM KAT runner (1000
  vectors each at 512/768/1024) and the ML-DSA KAT runner (300 byte-exact key
  generations + 1800 byte-exact signatures, all verifying).
- `dart test -p chrome` and `dart test -p chrome --compiler dart2wasm` pass.

## Resolved or Evidence-Backed Improvements

| ID         | Area                       | Current evidence                                                              |
| ---------- | -------------------------- | ----------------------------------------------------------------------------- |
| KEM-01     | ML-KEM input validation    | `kem_validation_test.dart` covers pk/sk/ct validation paths.                  |
| KEM-02     | Canonical ML-KEM reduction | `poly_test.dart` covers `Poly.barrettReduce` canonical residues.              |
| KEM-03     | KAT runner discovery       | Runner is `test/kat_evaluator_test.dart`, so it is discovered by `dart test`. |
| HASH-01    | Vendored SHA3/SHAKE        | `keccak_test.dart` covers FIPS 202 known-answer and XOF behavior.             |
| INTEROP-01 | OpenSSL interoperability   | `tool/openssl_interop/` covers A-G interop for all ML-KEM parameter sets.     |
| DSA-01     | Per-level `tau` values     | `DilithiumParams` contains 39/49/60 for ML-DSA-44/65/87.                      |
| DSA-02     | Production `print` leakage | `rg "print\\(" lib` shows no production-library `print()` calls.              |
| DSA-10     | ML-DSA correctness         | `mldsa_kat_test.dart`: 300 keygens + 1800 signatures byte-exact, all verify.  |
| DSA-11     | ML-DSA KAT validation      | Repo-local corpus `test/data/MLDSA` (18 files); discovered runner; no machine paths. |
| DSA-12     | Norm-check side channel    | `_checkNorm` replaced by no-early-exit `_normExceeds` (all 256 coeffs).       |
| DSA-13     | Sampler exhaustion         | `RejNTTPoly`/`RejBoundedPoly`/`SampleInBall` use an unbounded incremental XOF. |
| SEC-01     | Secret lifetime            | `lib/src/common/zeroize.dart`; applied in keygen/sign `finally` blocks.       |
| SHA2-01    | HashML-DSA pre-hash        | `sha2_test.dart` pins SHA-256/384/512 against direct NIST vectors.            |

## Open Findings

| ID     | Severity | Area                    | Finding                                                                      | Evidence                                        | Required action                               |
| ------ | -------- | ----------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------- |
| DSA-20 | Medium   | ML-DSA side channels    | `_normExceeds` and rejection loops have no early exit, but per-iteration branch directions are not provably constant-time in pure Dart. | `lib/src/algos/dilithium/dsa.dart`.             | Deeper review; accept best-effort posture for a pure-Dart lib and document it. |
| DSA-21 | Low      | HashML-DSA coverage     | Only the level-bound SHA-2 pre-hash is exposed; other approved pre-hashes (e.g. SHAKE) are not surfaced. | `lib/src/algos/dilithium/dsa.dart`.             | Add SHAKE pre-hash paths if broader HashML-DSA support is required. |
| KEM-10 | Medium   | Decapsulation selection | `decapsulate` branches on constant-time comparison result.                   | `lib/src/algos/kyber/kem.dart`.                 | Consider constant-time select for K/J output. |
| KEM-11 | Medium   | RNG allocation          | `_randomBytes` creates `Random.secure()` per call.                           | `lib/src/algos/kyber/kem.dart`.                 | Cache or inject RNG if measurement warrants.  |
| DOC-01 | Medium   | Assurance wording       | Any broad "FIPS validated" claim would exceed current evidence.              | [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md).       | Keep claim wording evidence-scoped.           |

## ML-KEM Security Boundary

ML-KEM is the package's supported security surface. Current evidence covers:

- standard parameter sizes and encodings;
- checked-in KAT vectors;
- keygen/encaps/decaps and invalid decapsulation vectors;
- public-key, secret-key, and ciphertext validation;
- vendored FIPS 202 primitives;
- web compiler round-trips;
- OpenSSL interop for ML-KEM-512/768/1024.

Remaining hardening work should focus on secret lifetime, constant-time output
selection, benchmarking the RNG allocation path, and maintaining interop/KAT
coverage as the code changes.

## ML-DSA Security Boundary

ML-DSA is now FIPS 204-aligned with byte-exact KAT evidence for 44/65/87. The
Definition of Done in
[MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md) is complete. The
implemented security posture includes:

- byte-exact KAT conformance across raw/pure/hashed × deterministic/hedged;
- hedged-by-default signing (explicit, discouraged deterministic path);
- total verification (returns `false`, never throws, on malformed input);
- a no-early-exit norm check (`_normExceeds`) over all 256 coefficients;
- unbounded incremental-XOF rejection sampling (no fixed-buffer exhaustion);
- best-effort secret zeroization in keygen/sign `finally` blocks.

Residual, accepted risks (do not affect KAT conformance):

- Per-iteration branch directions in the norm check and rejection loops are a
  best-effort, not provably constant-time, posture — a known limitation of pure
  Dart targeting the VM, dart2js, and dart2wasm. Best-effort zeroization is also
  not a hard memory-erasure guarantee under Dart's GC. See DSA-20.
- HashML-DSA exposes only the level-bound SHA-2 pre-hash (DSA-21).
- This is algorithm/KAT conformance evidence, not a CMVP/FIPS 140 validation.

## Audit Commands

```bash
rg "print\\(" lib
rg "Random\\.secure|_normExceeds|secureZero|fillRange" lib
dart analyze
dart test test/kat_evaluator_test.dart   # ML-KEM KAT
dart test test/mldsa_kat_test.dart       # ML-DSA KAT
dart test
```

Use the full suite result to constrain documentation claims. KAT conformance is
algorithm evidence, not a CMVP/FIPS 140 module validation.

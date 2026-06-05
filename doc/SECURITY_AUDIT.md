# Security Audit and Risk Register

Last updated: 2026-06-05

This document tracks security-relevant findings against the current repository
state. It is evidence-scoped: when a finding is not directly verified in this
pass, it is marked as open or needs verification.

## Executive Summary

| Component | Current security posture                                                                 |
| --------- | ---------------------------------------------------------------------------------------- |
| ML-KEM    | Supported surface with KAT, input-validation, Keccak, web, and OpenSSL interop evidence. |
| ML-DSA    | Experimental exported surface; current full test suite fails in ML-DSA/debug tests.      |
| Common    | Vendored FIPS 202 implementation; no runtime dependencies.                               |
| Package   | Not FIPS 140/CMVP validated.                                                             |

## Current Verification Snapshot

- `dart analyze`: exits successfully, with three info-level `avoid_print` notes
  in `test/kat_evaluator_test.dart`.
- `dart test`: exits unsuccessfully because ML-DSA/debug tests fail.
- The same `dart test` run completes the ML-KEM KAT runner for 1000 vectors each
  at ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

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

## Open Findings

| ID     | Severity | Area                    | Finding                                                                      | Evidence                                        | Required action                               |
| ------ | -------- | ----------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------- |
| DSA-10 | High     | ML-DSA correctness      | Full suite fails in ML-DSA packing/symmetric/debug tests.                    | `dart test` failure snapshot.                   | Fix failing tests before readiness claim.     |
| DSA-11 | High     | ML-DSA KAT validation   | ML-DSA has no repo-local KAT corpus; debug/KAT tests use a Windows KAT root. | `mldsa_debug_test.dart`, `mldsa_kat_test.dart`. | Vendor corpus or remove hardcoded paths.      |
| DSA-12 | High     | Side channels           | `_checkNorm` returns early on first violation.                               | `lib/src/algos/dilithium/dsa.dart`.             | Accumulate a flag over all coefficients.      |
| SEC-01 | High     | Secret lifetime         | No shared zeroization utility exists for secret buffers.                     | `rg secureZero/fillRange` in `lib/`.            | Add zeroization helpers and `finally` use.    |
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

ML-DSA must be described as experimental. The API is exported, but exported is
not validated. Do not use ML-DSA for production signatures until:

1. the ML-DSA unit and integration tests pass;
2. a repo-local ML-DSA KAT corpus is added and passes for 44/65/87;
3. `_checkNorm` and other rejection paths are reviewed for timing behavior;
4. secret-zeroization strategy is applied to signing and keygen intermediates;
5. readiness wording is updated in README, [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md),
   [ROADMAP.md](ROADMAP.md), and [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md).

The FIPS 204 implementation and release plan is
[MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md). Treat that
document as the controlling checklist for closing ML-DSA findings.

## Audit Commands

```bash
rg "print\\(" lib
rg "Random\\.secure|_checkNorm|secureZero|fillRange" lib
dart analyze
dart test test/kat_evaluator_test.dart
dart test
```

Use the full suite result to constrain documentation claims. A passing ML-KEM
KAT run does not imply ML-DSA readiness.

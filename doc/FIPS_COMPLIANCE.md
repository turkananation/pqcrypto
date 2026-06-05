# FIPS Evidence and Claim Boundary

Last updated: 2026-06-05

This document records standards alignment evidence for the current repository.
It is not a CMVP/FIPS 140 validation certificate, and it must not be cited as
one.

## Summary

| Standard | Scope in repo                   | Current status                                                                  |
| -------- | ------------------------------- | ------------------------------------------------------------------------------- |
| FIPS 203 | ML-KEM-512/768/1024             | Evidence-backed implementation alignment: checked-in KATs plus OpenSSL interop. |
| FIPS 202 | SHA3-256/512, SHAKE128/256      | Vendored implementation with known-answer tests.                                |
| FIPS 204 | ML-DSA-44/65/87                 | Implemented/exported but not production validated; full suite currently fails.  |
| FIPS 140 | Cryptographic module validation | Not claimed. No CMVP validation record exists in this repo.                     |

## FIPS 203 - ML-KEM

Current ML-KEM evidence:

- `test/data/kat_MLKEM_512.rsp`, `kat_MLKEM_768.rsp`, and
  `kat_MLKEM_1024.rsp` are checked in.
- `test/kat_evaluator_test.dart` verifies key generation, encapsulation,
  decapsulation, and invalid decapsulation fields where present.
- The latest local run used for this documentation pass completed 1000 vectors
  for each ML-KEM parameter set.
- `test/kem_validation_test.dart`, `test/pack_test.dart`, `test/poly_test.dart`,
  `test/keygen_derivation_test.dart`, `test/keccak_test.dart`, and
  `test/roundtrip_test.dart` cover key input-validation and regression risks.
- `tool/openssl_interop/` and `.github/workflows/interop.yml` provide the
  OpenSSL A-G interop proof for all three parameter sets.

See [MLKEM_TESTING.md](MLKEM_TESTING.md) and
[OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) for the detailed evidence.

Acceptable wording:

> `pqcrypto` provides a FIPS 203-aligned ML-KEM implementation that passes the
> checked-in KAT corpus and OpenSSL interoperability checks described in this
> repository.

Avoid wording such as:

- "FIPS validated"
- "CMVP validated"
- "FIPS 140 compliant module"
- "fully certified"

## FIPS 202 - SHA3/SHAKE

The package vendors its FIPS 202 primitives in `lib/src/common/keccak.dart` and
uses wrapper functions in `lib/src/common/shake.dart`.

Evidence:

- `test/keccak_test.dart` pins SHA3-256, SHA3-512, SHAKE128, and SHAKE256
  against known-answer values, including multi-block and XOF prefix-stability
  cases.
- `pubspec.yaml` has no runtime dependencies; `lints` and `test` are
  dev-only dependencies.

The vendored implementation is not a FIPS-validated module. It is implementation
evidence for this package's correctness boundary.

## FIPS 204 - ML-DSA

ML-DSA is present and exported:

- `lib/src/algos/dilithium/`
- `MlDsa`
- `DilithiumParams`
- `DilithiumParameter`

Current status is experimental. The full local `dart test` run used for this
documentation pass fails in ML-DSA/debug tests:

- `test/dsa_pack_test.dart`
- `test/dsa_symmetric_test.dart`
- `test/mldsa_debug_test.dart`
- `test/mldsa_kat_test.dart` skips when the same external KAT root is missing

Known blockers include:

| Area                   | Evidence or symptom                                                                                 |
| ---------------------- | --------------------------------------------------------------------------------------------------- |
| Packing round-trips    | Negative centered values unpack as field residues in current failures.                              |
| ExpandS sampling       | `Bad state: Too few elements` in `dsa_symmetric_test.dart`.                                         |
| Debug/KAT test paths   | `mldsa_debug_test.dart` fails and `mldsa_kat_test.dart` skips against a hardcoded Windows KAT root. |
| KAT validation         | No repo-local ML-DSA KAT corpus is checked in.                                                      |
| Side-channel hardening | `_checkNorm` still returns early on first norm violation.                                           |
| Zeroization            | No shared `secureZero` utility is implemented.                                                      |

The canonical completion plan is
[MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md). Use that guide
for the FIPS 204 source map, external/internal API requirements, HashML-DSA
decision, KAT plan, side-channel work, and release gates.

Do not describe ML-DSA as production-ready until all relevant tests pass, a
repo-local KAT corpus exists, and the readiness language has been updated in
[PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) and [ROADMAP.md](ROADMAP.md).

## RNG and Module Validation

The package uses `Random.secure()` for random bytes. That delegates to the
platform CSPRNG and is appropriate for a pure Dart package, but it is not a
repository-level SP 800-90A DRBG validation claim. A formal FIPS 140 module
would need its own validated entropy, DRBG, operational environment, and
security policy.

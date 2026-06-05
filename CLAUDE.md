# pqcrypto Project Overview for AI Assistants

Last updated: 2026-06-05

## Project Summary

`pqcrypto` is a pure Dart post-quantum cryptography package.

- **ML-KEM (FIPS 203):** supported package surface for ML-KEM-512,
  ML-KEM-768, and ML-KEM-1024. Evidence includes checked-in KAT vectors,
  focused unit tests, web tests, and OpenSSL interop.
- **ML-DSA (FIPS 204):** exported but experimental. Do not describe it as
  production-ready; the current full suite fails in ML-DSA/debug tests and no
  repo-local ML-DSA KAT corpus is checked in.
- **Version:** 0.2.1.
- **Runtime dependencies:** none. FIPS 202 SHA3/SHAKE is vendored in
  `lib/src/common/keccak.dart`.
- **Canonical documentation root:** `doc/`.

## Architecture Snapshot

```text
lib/src/
  common/
    keccak.dart          # vendored SHA3-256/512, SHAKE128/256
    shake.dart           # SHAKE wrappers
    poly.dart            # ML-KEM polynomial arithmetic
  algos/
    kyber/               # ML-KEM implementation
      kem.dart           # KyberKem, PqcKem
      indcpa.dart        # K-PKE core
      pack.dart          # ML-KEM serialization/compression
      params.dart        # ML-KEM sizes
    dilithium/           # experimental ML-DSA implementation
      dsa.dart
      params.dart
      poly.dart
      ntt.dart
      packing.dart
      rounding.dart
      symmetric.dart
```

## Current Verification Boundary

Use these commands to understand current state:

```bash
dart analyze
dart test test/kat_evaluator_test.dart
dart test
```

Expected as of this update:

- `dart analyze` succeeds with info-level `avoid_print` notes in
  `test/kat_evaluator_test.dart`.
- `dart test test/kat_evaluator_test.dart` passes and runs 1000 vectors for
  each ML-KEM parameter set.
- `dart test` fails until ML-DSA/debug blockers are fixed.

## Documentation Map

- Start with [doc/INDEX.md](doc/INDEX.md).
- ML-KEM evidence: [doc/MLKEM_TESTING.md](doc/MLKEM_TESTING.md).
- OpenSSL interop: [doc/OPENSSL_INTEROP.md](doc/OPENSSL_INTEROP.md).
- Architecture: [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md).
- Security posture: [doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md).
- Standards claim boundary: [doc/FIPS_COMPLIANCE.md](doc/FIPS_COMPLIANCE.md).
- Work tracker: [doc/PROGRESS_TRACKER.md](doc/PROGRESS_TRACKER.md).
- Roadmap: [doc/ROADMAP.md](doc/ROADMAP.md).

## Development Rules

- Treat ML-KEM and ML-DSA separately. ML-KEM evidence does not imply ML-DSA
  readiness.
- Prefer repo-local fixtures under `test/data`; do not add machine-local KAT
  paths.
- Keep runtime package dependencies at zero unless the package boundary is
  deliberately changed.
- Do not add `print()` to `lib/`.
- Do not claim CMVP/FIPS 140 validation.
- Update docs when public APIs, validation evidence, or security posture change.

## Known High-Priority Work

- Fix ML-DSA packing and `ExpandS` failures.
- Remove or replace the hardcoded Windows KAT root in
  `test/mldsa_debug_test.dart` and `test/mldsa_kat_test.dart`.
- Add repo-local ML-DSA KAT corpus and a discovered test runner.
- Add secret-zeroization helpers and apply them in `finally` blocks.
- Make ML-DSA `_checkNorm` constant-time.
- Decide how explicitly the public API should label experimental ML-DSA.

For details, use [doc/BUGS.md](doc/BUGS.md) and
[doc/IMPROVEMENTS.md](doc/IMPROVEMENTS.md).

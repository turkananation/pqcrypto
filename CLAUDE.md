# pqcrypto Project Overview for AI Assistants

Last updated: 2026-06-05

## Project Summary

`pqcrypto` is a pure Dart post-quantum cryptography package.

- **ML-KEM (FIPS 203):** supported package surface for ML-KEM-512,
  ML-KEM-768, and ML-KEM-1024. Evidence includes checked-in KAT vectors,
  focused unit tests, web tests, and OpenSSL interop.
- **ML-DSA (FIPS 204):** FIPS 204-aligned for ML-DSA-44/65/87. Byte-exact
  against the checked-in KAT corpus (`test/data/MLDSA`) across raw/pure/hashed ×
  deterministic/hedged: 300 key generations and 1800 signatures reproduced
  byte-for-byte, all verifying. External API is hedged-by-default with context
  strings and HashML-DSA (SHA-256/384/512 pre-hash). This is KAT/regression
  evidence, NOT a CMVP/FIPS 140 validation claim.
- **Version:** 0.3.1.
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
    dilithium/           # FIPS 204-aligned ML-DSA implementation
      dsa.dart           # external + internal + HashML-DSA APIs (Algs 1-8)
      params.dart        # parameter sets + computed FIPS 204 Table 2 sizes
      poly.dart
      ntt.dart
      packing.dart
      rounding.dart
      symmetric.dart     # ExpandA/S, sampling, SampleInBall, HashML-DSA pre-hash
  common/
    sha2.dart            # vendored FIPS 180-4 SHA-256/384/512 (HashML-DSA)
    zeroize.dart         # best-effort secret zeroization helpers
```

## Current Verification Boundary

Use these commands to understand current state:

```bash
dart analyze
dart test test/kat_evaluator_test.dart   # ML-KEM KAT (3000 vectors)
dart test test/mldsa_kat_test.dart       # ML-DSA KAT (18 files, all flavours)
dart test
dart test -p chrome                       # dart2js
dart test -p chrome --compiler dart2wasm  # dart2wasm
```

Expected as of this update:

- `dart analyze` exits 0 (info-level `avoid_print` notes remain in
  `test/kat_evaluator_test.dart`).
- The ML-KEM KAT runner passes 1000 vectors per parameter set; the ML-DSA KAT
  runner is byte-exact (300 key generations + 1800 signatures, all verifying).
- `dart test` is **green** (160 tests). The web JS and Wasm gates are green; the
  file-based KAT runners are VM-only and auto-skip on web.

## Documentation Map

- Start with [doc/INDEX.md](doc/INDEX.md).
- ML-KEM evidence: [doc/MLKEM_TESTING.md](doc/MLKEM_TESTING.md).
- OpenSSL interop: [doc/OPENSSL_INTEROP.md](doc/OPENSSL_INTEROP.md).
- Architecture: [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md).
- Security posture: [doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md).
- Standards claim boundary: [doc/FIPS_COMPLIANCE.md](doc/FIPS_COMPLIANCE.md) and
  [doc/FIPS_140_BOUNDARY.md](doc/FIPS_140_BOUNDARY.md).
- Work tracker: [doc/PROGRESS_TRACKER.md](doc/PROGRESS_TRACKER.md).
- ML-DSA release plan:
  [doc/MLDSA_FIPS204_RELEASE_GUIDE.md](doc/MLDSA_FIPS204_RELEASE_GUIDE.md).
- Roadmap: [doc/ROADMAP.md](doc/ROADMAP.md).
- Universal PQC agent framework:
  [doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md)
  and [tool/agent_framework/pqc_framework.yaml](tool/agent_framework/pqc_framework.yaml).

## Development Rules

- Treat ML-KEM and ML-DSA separately. ML-KEM evidence does not imply ML-DSA
  readiness.
- Prefer repo-local fixtures under `test/data`; do not add machine-local KAT
  paths.
- Keep runtime package dependencies at zero unless the package boundary is
  deliberately changed.
- Do not add `print()` to `lib/`.
- Do not claim CMVP/FIPS 140 validation. The rationale and the exact acceptable
  wording live in [doc/FIPS_140_BOUNDARY.md](doc/FIPS_140_BOUNDARY.md).
- Update docs when public APIs, validation evidence, or security posture change.
- For multi-agent PQC workflows, use the committed Claude wrapper at
  `.claude/skills/universal-pqc-framework/SKILL.md`; it is a thin wrapper over
  the canonical framework doc and manifest.

## Known High-Priority Work

ML-DSA FIPS 204 alignment is complete per the Definition of Done in
[doc/MLDSA_FIPS204_RELEASE_GUIDE.md](doc/MLDSA_FIPS204_RELEASE_GUIDE.md) (packing
and `ExpandS` fixed; repo-local corpus + discovered runner; zeroization helpers;
no-early-exit norm check; HashML-DSA). Remaining work:

- Deeper side-channel review: per-iteration branch directions in `_normExceeds`
  and the rejection loops are best-effort, not constant-time, in pure Dart.
- Surface additional approved HashML-DSA pre-hash functions (e.g. SHAKE) beyond
  the level-bound SHA-2 default, if broader HashML-DSA support is desired.
- KEM decapsulation output-selection side-channel review.
- Release decision: tag/version bump and `dart pub publish` are deliberate,
  outward-facing steps left to the maintainer.

For details, use [doc/BUGS.md](doc/BUGS.md) and
[doc/IMPROVEMENTS.md](doc/IMPROVEMENTS.md).

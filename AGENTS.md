# AI Development Workflows for pqcrypto

Last updated: 2026-06-05

This file tells coding agents how to work in this repository. Ground every
claim in the live code, [CHANGELOG.md](CHANGELOG.md), and the canonical
documentation root [doc/](doc/).

## Current Truth

- Package version: `0.2.1`.
- Runtime dependencies: none. FIPS 202 SHA3/SHAKE is vendored in
  `lib/src/common/keccak.dart`.
- ML-KEM: supported for ML-KEM-512/768/1024 with checked-in KAT vectors,
  focused unit tests, web tests, and OpenSSL interop.
- ML-DSA: FIPS 204-aligned for ML-DSA-44/65/87 and byte-exact against the
  checked-in KAT corpus (`test/data/MLDSA`) across raw/pure/hashed × det/hedged
  (300 key generations + 1800 signatures). The full `dart test` suite is green.
  This is KAT/regression evidence, not a CMVP/FIPS 140 validation claim.
- Documentation root: `doc/`; the older documentation directory has been retired.

## Exploration Phase

Start here:

1. Read [README.md](README.md).
2. Read [doc/INDEX.md](doc/INDEX.md).
3. Read [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md).
4. Read [doc/PROGRESS_TRACKER.md](doc/PROGRESS_TRACKER.md) and
   [doc/ROADMAP.md](doc/ROADMAP.md).
5. Read [doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md) and
   [doc/FIPS_COMPLIANCE.md](doc/FIPS_COMPLIANCE.md).
6. For ML-DSA work, read
   [doc/MLDSA_FIPS204_RELEASE_GUIDE.md](doc/MLDSA_FIPS204_RELEASE_GUIDE.md).
7. Inspect `lib/src/`, `test/`, and `tool/openssl_interop/`.

Run:

```bash
dart analyze
dart test test/kat_evaluator_test.dart
dart test test/mldsa_kat_test.dart
dart test
```

Expected current boundary: `dart analyze` exits 0, the ML-KEM and ML-DSA KAT
runners pass, and the full suite is green (VM, plus `dart2js`/`dart2wasm`).

## Implementation Phase

Before editing:

- Identify whether the change touches ML-KEM, ML-DSA, common primitives,
  tests, tooling, or docs.
- For ML-KEM arithmetic/serialization, run the focused ML-KEM test set before
  and after the change.
- For ML-DSA, the deterministic core and external/HashML-DSA APIs are
  KAT-validated; keep any change byte-exact against `test/data/MLDSA` by running
  `dart test test/mldsa_kat_test.dart`. Use
  [doc/MLDSA_FIPS204_RELEASE_GUIDE.md](doc/MLDSA_FIPS204_RELEASE_GUIDE.md) as the
  controlling implementation/Definition-of-Done checklist, and never upgrade
  claim wording past KAT/regression evidence (no CMVP/FIPS 140 claims).

Conventions:

- Use the existing parameter objects.
- Keep ML-KEM and ML-DSA polynomial types separate.
- Keep runtime package dependencies at zero unless a package-boundary decision
  is explicitly made.
- Avoid `print()` in `lib/`.
- Validate public inputs.
- Add or update tests with every behavior change.

## Testing Phase

Useful commands:

```bash
# Static analysis
dart analyze

# ML-KEM KAT corpus
dart test test/kat_evaluator_test.dart

# Focused ML-KEM evidence set
dart test test/kat_evaluator_test.dart test/keccak_test.dart test/kem_validation_test.dart test/keygen_derivation_test.dart test/pack_test.dart test/poly_test.dart test/roundtrip_test.dart

# Full suite
dart test

# Web portable tests
dart test -p chrome
dart test -p chrome --compiler dart2wasm
```

The OpenSSL interop harness is a separate unpublished package:

```bash
cd tool/openssl_interop
dart pub get
dart test
```

The interop harness needs an OpenSSL >= 3.5 `libcrypto` with ML-KEM support.

## Documentation Phase

Use `doc/` paths everywhere. Update documentation when:

- public APIs change;
- validation evidence changes;
- tests are added, removed, or renamed;
- package dependencies or publish boundaries change;
- readiness language changes.

Keep assurance wording scoped:

- Good: "passes the checked-in ML-KEM KAT corpus."
- Good: "OpenSSL interop A-G passes for ML-KEM-512/768/1024."
- Good: "ML-DSA is byte-exact on the checked-in FIPS 204 KAT corpus."
- Bad: "fully FIPS validated" / "CMVP validated" / "certified" without a record.

## Security Auditing Phase

Focus areas:

- cryptographic correctness against FIPS 203/204;
- side-channel behavior in comparisons, rejection loops, and decapsulation;
- secret-zeroization in `finally` blocks;
- public input validation;
- hardcoded local paths or secrets;
- documentation that overstates evidence.

Resolved (regression-guarded; keep them closed):

- ML-DSA packing and `ExpandS` (η=2) defects — fixed; covered by KATs.
- Windows ML-DSA KAT paths and the debug-only test — removed; replaced by the
  discovered runner `test/mldsa_kat_test.dart` over `test/data/MLDSA`.
- Missing repo-local ML-DSA KAT corpus — vendored under `test/data/MLDSA`.
- `_checkNorm` early return — replaced by the no-early-exit `_normExceeds`.
- Missing shared zeroization utilities — added `lib/src/common/zeroize.dart`.

Open priorities:

- Deeper side-channel review (per-iteration branch directions in `_normExceeds`
  and rejection loops remain a best-effort, not constant-time, posture in Dart).
- KEM decapsulation output-selection review.
- HashML-DSA currently exposes the level-bound SHA-2 pre-hash only; other
  approved pre-hash functions (e.g. SHAKE) are not yet surfaced.

## Common Pitfalls

- Treating ML-KEM KAT success as ML-DSA readiness.
- Reintroducing external or machine-local KAT paths.
- Referring to the retired documentation directory instead of `doc/`.
- Referring to the old non-discovered KAT runner path instead of
  `test/kat_evaluator_test.dart`.
- Mentioning `pointycastle` as a runtime dependency; it has been replaced by
  vendored FIPS 202 code.
- Updating roadmap/readiness docs without running the relevant verification
  commands.

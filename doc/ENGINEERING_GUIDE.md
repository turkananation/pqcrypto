# Engineering Guide

Last updated: 2026-06-05

This guide is for contributors working on the current `0.2.1` repository.

## Setup

```bash
dart --version
dart pub get
```

Runtime package dependencies: none. Dev dependencies: `lints` and `test`.

The OpenSSL interop harness is a separate path package:

```bash
cd tool/openssl_interop
dart pub get
```

## Core Commands

| Purpose               | Command                                                                                                                                                                                        |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Analyze               | `dart analyze`                                                                                                                                                                                 |
| Full VM suite         | `dart test`                                                                                                                                                                                    |
| ML-KEM KAT only       | `dart test test/kat_evaluator_test.dart`                                                                                                                                                       |
| Focused ML-KEM set    | `dart test test/kat_evaluator_test.dart test/keccak_test.dart test/kem_validation_test.dart test/keygen_derivation_test.dart test/pack_test.dart test/poly_test.dart test/roundtrip_test.dart` |
| Web dart2js           | `dart test -p chrome`                                                                                                                                                                          |
| Web dart2wasm         | `dart test -p chrome --compiler dart2wasm`                                                                                                                                                     |
| OpenSSL interop       | `cd tool/openssl_interop && dart test` with OpenSSL >= 3.5                                                                                                                                     |
| Example/rough timings | `dart run example/main.dart`                                                                                                                                                                   |

The full VM suite currently fails in ML-DSA/debug tests. Do not use a passing
ML-KEM focused set as evidence that ML-DSA is ready.

## Documentation Rules

- Use `doc/` as the only documentation root.
- Start readers at [INDEX.md](INDEX.md).
- Keep all readiness claims tied to current test evidence.
- Mention ML-DSA as exported but experimental until the full suite and KATs pass.
- Do not claim CMVP/FIPS 140 validation.

## Code Organization

| Path                         | Responsibility                        |
| ---------------------------- | ------------------------------------- |
| `lib/pqcrypto.dart`          | Public exports.                       |
| `lib/src/common/keccak.dart` | Vendored FIPS 202 implementation.     |
| `lib/src/common/shake.dart`  | SHAKE wrappers.                       |
| `lib/src/common/poly.dart`   | ML-KEM polynomial/NTT arithmetic.     |
| `lib/src/algos/kyber/`       | ML-KEM implementation.                |
| `lib/src/algos/dilithium/`   | Experimental ML-DSA implementation.   |
| `test/data/kat_MLKEM_*.rsp`  | Checked-in ML-KEM KAT corpus.         |
| `tool/openssl_interop/`      | Unpublished OpenSSL FFI interop tool. |

## Security Practices

Do:

- validate every external input;
- use byte-wise comparison helpers for secrets;
- zeroize temporary secret buffers where possible;
- keep all cryptographic debug output out of `lib/`;
- run KATs after arithmetic or serialization changes;
- keep tests deterministic unless randomness is explicitly under test.

Do not:

- use `Random()` for cryptographic material;
- store secret material in `String`;
- introduce runtime dependencies without a package-boundary decision;
- add machine-local KAT paths;
- update readiness docs without fresh verification evidence.

## Adding a New Algorithm

Before adding a new algorithm, read
[ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md) and make sure the
existing ML-KEM and ML-DSA validation work will not be diluted.

Minimum checklist:

1. Create `lib/src/algos/<name>/`.
2. Define parameter sets.
3. Implement math primitives and serialization.
4. Add unit, round-trip, negative, and KAT tests.
5. Export only when the intended public readiness boundary is documented.
6. Update README, [INDEX.md](INDEX.md), [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md),
   [SECURITY_AUDIT.md](SECURITY_AUDIT.md), and [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md).

## Review Standard

For cryptographic code, a review is not done when it "works once." It is done
when the implementation has deterministic tests, negative tests, corpus or
interop evidence where appropriate, and documentation that does not overclaim.

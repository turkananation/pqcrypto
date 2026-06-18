# Engineering Guide

Last updated: 2026-06-16

This guide is for contributors working on the current `0.4.0` repository.

## Setup

```bash
dart --version
dart pub get
```

Runtime package dependencies: none. Dev dependencies: `lints` and `test`.

The native interop harnesses are separate path packages:

```bash
cd tool/openssl_interop
dart pub get

cd ../liboqs_interop
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
| OpenSSL interop       | `cd tool/openssl_interop && LIBCRYPTO_PATH=.native/openssl-4.0.1/lib/libcrypto.so dart test --concurrency=1`                                                                                   |
| liboqs interop        | `cd tool/liboqs_interop && LIBOQS_PATH=.native/liboqs-0.15.0/lib/liboqs.so dart test --concurrency=1`                                                                                          |
| Example/rough timings | `dart run example/main.dart`                                                                                                                                                                   |

The full VM suite is green, as are the `dart2js`/`dart2wasm` web gates. Both the
ML-KEM (3000 vectors), ML-DSA (18-file), and SLH-DSA (1,248 ACVP cases) KAT
runners are byte-exact. Still keep ML-KEM, ML-DSA, and SLH-DSA evidence
separate: a passing ML-KEM set is not ML-DSA or SLH-DSA evidence.

## Documentation Rules

- Use `doc/` as the only documentation root.
- Start readers at [INDEX.md](INDEX.md).
- Keep all readiness claims tied to current test evidence.
- Current FIPS 202 support is partial: SHA3-224/256/384/512, SHAKE128/256, and
  incremental SHAKE XOFs are implemented; complete corpus/non-byte coverage and
  SP 800-185 work are controlled by
  [FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md).
- ML-DSA is FIPS 204-aligned and byte-exact on the checked-in KAT corpus; keep
  any change byte-exact via `dart test test/mldsa_kat_test.dart`.
- Do not claim CMVP/FIPS 140 validation (see [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)).

## Code Organization

| Path                            | Responsibility                                    |
| ------------------------------- | ------------------------------------------------- |
| `lib/pqcrypto.dart`             | Public exports.                                   |
| `lib/src/common/keccak.dart`    | Partial vendored FIPS 202 (SHA3/SHAKE + XOF).     |
| `lib/src/common/shake.dart`     | SHAKE wrappers + incremental XOF.                 |
| `lib/src/common/sp800_185.dart` | Planned SHA-3-derived functions; not present yet. |
| `lib/src/common/sha2.dart`      | Vendored FIPS 180-4 SHA-2 family.                 |
| `lib/src/common/hmac.dart`      | HMAC-SHA-256/512 for SLH-DSA SHA-2 sets.          |
| `lib/src/common/mgf1.dart`      | MGF1-SHA-256/512 for SLH-DSA SHA-2 sets.          |
| `lib/src/common/zeroize.dart`   | Best-effort secret zeroization.                   |
| `lib/src/common/poly.dart`      | ML-KEM polynomial/NTT arithmetic.                 |
| `lib/src/algos/kyber/`          | ML-KEM (FIPS 203) implementation.                 |
| `lib/src/algos/dilithium/`      | ML-DSA (FIPS 204) implementation.                 |
| `lib/src/algos/slhdsa/`         | SLH-DSA (FIPS 205) implementation.                |
| `test/data/MLKEM/`              | Checked-in ML-KEM KAT corpus.                     |
| `test/data/MLDSA/`              | Checked-in ML-DSA KAT corpus.                     |
| `test/data/SLHDSA/`             | Checked-in SLH-DSA ACVP sample corpus.            |
| `tool/interop_common/`          | Shared provider-neutral interop metadata.         |
| `tool/openssl_interop/`         | Unpublished OpenSSL FFI interop tool.             |
| `tool/liboqs_interop/`          | Unpublished liboqs FFI interop tool.              |

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

## Completing FIPS 202 / SP 800-185

Before editing Keccak or adding SP 800-185 code, read
[FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md).

Minimum checklist:

1. Preserve current `sha3224`, `sha3256`, `sha3384`, `sha3512`, `shake128`,
   `shake256`, and XOF
   behavior.
2. Extend FIPS 202 corpus coverage, including non-byte examples, before broad
   FIPS 202 claims.
3. Add SP 800-185 encodings before cSHAKE/KMAC/TupleHash/ParallelHash.
4. Keep public APIs byte-oriented unless a bit-string API is deliberately
   designed.
5. Add official NIST example vectors with source URLs, retrieval dates, and
   hashes.
6. Run VM and web gates before updating release claims.

## Review Standard

For cryptographic code, a review is not done when it "works once." It is done
when the implementation has deterministic tests, negative tests, corpus or
interop evidence where appropriate, and documentation that does not overclaim.

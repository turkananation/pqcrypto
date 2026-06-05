# Known Bugs and Validation Gaps

Last updated: 2026-06-05

This file tracks bugs that affect current claims, tests, or release planning.
For security prioritization, also read [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Status Key

| Status | Meaning                                          |
| ------ | ------------------------------------------------ |
| Open   | Confirmed unresolved issue.                      |
| Fixed  | Fixed and covered by local evidence.             |
| Review | Needs a focused audit or fresh verification run. |

## Open Bugs

| ID     | Status | Severity | Component | Summary                                                                                | Evidence                               |
| ------ | ------ | -------- | --------- | -------------------------------------------------------------------------------------- | -------------------------------------- |
| BUG-01 | Open   | High     | ML-DSA    | `bitPack`/`bitUnpack` and `packSK` fail centered-value round-trips.                    | `dart test`, `dsa_pack_test.dart`      |
| BUG-02 | Open   | High     | ML-DSA    | `ExpandS` bounded sampling can throw `Bad state: Too few elements`.                    | `dart test`, `dsa_symmetric_test.dart` |
| BUG-03 | Open   | Medium   | ML-DSA    | `mldsa_debug_test.dart` and `mldsa_kat_test.dart` use `C:\Dev\Research\KAT\MLDSA\...`. | Current test files                     |
| BUG-04 | Open   | High     | ML-DSA    | No repo-local ML-DSA KAT corpus is checked in.                                         | File inventory                         |
| BUG-05 | Open   | High     | ML-DSA    | `_checkNorm` returns early and can leak first failing coefficient timing.              | `lib/src/algos/dilithium/dsa.dart`     |
| BUG-06 | Open   | High     | All       | No shared zeroization helpers or systematic `finally` zeroization.                     | `rg secureZero` in `lib/`              |
| BUG-07 | Review | Medium   | ML-KEM    | `Random.secure()` is instantiated per `_randomBytes` call.                             | `lib/src/algos/kyber/kem.dart`         |
| BUG-08 | Review | Medium   | ML-KEM    | Decapsulation branches after constant-time ciphertext comparison.                      | `lib/src/algos/kyber/kem.dart`         |
| BUG-09 | Review | Low      | Example   | `example/main.dart` compares `Uint8List.toString()` for shared secrets.                | `example/main.dart`                    |

## Fixed or Superseded Bugs

| ID     | Status | Component | Summary                                                  | Current evidence                                                |
| ------ | ------ | --------- | -------------------------------------------------------- | --------------------------------------------------------------- |
| FIX-01 | Fixed  | ML-KEM    | Old KAT runner was not discovered by `dart test`.        | Runner is now `test/kat_evaluator_test.dart`.                   |
| FIX-02 | Fixed  | ML-KEM    | ML-KEM public/secret/ciphertext input validation gaps.   | `test/kem_validation_test.dart`.                                |
| FIX-03 | Fixed  | ML-KEM    | `Poly.barrettReduce` could return non-canonical residue. | `test/poly_test.dart`.                                          |
| FIX-04 | Fixed  | Common    | Runtime dependency on `pointycastle`.                    | `pubspec.yaml` has no runtime dependencies; Keccak is vendored. |
| FIX-05 | Fixed  | ML-DSA    | Per-level `tau` was not encoded in params.               | `DilithiumParams` contains 39, 49, 60.                          |
| FIX-06 | Fixed  | ML-DSA    | Production-library debug `print()` leakage.              | `rg "print\\(" lib` returns no production matches.              |

## How to Retire an Open Bug

1. Fix the code or test fixture.
2. Add or update a regression test.
3. Run the smallest targeted test and the relevant release gate.
4. Update this file, [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md), and any affected
   readiness wording in README or [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md).

Do not mark ML-DSA production-ready until all ML-DSA blockers above are closed
and backed by repo-local KAT evidence.

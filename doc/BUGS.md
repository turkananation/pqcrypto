# Known Bugs and Validation Gaps

Last updated: 2026-06-16

This file tracks bugs that affect current claims, tests, or release planning.
For security prioritization, also read [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Status Key

| Status | Meaning                                          |
| ------ | ------------------------------------------------ |
| Open   | Confirmed unresolved issue.                      |
| Fixed  | Fixed and covered by local evidence.             |
| Review | Needs a focused audit or fresh verification run. |

## Open Bugs

No open bugs currently affect the documented release claims.

## Fixed or Superseded Bugs

| ID     | Status | Component | Summary                                                    | Current evidence                                                   |
| ------ | ------ | --------- | ---------------------------------------------------------- | ------------------------------------------------------------------ |
| FIX-01 | Fixed  | ML-KEM    | Old KAT runner was not discovered by `dart test`.          | Runner is now `test/kat_evaluator_test.dart`.                      |
| FIX-02 | Fixed  | ML-KEM    | ML-KEM public/secret/ciphertext input validation gaps.     | `test/kem_validation_test.dart`.                                   |
| FIX-03 | Fixed  | ML-KEM    | `Poly.barrettReduce` could return non-canonical residue.   | `test/poly_test.dart`.                                             |
| FIX-04 | Fixed  | Common    | Runtime dependency on `pointycastle`.                      | `pubspec.yaml` has no runtime dependencies; Keccak is vendored.    |
| FIX-05 | Fixed  | ML-DSA    | Per-level `tau` was not encoded in params.                 | `DilithiumParams` contains 39, 49, 60.                             |
| FIX-06 | Fixed  | ML-DSA    | Production-library debug `print()` leakage.                | `rg "print\\(" lib` returns no production matches.                 |
| FIX-07 | Fixed  | ML-DSA    | `bitPack`/`bitUnpack`/`packSK` centered-value round-trips. | Signed-domain packing; `dsa_pack_test.dart` green.                 |
| FIX-08 | Fixed  | ML-DSA    | `ExpandS` (η=2) threw / diverged from FIPS 204.            | `RejBoundedPoly` η=2 fix; `dsa_symmetric_test.dart` green.         |
| FIX-09 | Fixed  | ML-DSA    | Windows KAT root in ML-DSA tests.                          | Debug test removed; `mldsa_kat_test.dart` reads `test/data/MLDSA`. |
| FIX-10 | Fixed  | ML-DSA    | No repo-local ML-DSA KAT corpus.                           | `test/data/MLDSA` (18 files); 300 keygens + 1800 sigs byte-exact.  |
| FIX-11 | Fixed  | ML-DSA    | `_checkNorm` early-exit timing leak.                       | Replaced by no-early-exit `_normExceeds`.                          |
| FIX-12 | Fixed  | All       | No shared zeroization helpers.                             | `lib/src/common/zeroize.dart`; used in KEM/DSA `finally` blocks.   |
| FIX-13 | Fixed  | ML-KEM    | `Random.secure()` per call.                                | Cached `_secureRng`.                                               |
| FIX-14 | Fixed  | ML-KEM    | Decapsulation branched after the ciphertext comparison.    | Constant-time branchless output select; 3000 KATs byte-exact.      |
| FIX-15 | Fixed  | Example   | Shared-secret equality used `Uint8List.toString()`.        | Byte-wise equality in `example/main.dart`.                         |

## How to Retire an Open Bug

1. Fix the code or test fixture.
2. Add or update a regression test.
3. Run the smallest targeted test and the relevant release gate.
4. Update this file, [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md), and any affected
   readiness wording in README or [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md).

Keep ML-KEM, ML-DSA, and SLH-DSA evidence separate, and keep all claims scoped
to KAT/ACVP/regression evidence (no CMVP/FIPS 140 claim; see
[FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)).

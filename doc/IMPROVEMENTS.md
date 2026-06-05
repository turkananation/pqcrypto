# Improvements

Last updated: 2026-06-05

This file lists current improvement work in priority order. Completed quick wins
from older 0.1.0-era audits are not repeated except where they define current
guardrails.

## P0 - Correct Misleading Surfaces

| ID     | Improvement                                       | Status | Files                                                   |
| ------ | ------------------------------------------------- | ------ | ------------------------------------------------------- |
| IMP-01 | Keep documentation under canonical `doc/`.        | Done   | `doc/`, README, AGENTS, CLAUDE                          |
| IMP-02 | State ML-DSA validation status accurately.        | Done   | FIPS 204-aligned, byte-exact KATs; docs updated.        |
| IMP-03 | Remove old `pointycastle` dependency claims.      | Done   | Only historical/replacement references remain.          |
| IMP-04 | Replace old non-discovered KAT runner references. | Done   | Current runner is `test/kat_evaluator_test.dart`.       |
| IMP-05 | Fix Serverpod guide link and dependency snippet.  | Done   | README and guide now use `doc/` and `pqcrypto: ^0.3.1`. |

## P0 - ML-DSA Correctness (complete)

| ID     | Improvement                           | Status | Rationale                                          |
| ------ | ------------------------------------- | ------ | -------------------------------------------------- |
| DSA-01 | Fix centered-value packing/unpacking. | Done   | Signed-domain packing; `dsa_pack_test.dart` green. |
| DSA-02 | Fix `ExpandS` bounded sampling.       | Done   | η=2 `RejBoundedPoly` fix; symmetric tests green.   |
| DSA-03 | Replace hardcoded ML-DSA KAT paths.   | Done   | Discovered runner over `test/data/MLDSA`.          |
| DSA-04 | Add repo-local ML-DSA KAT corpus.     | Done   | `test/data/MLDSA` (18 files).                      |
| DSA-05 | Add discovered ML-DSA KAT runner.     | Done   | `test/mldsa_kat_test.dart` under `dart test`.      |

## P1 - Security Hardening (complete)

| ID     | Improvement                                        | Status | Notes                                          |
| ------ | -------------------------------------------------- | ------ | ---------------------------------------------- |
| SEC-01 | Add `secureZero(Uint8List)` and `secureZeroInt32`. | Done   | `lib/src/common/zeroize.dart`; `finally` use.  |
| SEC-02 | Make ML-DSA `_checkNorm` constant-time.            | Done   | No-early-exit `_normExceeds` over 256 coeffs.  |
| SEC-03 | Review KEM decapsulation branch/select behavior.   | Done   | Constant-time branchless output select.        |
| SEC-04 | Add ML-DSA public input validation.                | Done   | `dsa_negative_test.dart`, `dsa_api_test.dart`. |
| SEC-05 | Add malformed DSA signature/key negative tests.    | Done   | `dsa_negative_test.dart`.                      |

## P2 - API and Package Boundary

| ID     | Improvement                                       | Status | Notes                                                  |
| ------ | ------------------------------------------------- | ------ | ------------------------------------------------------ |
| API-01 | Decide ML-DSA export policy before 1.0.           | Done   | ML-DSA is KAT-validated and exported as supported.     |
| API-02 | Consider FIPS-name aliases for KEM levels.        | Review | `PqcKem.mlKem768` alias may reduce Kyber naming drift. |
| API-03 | Add Dartdoc to all public API members.            | Open   | Required for stable API.                               |
| API-04 | Fix example byte equality in `example/main.dart`. | Done   | Uses byte-wise equality in the ML-KEM examples.        |

## P3 - Performance and Tooling

| ID      | Improvement                             | Status | Notes                              |
| ------- | --------------------------------------- | ------ | ---------------------------------- |
| PERF-01 | Add benchmark suite under `benchmark/`. | Open   | Avoid relying only on examples.    |
| PERF-02 | Measure VM, AOT, dart2js, dart2wasm.    | Open   | Needed before optimization claims. |
| PERF-03 | Evaluate `Int32List` for ML-KEM poly.   | Review | Likely performance and GC win.     |
| PERF-04 | Evaluate in-place ML-KEM NTT.           | Review | Higher refactor risk.              |

## Completed Guardrails

| Guardrail                                       | Evidence                                      |
| ----------------------------------------------- | --------------------------------------------- |
| ML-KEM KAT runner is discovered by `dart test`. | `test/kat_evaluator_test.dart`.               |
| FIPS 202 is vendored.                           | `lib/src/common/keccak.dart`, `pubspec.yaml`. |
| Runtime package has no third-party deps.        | `pubspec.yaml`.                               |
| Production `lib/` has no `print()`.             | `rg "print\\(" lib`.                          |
| ML-KEM input validation exists.                 | `test/kem_validation_test.dart`.              |

## Implementation Discipline

Every improvement that changes readiness language must include:

1. code or fixture change;
2. targeted regression test;
3. relevant verification command output;
4. documentation update in this file and [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md).

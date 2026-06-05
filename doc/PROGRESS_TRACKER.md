# Progress Tracker

Last updated: 2026-06-05

This tracker reconciles the current codebase, changelog, and local verification
snapshot. It deliberately separates ML-KEM release evidence from ML-DSA
experimental work.

## Current State

| Area              | Status         | Evidence                                                        |
| ----------------- | -------------- | --------------------------------------------------------------- |
| Version           | 0.2.1          | `pubspec.yaml`, `CHANGELOG.md`.                                 |
| Runtime deps      | Complete       | No runtime dependencies; FIPS 202 vendored.                     |
| ML-KEM            | Supported      | Checked-in KAT corpus, unit tests, OpenSSL interop.             |
| OpenSSL interop   | Supported      | A-G suite for ML-KEM-512/768/1024.                              |
| Web support       | Tested surface | CI has `dart2js` and `dart2wasm` test jobs.                     |
| ML-DSA            | Experimental   | Exported, but full suite currently fails in ML-DSA/debug tests. |
| Formal validation | Not claimed    | No CMVP/FIPS 140 validation record.                             |

## Phase 0 - Documentation Consolidation

| Task                                                | Status | Notes                                       |
| --------------------------------------------------- | ------ | ------------------------------------------- |
| Move remaining old documentation files into `doc/`. | Done   | `doc/` is the canonical documentation root. |
| Update root README documentation links.             | Done   | Serverpod link and doc references updated.  |
| Update AGENTS/CLAUDE assistant docs.                | Done   | Old path and dependency facts removed.      |
| Rewrite stale 0.1.0-era docs.                       | Done   | Evidence-scoped 0.2.1 docs.                 |
| Preserve Conclave verdict.                          | Done   | `verdicts/verdict-20260605T081457Z.md`.     |

## Phase 1 - ML-KEM Maintenance

| Task                                             | Status | Gate                                                        |
| ------------------------------------------------ | ------ | ----------------------------------------------------------- |
| Maintain checked-in ML-KEM KAT corpus.           | Open   | `dart test test/kat_evaluator_test.dart`.                   |
| Maintain FIPS 202 vendored Keccak tests.         | Open   | `dart test test/keccak_test.dart`.                          |
| Maintain input-validation regressions.           | Open   | `dart test test/kem_validation_test.dart`.                  |
| Maintain OpenSSL interop on ML-KEM 512/768/1024. | Open   | `cd tool/openssl_interop && dart test` with OpenSSL >= 3.5. |
| Consider constant-time output select in decaps.  | Open   | New regression/audit needed.                                |
| Consider RNG allocation refactor.                | Review | Measure before changing.                                    |

## Phase 2 - ML-DSA Correctness and Validation

ML-DSA must stay labeled experimental until this phase is complete.

| Task                                                            | Status | Evidence or blocker                                               |
| --------------------------------------------------------------- | ------ | ----------------------------------------------------------------- |
| Publish FIPS 204 ML-DSA release guide.                          | Done   | [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md). |
| Fix `dsa_pack_test.dart` centered-value failures.               | Open   | Current full suite failure.                                       |
| Fix `dsa_symmetric_test.dart` `ExpandS` failure.                | Open   | Current full suite failure.                                       |
| Remove hardcoded Windows KAT root from ML-DSA KAT/debug tests.  | Open   | Current full suite failure/skip.                                  |
| Add repo-local ML-DSA KAT corpus.                               | Open   | No corpus under `test/data` for ML-DSA.                           |
| Add ML-DSA KAT evaluator discovered by `dart test`.             | Open   | Needed for readiness claim.                                       |
| Make `_checkNorm` constant-time.                                | Open   | Early return remains.                                             |
| Add ML-DSA public input validation.                             | Open   | Needs focused API tests.                                          |
| Decide whether ML-DSA should remain exported before validation. | Review | Public API boundary risk.                                         |

## Phase 3 - Security Hardening

| Task                            | Status | Notes                                              |
| ------------------------------- | ------ | -------------------------------------------------- |
| Implement `secureZero` helpers. | Open   | Apply to KEM/DSA temporary secrets with `finally`. |
| Review all rejection loops.     | Open   | Timing behavior and fixed-output XOF buffers.      |
| Add adversarial negative tests. | Open   | Especially malformed DSA signatures/keys.          |
| Add security reporting process. | Open   | Consider `SECURITY.md`.                            |

## Phase 4 - Future Algorithms

Future algorithm work should wait behind ML-DSA validation unless a specific
research branch is created.

| Algorithm | Status      | Guidance                                     |
| --------- | ----------- | -------------------------------------------- |
| SLH-DSA   | Not started | Most practical next signature after ML-DSA.  |
| HQC       | Not started | Wait for final parameter/spec stability.     |
| FN-DSA    | Not started | High sampler/side-channel risk in pure Dart. |

See [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

## Verification Gates

| Gate               | Command                                                                                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static analysis    | `dart analyze`                                                                                                                                                                                 |
| ML-KEM KAT         | `dart test test/kat_evaluator_test.dart`                                                                                                                                                       |
| ML-KEM focused set | `dart test test/kat_evaluator_test.dart test/keccak_test.dart test/kem_validation_test.dart test/keygen_derivation_test.dart test/pack_test.dart test/poly_test.dart test/roundtrip_test.dart` |
| Full VM suite      | `dart test`                                                                                                                                                                                    |
| Web portable suite | `dart test -p chrome` and `dart test -p chrome --compiler dart2wasm`                                                                                                                           |
| OpenSSL interop    | `cd tool/openssl_interop && dart test` with ML-KEM-capable OpenSSL                                                                                                                             |

The full VM suite is currently expected to fail until ML-DSA blockers are fixed.

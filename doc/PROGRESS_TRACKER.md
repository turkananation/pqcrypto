# Progress Tracker

Last updated: 2026-06-05

This tracker reconciles the current codebase, changelog, and local verification
snapshot. It deliberately separates ML-KEM evidence, ML-DSA evidence, and the
claim boundary for both algorithms.

## Current State

| Area              | Status           | Evidence                                                                                  |
| ----------------- | ---------------- | ----------------------------------------------------------------------------------------- |
| Version           | 0.3.1            | `pubspec.yaml`, `CHANGELOG.md`.                                                           |
| Runtime deps      | Complete         | No runtime dependencies; FIPS 202 and FIPS 180-4 primitives vendored.                     |
| ML-KEM            | Supported        | Checked-in KAT corpus, unit tests, OpenSSL interop.                                       |
| OpenSSL interop   | Supported        | A-G suite for ML-KEM-512/768/1024.                                                        |
| Web support       | Tested surface   | CI has `dart2js` and `dart2wasm` test jobs.                                               |
| ML-DSA            | FIPS 204-aligned | Byte-exact on the checked-in KAT corpus (raw/pure/hashed × det/hedged); full suite green. |
| SLH-DSA           | Planned          | FIPS 205; not started. SHAKE sets target 0.4.0, SHA-2 sets 0.5.0. See the release guide.  |
| Formal validation | Not claimed      | No CMVP/FIPS 140 validation record.                                                       |

## Phase 0 - Documentation Consolidation

| Task                                                | Status | Notes                                       |
| --------------------------------------------------- | ------ | ------------------------------------------- |
| Move remaining old documentation files into `doc/`. | Done   | `doc/` is the canonical documentation root. |
| Update root README documentation links.             | Done   | Serverpod link and doc references updated.  |
| Update AGENTS/CLAUDE assistant docs.                | Done   | Old path and dependency facts removed.      |
| Rewrite stale 0.1.0-era docs.                       | Done   | Evidence-scoped 0.3.1 docs.                 |
| Preserve Conclave verdict.                          | Done   | `verdicts/verdict-20260605T081457Z.md`.     |

## Phase 1 - ML-KEM Maintenance

| Task                                             | Status | Gate                                                        |
| ------------------------------------------------ | ------ | ----------------------------------------------------------- |
| Maintain checked-in ML-KEM KAT corpus.           | Open   | `dart test test/kat_evaluator_test.dart`.                   |
| Maintain FIPS 202 vendored Keccak tests.         | Open   | `dart test test/keccak_test.dart`.                          |
| Maintain input-validation regressions.           | Open   | `dart test test/kem_validation_test.dart`.                  |
| Maintain OpenSSL interop on ML-KEM 512/768/1024. | Open   | `cd tool/openssl_interop && dart test` with OpenSSL >= 3.5. |
| Add constant-time output select in decaps.       | Done   | Branchless select; ML-KEM KAT corpus remains byte-exact.    |
| Avoid per-call `Random.secure()` construction.   | Done   | Cached `_secureRng` in KEM.                                 |

## Phase 2 - ML-DSA Correctness and Validation

Complete per the Definition of Done in the release guide.

| Task                                                           | Status | Evidence or blocker                                               |
| -------------------------------------------------------------- | ------ | ----------------------------------------------------------------- |
| Publish FIPS 204 ML-DSA release guide.                         | Done   | [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md). |
| Fix `dsa_pack_test.dart` centered-value failures.              | Done   | Signed-domain packing; `dsa_pack_test.dart` green.                |
| Fix `dsa_symmetric_test.dart` `ExpandS` failure.               | Done   | η=2 `RejBoundedPoly` fix; `dsa_symmetric_test.dart` green.        |
| Remove hardcoded Windows KAT root from ML-DSA KAT/debug tests. | Done   | Debug test removed; runner uses `test/data/MLDSA`.                |
| Add repo-local ML-DSA KAT corpus.                              | Done   | `test/data/MLDSA` (18 files).                                     |
| Add ML-DSA KAT evaluator discovered by `dart test`.            | Done   | `test/mldsa_kat_test.dart`; 300 keygens + 1800 sigs byte-exact.   |
| Make `_checkNorm` constant-time.                               | Done   | Replaced by no-early-exit `_normExceeds`.                         |
| Add ML-DSA public input validation.                            | Done   | `dsa_negative_test.dart`, `dsa_api_test.dart`.                    |
| External API: hedged default, context, HashML-DSA.             | Done   | `dsa_api_test.dart`; pure+hashed KATs byte-exact.                 |

## Phase 3 - Security Hardening

| Task                            | Status | Notes                                                          |
| ------------------------------- | ------ | -------------------------------------------------------------- |
| Implement `secureZero` helpers. | Done   | `lib/src/common/zeroize.dart`; applied in `finally` blocks.    |
| Review all rejection loops.     | Done   | Incremental XOF; no fixed-buffer exhaustion. Residual: DSA-20. |
| Add adversarial negative tests. | Done   | `dsa_negative_test.dart` (malformed pk/sig/hint/context).      |
| Deeper constant-time review.    | Open   | Best-effort posture in pure Dart; tracked as DSA-20.           |
| Add security reporting process. | Done   | SECURITY.md configuration.                                     |

## Phase 4 - Future Algorithms

ML-DSA is validated, so SLH-DSA (FIPS 205) is the next scheduled scheme. Its
detailed task tracking is in Phase 5 below.

| Algorithm  | Status              | Guidance                                              |
| ---------- | ------------------- | ----------------------------------------------------- |
| SLH-DSA    | 0.4.0/0.5.0 planned | Hash-based; SHAKE then SHA-2. See the release guide.  |
| LMS / XMSS | Future workstream   | Stateful HBS (SP 800-208); separate guide if pursued. |
| HQC        | Not started         | Wait for final parameter/spec stability.              |
| FN-DSA     | Not started         | High sampler/side-channel risk in pure Dart.          |

See [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md) and
[ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

## Phase 5 - SLH-DSA (FIPS 205)

Not started. Controlled by
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md). The SHAKE
family ships at 0.4.0 (reuses `KeccakXof`, no new primitive); the SHA-2 family
ships at 0.5.0 (vendored HMAC/MGF1, 22-byte `ADRS^c`, SHA-256/512 split).

| Task                                                      | Status | Gate / evidence                               |
| --------------------------------------------------------- | ------ | --------------------------------------------- |
| Acquire + check in NIST ACVP SLH-DSA vectors.             | Open   | `test/data/SLHDSA` + provenance README.       |
| Params, util, `ADRS` (32B), SHAKE hashing.                | Open   | `slhdsa_address_test`, `slhdsa_hashing_test`. |
| WOTS+, XMSS, hypertree, FORS (Algorithms 5-17).           | Open   | `slhdsa_wots/xmss_ht/fors_test`.              |
| Internal + external SLH-DSA (Algorithms 18-25).           | Open   | `slhdsa_kat_test` byte-exact (SHAKE).         |
| Hedged default, `s`-gating, BUFF + perf docs, benchmarks. | Open   | API docstrings, README, PERFORMANCE.md.       |
| Ship v0.4.0 (6 SHAKE sets); platform matrix green.        | Open   | `dart pub publish --dry-run`.                 |
| Vendor + KAT-gate HMAC-SHA-256/512 (RFC 4231).            | Open   | `hmac_test`.                                  |
| Vendor + KAT-gate MGF1-SHA-256/512 (RFC 8017).            | Open   | `mgf1_test`.                                  |
| `ADRS^c` (22B) + SHA-2 hashing (cat 1 + cat 3/5 split).   | Open   | `slhdsa_hashing_test`, `slhdsa_address_test`. |
| Wire 6 SHA-2 sets; ACVP KAT to all 12; ship v0.5.0.       | Open   | `slhdsa_kat_test` byte-exact (all 12).        |

SLH-DSA security design controls (BUFF, fault, RBG, performance, zeroization)
are tracked as SLH-01..SLH-05 in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Verification Gates

| Gate               | Command                                                                                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static analysis    | `dart analyze`                                                                                                                                                                                 |
| ML-KEM KAT         | `dart test test/kat_evaluator_test.dart`                                                                                                                                                       |
| ML-KEM focused set | `dart test test/kat_evaluator_test.dart test/keccak_test.dart test/kem_validation_test.dart test/keygen_derivation_test.dart test/pack_test.dart test/poly_test.dart test/roundtrip_test.dart` |
| Full VM suite      | `dart test`                                                                                                                                                                                    |
| Web portable suite | `dart test -p chrome` and `dart test -p chrome --compiler dart2wasm`                                                                                                                           |
| OpenSSL interop    | `cd tool/openssl_interop && dart test` with ML-KEM-capable OpenSSL                                                                                                                             |

The full VM suite is expected to be green (160 tests), as are the `dart2js` and
`dart2wasm` web gates. Add `dart test test/mldsa_kat_test.dart` for the ML-DSA
KAT runner.

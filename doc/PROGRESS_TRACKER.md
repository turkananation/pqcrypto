# Progress Tracker

Last updated: 2026-06-15

This tracker reconciles the current codebase, changelog, and local verification
snapshot. It deliberately separates ML-KEM evidence, ML-DSA evidence, and the
claim boundary for both algorithms.

## Current State

| Area              | Status            | Evidence                                                                                                   |
| ----------------- | ----------------- | ---------------------------------------------------------------------------------------------------------- |
| Version           | 0.3.1             | `pubspec.yaml`, `CHANGELOG.md`.                                                                            |
| Runtime deps      | Complete          | No runtime dependencies; FIPS 202 and FIPS 180-4 primitives vendored.                                      |
| FIPS 202          | Partial           | SHA3-224/256/384/512 plus SHAKE128/256; official byte examples and table tests pass.                       |
| SP 800-185        | Not started       | cSHAKE/KMAC/TupleHash/ParallelHash planned for 0.6.0, with 0.7.0 spillover if needed.                      |
| ML-KEM            | Supported         | Checked-in KAT corpus, unit tests, OpenSSL interop.                                                        |
| OpenSSL interop   | Supported         | A-G suite for ML-KEM-512/768/1024.                                                                         |
| Web support       | Tested surface    | CI has `dart2js` and `dart2wasm` test jobs.                                                                |
| ML-DSA            | FIPS 204-aligned  | Byte-exact on the checked-in KAT corpus (raw/pure/hashed × det/hedged); full suite green                   |
| SLH-DSA           | Release candidate | All 12 sets (SHAKE + SHA-2) exported in the development tree; 1,248/1,248 ACVP cases byte-exact; v0.4.0 not released. |
| Formal validation | Not claimed       | No CMVP/FIPS 140 validation record.                                                                        |

## Phase 0 - Documentation Consolidation

| Task                                                | Status | Notes                                       |
| --------------------------------------------------- | ------ | ------------------------------------------- |
| Move remaining old documentation files into `doc/`. | Done   | `doc/` is the canonical documentation root. |
| Update root README documentation links.             | Done   | Serverpod link and doc references updated.  |
| Update AGENTS/CLAUDE assistant docs.                | Done   | Old path and dependency facts removed.      |
| Rewrite stale 0.1.0-era docs.                       | Done   | Evidence-scoped 0.3.1 docs.                 |

## Phase 1 - ML-KEM Maintenance

| Task                                             | Status | Gate                                                        |
| ------------------------------------------------ | ------ | ----------------------------------------------------------- |
| Maintain checked-in ML-KEM KAT corpus.           | Open   | `dart test test/kat_evaluator_test.dart`.                   |
| Maintain current FIPS 202 vendored Keccak tests. | Open   | `dart test test/keccak_test.dart`.                          |
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
| SLH-DSA    | 0.4.0 RC (all 12)   | Hash-based; SHAKE + SHA-2 byte-exact on ACVP. See the guide. |
| LMS / XMSS | Future workstream   | Stateful HBS (SP 800-208); separate guide if pursued. |
| HQC        | Not started         | Wait for final parameter/spec stability.              |
| FN-DSA     | Not started         | High sampler/side-channel risk in pure Dart.          |

See [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md) and
[ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

## Phase 5 - SLH-DSA (FIPS 205)

In active development. Controlled by
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md). All 12
parameter sets (SHAKE + SHA-2) are byte-exact on the official NIST ACVP corpus
and ship together in the v0.4.0 development candidate. SHAKE was implemented
first (reuses `KeccakXof`, no new primitive); the SHA-2 family followed
(vendored HMAC/MGF1, 22-byte `ADRS^c`, SHA-256/512 split).

| Task                                                        | Status | Gate / evidence                                            |
| ----------------------------------------------------------- | ------ | ---------------------------------------------------------- |
| Acquire + check in NIST ACVP SLH-DSA vectors.               | Done   | 1,248 official cases; pinned commit + hashes.              |
| Params, util, `ADRS` (32B), SHAKE hashing.                  | Done   | Focused component tests green.                             |
| WOTS+, XMSS, hypertree, FORS (Algorithms 5-17).             | Done   | Component round-trip/negative tests green.                 |
| Internal + external SLH-DSA (Algorithms 18-25).             | Done   | 1,248 ACVP cases byte-exact (all 12 sets).                 |
| Export all 12 supported sets (SHAKE + SHA-2).               | Done   | Package-root API test; all 12 exported and supported.      |
| Hedged default, `s`-gating, BUFF/performance documentation. | Done   | API docstrings, README, SECURITY_AUDIT, PERFORMANCE.       |
| Optional verify-after-sign fault detection.                 | Done   | Success and inconsistent-secret-key regressions.           |
| Per-set VM/dart2js/dart2wasm benchmark baselines.           | Done   | 18 measurements published in `PERFORMANCE.md`.             |
| Full VM and web package platform matrix.                    | Done   | VM decomposed matrix; 217/217 on dart2js and dart2wasm.    |
| Visibility and AI-discovery release boundary.               | Done   | Generated surfaces identify SLH-DSA as a development RC.   |
| Package publication preflight.                              | Done   | Valid archive; expected dirty-worktree warning only.       |
| Maintainer v0.4.0 version/tag/publish decision.             | Open   | Release branch workflow; no tag/publication in this pass.  |
| Vendor + KAT-gate HMAC-SHA-256/512 (RFC 4231).              | Done   | `hmac_test` green.                                         |
| Vendor + KAT-gate MGF1-SHA-256/512 (RFC 8017).              | Done   | `mgf1_test` green.                                         |
| `ADRS^c` (22B) + SHA-2 hashing (cat 1 + cat 3/5 split).     | Done   | `slhdsa_hashing_test`, `slhdsa_address_test` green.        |
| Wire 6 SHA-2 sets; ACVP KAT to all 12 (in v0.4.0).          | Done   | `slhdsa_kat_test` byte-exact (all 12).                     |

SLH-DSA security design controls (BUFF, fault, RBG, performance, zeroization)
are tracked as SLH-01..SLH-05 in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Phase 7 - FIPS 202 / SP 800-185 SHA-3 Foundation

Target release: **0.6.0**, with **0.7.0** reserved for standards-complete
spillover if the full evidence gate cannot close in 0.6.0. The byte-oriented
shared-core prerequisite has started; non-byte examples and SP 800-185 remain.
Controlled by
[FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md).

| Task                                                  | Status  | Gate / evidence                                                         |
| ----------------------------------------------------- | ------- | ----------------------------------------------------------------------- |
| Publish FIPS 202 / SP 800-185 release guide.          | Done    | [FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md). |
| Create GitHub issue map SHA3-00..SHA3-12.             | Done    | Epic #48 and child issues #36..#47.                                     |
| Acquire + normalize NIST FIPS 202 example vectors.    | Partial | Empty/1600-bit byte cases for all six functions; non-byte cases remain  |
| Acquire + normalize NIST SP 800-185 example vectors.  | Open    | `test/data/SP800185` provenance manifest.                               |
| Implement SHA3-224 and SHA3-384.                      | Done    | Official byte examples plus VM/dart2js focused tests.                   |
| Add Keccak constants/suffix/rate/capacity tests.      | Done    | Active implementation tables are directly pinned in `keccak_test.dart`. |
| Implement SP 800-185 encodings and cSHAKE.            | Open    | `sp800_185_encoding_test`, `sp800_185_cshake_test`.                     |
| Implement KMAC/KMACXOF.                               | Open    | `sp800_185_kmac_test`; key/tag guidance docs.                           |
| Implement TupleHash/ParallelHash families.            | Open    | Tuple-boundary and multi-block ParallelHash tests.                      |
| Run VM/web gates and publish benchmark notes.         | Open    | VM, dart2js, dart2wasm, `PERFORMANCE.md`.                               |
| Update release docs and claims after evidence passes. | Open    | README, CHANGELOG, FIPS docs, `dart pub publish --dry-run`.             |

## Verification Gates

| Gate               | Command                                                                                                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static analysis    | `dart analyze`                                                                                                                                                                                                      |
| ML-KEM KAT         | `dart test test/kat_evaluator_test.dart`                                                                                                                                                                            |
| ML-KEM focused set | `dart test test/kat_evaluator_test.dart test/keccak_test.dart test/kem_validation_test.dart test/keygen_derivation_test.dart test/pack_test.dart test/poly_test.dart test/roundtrip_test.dart`                      |
| SLH-DSA corpus     | `dart test test/slhdsa_acvp_corpus_test.dart`                                                                                                                                                                       |
| SLH-DSA components | `dart test test/slhdsa_address_test.dart test/slhdsa_params_test.dart test/slhdsa_util_test.dart test/slhdsa_hashing_test.dart test/slhdsa_wots_test.dart test/slhdsa_xmss_ht_test.dart test/slhdsa_fors_test.dart` |
| SLH-DSA ACVP       | `dart test test/slhdsa_kat_test.dart` (VM-only; full `s`-set execution is intentionally expensive)                                                                                                                  |
| SLH-DSA API        | `dart test test/slhdsa_api_test.dart test/slhdsa_negative_test.dart test/slhdsa_public_api_test.dart`                                                                                                               |
| SLH-DSA benchmark  | `dart run tool/bench/slhdsa_bench.dart --target=vm-jit` plus the compiled-target commands in `PERFORMANCE.md`                                                                                                       |
| Full VM suite      | `dart test`                                                                                                                                                                                                         |
| Web portable suite | `dart test -p chrome` and `dart test -p chrome --compiler dart2wasm`                                                                                                                                                |
| OpenSSL interop    | `cd tool/openssl_interop && dart test` with ML-KEM-capable OpenSSL                                                                                                                                                  |

Fresh M4 verification on 2026-06-15:

- the VM suite excluding the separately executed SLH-DSA KAT file passed
  256/256 tests;
- all 12 ACVP parameter sets passed keyGen/sigGen/sigVer, with slow-set
  sigGen progress reported per case;
- `dart test -p chrome` passed 217/217;
- `dart test -p chrome --compiler dart2wasm --concurrency=1` passed 217/217;
- `dart run tool/visibility/generate_visibility.dart --check` passed after the
  canonical manifest and generated surfaces were updated with all 12
  sets, 1,248/1,248 evidence, and the unpublished v0.4.0 boundary;
- `dart pub publish --dry-run --ignore-warnings` validated the 190 KB package
  archive, with only the expected uncommitted-worktree warning.

The v0.4.0 version bump, release branch, tag, and publication remain maintainer
actions.

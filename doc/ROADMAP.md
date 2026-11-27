# Release Roadmap

Last updated: 2026-11-26

The roadmap starts from the `0.4.0` release: ML-KEM (FIPS 203) and ML-DSA
(FIPS 204) are byte-exact against their checked-in KAT corpora, and SLH-DSA
(FIPS 205, all 12 sets) is byte-exact on all 1,248 checked-in official ACVP
sample cases. Claims remain scoped to algorithm/KAT and interop evidence, not
CMVP/FIPS 140 module validation
([FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)).

## Version History

| Version | State                         | Notes                                                                                                                                                         |
| ------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0.1.0   | Initial ML-KEM release        | ML-KEM 512/768/1024 with KAT evidence.                                                                                                                        |
| 0.2.0   | ML-KEM validation hardening   | Input validation, KAT discovery, scoped ML-KEM docs.                                                                                                          |
| 0.2.1   | OpenSSL and zero-dep release  | All-parameter OpenSSL interop, vendored FIPS 202, web tests.                                                                                                  |
| 0.3.0   | ML-DSA validation + hardening | Byte-exact FIPS 204 KATs (44/65/87 × raw/pure/hashed × det/hedged), HashML-DSA, vendored SHA-2, KEM constant-time output selection, zeroization, SECURITY.md. |
| 0.3.1   | Package metadata alignment    | Published package metadata reflects zero dependencies, ML-KEM, ML-DSA, and checked-in vector evidence.                                                        |
| 0.4.0   | SLH-DSA (FIPS 205, 12 sets)   | All 12 SLH-DSA sets (SHAKE + SHA-2) byte-exact on the 1,248-case NIST ACVP corpus; hedged API, verify-after-sign, OpenSSL/liboqs interop.                     |
| 0.4.2   | Docs in the published archive | Cookbook markdown ships in the pub.dev archive. Tag `vX.Y.Z` publishes and opens the GitHub Release.                                                          |
| 0.4.3   | ML-KEM size tables exported   | `KyberParams` and `KyberLevel` are exported from the package root.                                                                                            |
| 0.4.4   | Seeded SLH-DSA key generation | Public `SlhDsa.generateKeyPairSeeded` (FIPS 205 Algorithm 18).                                                                                                |
| 0.4.5   | Division removal              | Secret-dependent `%` and `~/` removed from the ML-KEM and ML-DSA coefficient paths. ML-KEM coefficients are an `Int16List`. Published.                        |

## Completed Documentation and Boundary Cleanup

| Task                                                     | Priority | Status |
| -------------------------------------------------------- | -------- | ------ |
| Consolidate documentation under `doc/`.                  | P0       | Done   |
| Update README/AGENTS/CLAUDE doc links.                   | P0       | Done   |
| Mark ML-DSA as exported but experimental.                | P0       | Done   |
| Remove stale pointycastle-era docs.                      | P0       | Done   |
| Fix package metadata if it undersells/overstates ML-DSA. | P1       | Done   |

Release criteria:

- no stale old-directory references remain;
- no stale `pointycastle` dependency claims remain outside historical notes;
- README and `doc/INDEX.md` link every maintained document;
- ML-DSA readiness wording matches current tests.

## 0.3.0 - ML-DSA Validation and Cross-Cutting Hardening

This milestone is **complete** (the security-hardening work originally scheduled
for 0.4.0 was folded in).

| Task                                                       | Priority | Status                 |
| ---------------------------------------------------------- | -------- | ---------------------- |
| Use the FIPS 204 release guide as the controlling plan.    | P0       | Done                   |
| Fix ML-DSA packing round-trip failures.                    | P0       | Done                   |
| Fix ML-DSA `ExpandS` bounded sampling failure.             | P0       | Done                   |
| Remove hardcoded external ML-DSA KAT path.                 | P0       | Done                   |
| Add repo-local ML-DSA KAT corpus and discovered runner.    | P0       | Done                   |
| Add negative ML-DSA verification tests.                    | P1       | Done                   |
| Validated public API: hedged default, context, HashML-DSA. | P1       | Done                   |
| Make ML-DSA side-channel checks no-early-exit.             | P1       | Done                   |
| Add zeroization helpers and apply in KEM and DSA.          | P0       | Done                   |
| Add constant-time select for KEM decapsulation output.     | P1       | Done                   |
| Audit all rejection loops and comparisons.                 | P1       | Done (residual DSA-20) |
| Add security reporting process (`SECURITY.md`).            | P1       | Done                   |
| Expand malformed-input tests.                              | P1       | Done                   |
| Bump package metadata to `0.3.0`.                          | P0       | Done                   |

Release criteria (met):

- [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md) Definition of
  Done is complete;
- `dart test` passes on VM, plus the `dart2js`/`dart2wasm` web gates;
- ML-DSA-44/65/87 KATs pass byte-exact from the checked-in corpus (raw/pure/
  hashed × det/hedged); the 3000-vector ML-KEM corpus stays byte-exact after the
  decapsulation hardening;
- ML-DSA docs upgraded from experimental to validated-in-repo;
- no readiness wording exceeds the KAT/regression evidence (no CMVP/FIPS 140).

Remaining (carried forward, not release-blocking): deeper constant-time review
(DSA-20), broader HashML-DSA pre-hash functions (DSA-21), and the maintainer's
`dart pub publish` / tag decision.

## 0.4.0 - SLH-DSA (FIPS 205, all 12 sets)

Introduce stateless hash-based signatures (SLH-DSA, FIPS 205) as the next
signature scheme. It is hash-only (no lattice arithmetic) and is a strong
diversification against any future lattice cryptanalysis. The implementation was
sequenced by hash family — the six **SHAKE** sets first (they reuse `KeccakXof`
and add no new primitive, isolating correctness risk), then the six **SHA-2**
sets — but all 12 are now byte-exact against the official NIST ACVP corpus and
ship together in 0.4.0. See
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md).

| Task                                                              | Priority | Status |
| ----------------------------------------------------------------- | -------- | ------ |
| Acquire + check in NIST ACVP SLH-DSA vectors (provenance README). | P0       | Done   |
| Shared scaffolding: params, util, `ADRS` (32B), SHAKE hashing.    | P0       | Done   |
| Implement WOTS+, XMSS, hypertree, FORS (Algorithms 5-17).         | P0       | Done   |
| Internal + external SLH-DSA (Algorithms 18-25); ACVP KAT runner.  | P0       | Done   |
| Hedged default; `s`-variant gating; BUFF + performance docs.      | P0       | Done   |
| Public API boundary (all 12) and optional verify-after-sign.      | P0       | Done   |
| Zeroization and VM/dart2js/dart2wasm SHAKE benchmark baselines.   | P1       | Done   |
| Full VM/web package matrix and publication preflight.             | P0       | Done   |
| OpenSSL/liboqs native interop tooling.                            | P1       | Done   |

Release criteria:

- byte-exact against the checked-in NIST ACVP SLH-DSA corpus for all 12
  parameter sets (keyGen/sigGen/sigVer);
- `dart test` plus web gates green; at least one benchmark per set per target;
- BUFF and performance caveats surfaced at the API level; default `shake128f`;
- evidence-scoped docs (no CMVP/FIPS 140 claim); zero added runtime dependencies.

Engineering release gates are complete. 0.4.0 was tagged and published. The
current package is 0.4.5.

### SHA-2 family (originally a separate later release, folded into 0.4.0)

The six **SHA-2** sets were originally planned as a separate later release to
isolate the new hand-vendored primitives — HMAC-SHA-256/512 (RFC 4231),
MGF1-SHA-256/512 (RFC 8017), the 22-byte compressed address (`ADRS^c`), and the
security-category 1 vs 3/5 SHA-256/SHA-512 split — each gated on its own
known-answer test before composition. That work is complete and byte-exact
against ACVP for all 12 sets, so it ships in 0.4.0; the split now records the
implementation sequence only.

See [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md) for the
full A-Z implementation, hardening, and milestone plan.

## 0.5.0 - Performance and Platform Work

GitHub milestone: **v0.5.0 - Performance and Platform Work**.

| Issue | Task                                            | Priority | Status |
| ----- | ----------------------------------------------- | -------- | ------ |
| #7    | Add automated benchmark suite.                  | P1       | Open   |
| #11   | Measure AOT, dart2js, and dart2wasm paths.      | P1       | Open   |
| #12   | Consider `Int32List` Kyber polynomial refactor. | P2       | Closed. Coefficients are an `Int16List`. |
| #13   | Consider in-place Kyber NTT.                    | P2       | Open   |
| #14   | Evaluate native SHAKE only as optional tooling. | P3       | Open   |

Zero runtime dependencies stay unless a separate package boundary is introduced.

## 0.6.0 - FIPS 202 and SP 800-185

GitHub milestone: **v0.6.0 - FIPS 202 and SP 800-185**. Spillover milestone: **v0.7.0 - FIPS 202 and SP 800-185 spillover** (no issues). Controlled by [FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md).

| Issue | Task                                              | Priority | Status |
| ----- | ------------------------------------------------- | -------- | ------ |
| #36   | Source corpus and NIST example-vector provenance. | P0       | Open   |
| #37   | SHA3-224 and SHA3-384 APIs.                       | P0       | Closed |
| #38   | FIPS 202 conformance harness, including bit cases.| P0       | Open   |
| #39   | Keccak constants, suffix, rate, and capacity.     | P0       | Closed |
| #40   | SP 800-185 encoding helpers.                      | P0       | Open   |
| #41   | cSHAKE128/256.                                    | P0       | Open   |
| #42   | KMAC128/256 and KMACXOF.                          | P0       | Open   |
| #43   | TupleHash and TupleHashXOF.                       | P1       | Open   |
| #44   | ParallelHash and ParallelHashXOF.                 | P1       | Open   |
| #45   | Security, zeroization, and API misuse docs.       | P1       | Open   |
| #46   | VM/web portability and benchmarks.                | P1       | Open   |
| #47   | Release docs, changelog, and package metadata.    | P0       | Open   |
| #48   | Epic.                                             | P0       | Open   |

Release criteria:

- all claimed functions pass checked-in NIST example vectors;
- byte-only limitations or bit-level support are explicit;
- `dart test`, `dart test -p chrome`, and `dart test -p chrome --compiler
  dart2wasm` are green;
- KMAC key/tag guidance is surfaced in API docs and README;
- no runtime dependency is added; and
- public wording remains algorithm/vector evidence only, not CMVP/FIPS 140.

## 1.0.0 - Stable API

GitHub milestone: **v1.0.0 - Stable API**. Open issues: #31, #32, #33.

Release criteria:

- ML-KEM KAT and interop evidence remains green;
- ML-DSA is validated in-repo (done at 0.3.0) and its API is stable;
- public API is frozen;
- documentation and package metadata match release evidence;
- external security review has been considered or explicitly deferred.

## Extended Algorithms

| Algorithm  | Direction                                                                         |
| ---------- | --------------------------------------------------------------------------------- |
| SLH-DSA    | 0.4.0, FIPS 205, all 12 sets (SHAKE + SHA-2), hash-based; reuses FIPS 202/180-4.  |
| SHA-3      | 0.6.0 target, 0.7.0 spillover; full FIPS 202 and SP 800-185 release workstream.   |
| LMS / XMSS | Stateful HBS (SP 800-208); separate future workstream. NIST ACVP vectors on hand. |
| HQC        | Consider after final standard details are stable and ML-KEM remains green.        |
| FN-DSA     | Defer until sampler and side-channel approach are credible in Dart.               |

SLH-DSA detail is in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md); broader
expansion guidance is in
[ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

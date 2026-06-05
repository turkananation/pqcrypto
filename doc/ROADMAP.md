# Release Roadmap

Last updated: 2026-06-05

The roadmap starts from the released `0.2.1` state. It does not assume ML-DSA is
production-ready just because its API is exported.

## Version History

| Version | State                        | Notes                                                        |
| ------- | ---------------------------- | ------------------------------------------------------------ |
| 0.1.0   | Initial ML-KEM release       | ML-KEM 512/768/1024 with KAT evidence.                       |
| 0.2.0   | ML-KEM validation hardening  | Input validation, KAT discovery, scoped ML-KEM docs.         |
| 0.2.1   | OpenSSL and zero-dep release | All-parameter OpenSSL interop, vendored FIPS 202, web tests. |

## Next Release - 0.2.x Documentation and Boundary Cleanup

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

## 0.3.0 - ML-DSA Correctness and Validation

This milestone is **functionally complete**;

| Task                                                    | Priority | Status |
| ------------------------------------------------------- | -------- | ------ |
| Use the FIPS 204 release guide as the controlling plan. | P0       | Done   |
| Fix ML-DSA packing round-trip failures.                 | P0       | Done   |
| Fix ML-DSA `ExpandS` bounded sampling failure.          | P0       | Done   |
| Remove hardcoded external ML-DSA KAT path.              | P0       | Done   |
| Add repo-local ML-DSA KAT corpus and discovered runner. | P0       | Done   |
| Add negative ML-DSA verification tests.                 | P1       | Done   |
| Validated public API: hedged default, context, HashML-DSA. | P1    | Done   |
| Make ML-DSA side-channel checks no-early-exit.          | P1       | Done   |
| Tag/bump version and publish.                           | P0       | Done   |

Release criteria (met, pending tag):

- [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md) Definition of
  Done is complete;
- `dart test` passes on VM (160 tests), plus `dart2js`/`dart2wasm` web gates;
- ML-DSA-44/65/87 KATs pass byte-exact from the checked-in corpus (raw/pure/
  hashed × det/hedged);
- ML-DSA docs upgraded from experimental to validated-in-repo;
- no readiness wording exceeds the KAT/regression evidence (no CMVP/FIPS 140).

## 0.4.0 - Security Hardening

| Task                                                   | Priority | Status |
| ------------------------------------------------------ | -------- | ------ |
| Add zeroization helpers and apply in KEM/DSA.          | P0       | Done (DSA; apply to KEM next) |
| Add constant-time select for KEM decapsulation output. | P1       | Open   |
| Audit all rejection loops and comparisons.             | P1       | Done (ML-DSA; residual DSA-20) |
| Add security reporting process.                        | P1       | Open   |
| Expand malformed-input tests.                          | P1       | Done (ML-DSA `dsa_negative_test.dart`) |

## 0.5.0 - Performance and Platform Work

| Task                                            | Priority | Status |
| ----------------------------------------------- | -------- | ------ |
| Add automated benchmark suite.                  | P1       | Open   |
| Measure AOT, dart2js, and dart2wasm paths.      | P1       | Open   |
| Consider `Int32List` Kyber polynomial refactor. | P2       | Open   |
| Consider in-place Kyber NTT.                    | P2       | Open   |
| Evaluate native SHAKE only as optional tooling. | P3       | Open   |

The package should preserve zero runtime dependencies unless a deliberate
feature flag or separate package boundary is introduced.

## 1.0.0 - Stable API

Release criteria:

- ML-KEM KAT and interop evidence remains green;
- ML-DSA readiness decision is resolved;
- public API is frozen;
- documentation and package metadata match release evidence;
- external security review has been considered or explicitly deferred.

## Extended Algorithms

| Algorithm | Direction                                                                  |
| --------- | -------------------------------------------------------------------------- |
| SLH-DSA   | Best next signature candidate after ML-DSA validation.                     |
| HQC       | Consider after final standard details are stable and ML-KEM remains green. |
| FN-DSA    | Defer until sampler and side-channel approach are credible in Dart.        |

See [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

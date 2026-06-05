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

| Task                                                    | Priority | Status |
| ------------------------------------------------------- | -------- | ------ |
| Fix ML-DSA packing round-trip failures.                 | P0       | Open   |
| Fix ML-DSA `ExpandS` bounded sampling failure.          | P0       | Open   |
| Remove hardcoded external ML-DSA KAT path.              | P0       | Open   |
| Add repo-local ML-DSA KAT corpus and discovered runner. | P0       | Open   |
| Add negative ML-DSA verification tests.                 | P1       | Open   |
| Decide validated public API shape for ML-DSA.           | P1       | Review |
| Make ML-DSA side-channel checks constant-time.          | P1       | Open   |

Release criteria:

- `dart test` passes on VM;
- ML-DSA-44/65/87 KATs pass from checked-in corpus;
- ML-DSA docs can be upgraded from experimental to validated-in-repo;
- no production readiness wording exceeds the new evidence.

## 0.4.0 - Security Hardening

| Task                                                   | Priority | Status |
| ------------------------------------------------------ | -------- | ------ |
| Add zeroization helpers and apply in KEM/DSA.          | P0       | Open   |
| Add constant-time select for KEM decapsulation output. | P1       | Open   |
| Audit all rejection loops and comparisons.             | P1       | Open   |
| Add security reporting process.                        | P1       | Open   |
| Expand malformed-input tests.                          | P1       | Open   |

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

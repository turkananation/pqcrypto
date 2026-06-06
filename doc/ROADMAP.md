# Release Roadmap

Last updated: 2026-06-05

The roadmap starts from the `0.3.0` state: both ML-KEM (FIPS 203) and ML-DSA
(FIPS 204) are byte-exact against their checked-in KAT corpora, with KEM/DSA
side-channel and zeroization hardening folded in. Claims remain scoped to
algorithm/KAT conformance, not CMVP/FIPS 140 module validation
([FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)).

## Version History

| Version | State                         | Notes                                                                                                                                                         |
| ------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0.1.0   | Initial ML-KEM release        | ML-KEM 512/768/1024 with KAT evidence.                                                                                                                        |
| 0.2.0   | ML-KEM validation hardening   | Input validation, KAT discovery, scoped ML-KEM docs.                                                                                                          |
| 0.2.1   | OpenSSL and zero-dep release  | All-parameter OpenSSL interop, vendored FIPS 202, web tests.                                                                                                  |
| 0.3.0   | ML-DSA validation + hardening | Byte-exact FIPS 204 KATs (44/65/87 × raw/pure/hashed × det/hedged), HashML-DSA, vendored SHA-2, KEM constant-time output selection, zeroization, SECURITY.md. |

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

## 0.4.0 - SLH-DSA SHAKE Family (FIPS 205)

Introduce stateless hash-based signatures (SLH-DSA, FIPS 205) as the next
signature scheme. It is hash-only (no lattice arithmetic) and is a strong
diversification against any future lattice cryptanalysis. Per the
council-reviewed release strategy in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md), the six
**SHAKE** parameter sets ship first: they reuse `KeccakXof` and add no new
cryptographic primitive, which isolates correctness risk before the SHA-2 family.

| Task                                                              | Priority | Status |
| ----------------------------------------------------------------- | -------- | ------ |
| Acquire + check in NIST ACVP SLH-DSA vectors (provenance README). | P0       | Open   |
| Shared scaffolding: params, util, `ADRS` (32B), SHAKE hashing.    | P0       | Open   |
| Implement WOTS+, XMSS, hypertree, FORS (Algorithms 5-17).         | P0       | Open   |
| Internal + external SLH-DSA (Algorithms 18-25); ACVP KAT runner.  | P0       | Open   |
| Hedged default; `s`-variant gating; BUFF + performance docs.      | P0       | Open   |
| Zeroization, benchmarks, cross-platform (VM/dart2js/dart2wasm).   | P1       | Open   |

Release criteria:

- byte-exact against the checked-in NIST ACVP SLH-DSA corpus for the six SHAKE
  sets (keyGen/sigGen/sigVer);
- `dart test` plus web gates green; at least one benchmark per set per target;
- BUFF and performance caveats surfaced at the API level; default `shake128f`;
- evidence-scoped docs (no CMVP/FIPS 140 claim); zero added runtime dependencies.

## 0.5.0 - SLH-DSA SHA-2 Family (FIPS 205)

Add the six **SHA-2** parameter sets. These require vendoring HMAC-SHA-256/512
and MGF1-SHA-256/512, the 22-byte compressed address (`ADRS^c`), and the
SHA-256/SHA-512 split for security categories 3 and 5 - each gated on its own
known-answer test before it enters the SLH-DSA composition.

| Task                                                         | Priority | Status |
| ------------------------------------------------------------ | -------- | ------ |
| Vendor + independently KAT-gate HMAC-SHA-256/512 (RFC 4231). | P0       | Open   |
| Vendor + independently KAT-gate MGF1-SHA-256/512 (RFC 8017). | P0       | Open   |
| `ADRS^c` (22B) + SHA-2 hashing (cat 1 and cat 3/5 split).    | P0       | Open   |
| Wire 6 SHA-2 sets; extend ACVP KAT to all 12; cross-verify.  | P0       | Open   |

Release criteria:

- HMAC and MGF1 byte-exact against RFC 4231 / RFC 8017 before composition;
- byte-exact against ACVP vectors for all six SHA-2 sets (12 total);
- `dart test` plus web gates green; evidence-scoped docs; zero runtime deps.

See [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md) for the
full A-Z implementation, hardening, and milestone plan.

## 0.6.0 - Performance and Platform Work

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
- ML-DSA is validated in-repo (done at 0.3.0) and its API is stable;
- public API is frozen;
- documentation and package metadata match release evidence;
- external security review has been considered or explicitly deferred.

## Extended Algorithms

| Algorithm  | Direction                                                                         |
| ---------- | --------------------------------------------------------------------------------- |
| SLH-DSA    | 0.4.0 (SHAKE) + 0.5.0 (SHA-2), FIPS 205, hash-based; reuses FIPS 202/180-4.       |
| LMS / XMSS | Stateful HBS (SP 800-208); separate future workstream. NIST ACVP vectors on hand. |
| HQC        | Consider after final standard details are stable and ML-KEM remains green.        |
| FN-DSA     | Defer until sampler and side-channel approach are credible in Dart.               |

SLH-DSA detail is in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md); broader
expansion guidance is in
[ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

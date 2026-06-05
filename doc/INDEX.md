# pqcrypto Documentation Index

Last updated: 2026-06-05

This is the canonical documentation root for `pqcrypto`. Use `doc/` links for
project documentation; the older documentation directory has been retired.

## Current Package Boundary

| Area                         | Current state                                                                                                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Package version              | `0.3.0`                                                                                                                                    |
| Runtime dependencies         | None. FIPS 202 SHA3/SHAKE is vendored in `lib/src/common/keccak.dart`.                                                                     |
| ML-KEM                       | Supported for ML-KEM-512, ML-KEM-768, and ML-KEM-1024 with checked-in KAT and interop evidence.                                            |
| ML-DSA                       | FIPS 204-aligned for ML-DSA-44/65/87; byte-exact on the checked-in KAT corpus (raw/pure/hashed × det/hedged). Not CMVP/FIPS 140 validated. |
| OpenSSL interop              | ML-KEM A-G suite for all three parameter sets.                                                                                             |
| Certification claim boundary | Implementation/KAT evidence, not CMVP/FIPS 140 module validation. See [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).                        |

## Read This First

| Need                         | Start here                                                                       | Then read                                                |
| ---------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Current assurance boundary   | [MLKEM_TESTING.md](MLKEM_TESTING.md)                                             | [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)                 |
| ML-DSA release work          | [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md)                 | [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)               |
| OpenSSL interoperability     | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                                         | [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md)             |
| Architecture and code layout | [ARCHITECTURE.md](ARCHITECTURE.md)                                               | [PERFORMANCE.md](PERFORMANCE.md)                         |
| Security review              | [SECURITY_AUDIT.md](SECURITY_AUDIT.md)                                           | [BUGS.md](BUGS.md)                                       |
| Implementation planning      | [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)                                       | [ROADMAP.md](ROADMAP.md)                                 |
| Multi-agent PQC workflows    | [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md) | [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md) |
| Future algorithms            | [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md)                     | [IMPROVEMENTS.md](IMPROVEMENTS.md)                       |
| Serverpod/Flutter use        | [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md)                         | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                 |

## Documents

| Document                                                                         | Purpose                                                                              |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| [MLKEM_TESTING.md](MLKEM_TESTING.md)                                             | Checked-in ML-KEM KAT corpus, hashes, coverage, release gates, and claim boundary.   |
| [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md)                 | FIPS 204 implementation, validation, hardening, and release guide for ML-DSA.        |
| [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                                         | OpenSSL ML-KEM interop matrix, harness, platform notes, and results.                 |
| [ARCHITECTURE.md](ARCHITECTURE.md)                                               | Current module layout, API surface, data flow, and package boundaries.               |
| [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)                                         | Evidence-scoped FIPS 203/204/202/180-4 status.                                       |
| [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)                                     | Why we claim algorithm conformance but not CMVP/FIPS 140 module validation.          |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md)                                           | Current security posture, resolved issues, open risks, and audit priorities.         |
| [BUGS.md](BUGS.md)                                                               | Known bugs and regressions, especially ML-DSA blockers.                              |
| [IMPROVEMENTS.md](IMPROVEMENTS.md)                                               | Prioritized engineering improvements with current status.                            |
| [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)                                       | Cross-document tracker for open work and validation gates.                           |
| [ROADMAP.md](ROADMAP.md)                                                         | Release direction after 0.3.0.                                                       |
| [PERFORMANCE.md](PERFORMANCE.md)                                                 | Performance baseline, optimization ideas, and benchmark guidance.                    |
| [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md)                                     | Contributor setup, test commands, coding conventions, and security practices.        |
| [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md)                     | Guidance for SLH-DSA, HQC, FN-DSA, and future PQC work.                              |
| [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md)                         | Example ML-KEM + ML-DSA handshake pattern for Serverpod and Flutter.                 |
| [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md) | Project-level Codex/Claude/Antigravity agent framework for PQC integration planning. |

## Verification Snapshot

The current local verification snapshot used for this documentation pass:

- `dart analyze` exits 0.
- `dart test` is **green**: 160 tests including the ML-KEM KAT runner (1000
  vectors each at 512/768/1024) and the ML-DSA KAT runner (18 files;
  300 byte-exact key generations and 1800 byte-exact signatures that all
  verify, across ML-DSA-44/65/87 × {det, hedged} × {raw, pure, hashed}).
- `dart test -p chrome` (dart2js) and `dart test -p chrome --compiler dart2wasm`
  are green (the file-based KAT runners are VM-only and auto-skip on web).
- `dart format --set-exit-if-changed .` and `markdownlint-cli2 "**/*.md"` pass.
- The OpenSSL interop workflow is maintained separately in
  `.github/workflows/interop.yml` and `tool/openssl_interop/`.

Do not upgrade readiness wording unless a fresh verification run supports it.
The KAT corpora are described in `test/data/MLKEM/README.md` and
`test/data/MLDSA/README.md`.

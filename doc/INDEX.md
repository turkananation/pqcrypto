# pqcrypto Documentation Index

Last updated: 2026-06-05

This is the canonical documentation root for `pqcrypto`. Use `doc/` links for
project documentation; the older documentation directory has been retired.

## Current Package Boundary

| Area                         | Current state                                                                                   |
| ---------------------------- | ----------------------------------------------------------------------------------------------- |
| Package version              | `0.2.1`                                                                                         |
| Runtime dependencies         | None. FIPS 202 SHA3/SHAKE is vendored in `lib/src/common/keccak.dart`.                          |
| ML-KEM                       | Supported for ML-KEM-512, ML-KEM-768, and ML-KEM-1024 with checked-in KAT and interop evidence. |
| ML-DSA                       | Exported but experimental. The current full test suite fails in ML-DSA/debug tests.             |
| OpenSSL interop              | ML-KEM A-G suite for all three parameter sets.                                                  |
| Certification claim boundary | This repository provides implementation evidence, not CMVP/FIPS 140 module validation.          |

## Read This First

| Need                         | Start here                                                   | Then read                                    |
| ---------------------------- | ------------------------------------------------------------ | -------------------------------------------- |
| Current assurance boundary   | [MLKEM_TESTING.md](MLKEM_TESTING.md)                         | [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)     |
| OpenSSL interoperability     | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                     | [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md) |
| Architecture and code layout | [ARCHITECTURE.md](ARCHITECTURE.md)                           | [PERFORMANCE.md](PERFORMANCE.md)             |
| Security review              | [SECURITY_AUDIT.md](SECURITY_AUDIT.md)                       | [BUGS.md](BUGS.md)                           |
| Implementation planning      | [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)                   | [ROADMAP.md](ROADMAP.md)                     |
| Future algorithms            | [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md) | [IMPROVEMENTS.md](IMPROVEMENTS.md)           |
| Serverpod/Flutter use        | [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md)     | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)     |

## Documents

| Document                                                     | Purpose                                                                            |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| [MLKEM_TESTING.md](MLKEM_TESTING.md)                         | Checked-in ML-KEM KAT corpus, hashes, coverage, release gates, and claim boundary. |
| [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                     | OpenSSL ML-KEM interop matrix, harness, platform notes, and results.               |
| [ARCHITECTURE.md](ARCHITECTURE.md)                           | Current module layout, API surface, data flow, and package boundaries.             |
| [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)                     | Evidence-scoped FIPS 203/204/202 status.                                           |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md)                       | Current security posture, resolved issues, open risks, and audit priorities.       |
| [BUGS.md](BUGS.md)                                           | Known bugs and regressions, especially ML-DSA blockers.                            |
| [IMPROVEMENTS.md](IMPROVEMENTS.md)                           | Prioritized engineering improvements with current status.                          |
| [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)                   | Cross-document tracker for open work and validation gates.                         |
| [ROADMAP.md](ROADMAP.md)                                     | Release direction after 0.2.1.                                                     |
| [PERFORMANCE.md](PERFORMANCE.md)                             | Performance baseline, optimization ideas, and benchmark guidance.                  |
| [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md)                 | Contributor setup, test commands, coding conventions, and security practices.      |
| [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md) | Guidance for SLH-DSA, HQC, FN-DSA, and future PQC work.                            |
| [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md)     | Example ML-KEM session establishment pattern for Serverpod and Flutter.            |

## Verification Snapshot

The current local verification snapshot used for this documentation pass:

- `dart analyze` exits successfully with three info-level `avoid_print` notes in
  `test/kat_evaluator_test.dart`.
- `dart test` is not fully green because ML-DSA/debug tests fail. The same run
  completes the ML-KEM KAT runner for 1000 vectors each at ML-KEM-512,
  ML-KEM-768, and ML-KEM-1024.
- The OpenSSL interop workflow is maintained separately in
  `.github/workflows/interop.yml` and `tool/openssl_interop/`.

Do not upgrade readiness wording unless a fresh verification run supports it.

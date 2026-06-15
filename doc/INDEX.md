# pqcrypto Documentation Index

Last updated: 2026-06-15

This is the canonical documentation root for `pqcrypto`. Use `doc/` links for
project documentation; the older documentation directory has been retired.

## Current Package Boundary

| Area                         | Current state                                                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Package version              | `0.3.1`                                                                                                                                           |
| Runtime dependencies         | None. Partial FIPS 202 SHA3/SHAKE is vendored in `lib/src/common/keccak.dart`.                                                                    |
| ML-KEM                       | Supported for ML-KEM-512, ML-KEM-768, and ML-KEM-1024 with checked-in KAT and interop evidence.                                                   |
| ML-DSA                       | FIPS 204-aligned for ML-DSA-44/65/87; byte-exact on the checked-in KAT corpus (raw/pure/hashed × det/hedged). Not CMVP/FIPS 140 validated.        |
| FIPS 202 / SP 800-185        | FIPS 202 is partial today (SHA3-256/512, SHAKE128/256). Full FIPS 202 and SP 800-185 target 0.6.0, with 0.7.0 spillover if needed.                |
| SLH-DSA                      | FIPS 205 release candidate. All 12 sets (SHAKE + SHA-2) are exported in source and 1,248/1,248 ACVP cases pass; v0.4.0 gates remain.              |
| OpenSSL interop              | ML-KEM A-G suite for all three parameter sets.                                                                                                    |
| Certification claim boundary | Implementation/KAT evidence, not CMVP/FIPS 140 module validation. See [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).                               |

## Read This First

| Need                            | Start here                                                                       | Then read                                                |
| ------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Current assurance boundary      | [MLKEM_TESTING.md](MLKEM_TESTING.md)                                             | [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)                 |
| FIPS 202 / SP 800-185 work      | [FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md)           | [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)               |
| ML-DSA release work             | [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md)                 | [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)               |
| SLH-DSA release work            | [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md)               | [ROADMAP.md](ROADMAP.md)                                 |
| OpenSSL interoperability        | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                                         | [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md)             |
| Architecture and code layout    | [ARCHITECTURE.md](ARCHITECTURE.md)                                               | [PERFORMANCE.md](PERFORMANCE.md)                         |
| Security review                 | [SECURITY_AUDIT.md](SECURITY_AUDIT.md)                                           | [BUGS.md](BUGS.md)                                       |
| Implementation planning         | [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)                                       | [ROADMAP.md](ROADMAP.md)                                 |
| Multi-agent PQC workflows       | [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md) | [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md) |
| Future algorithms               | [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md)                     | [IMPROVEMENTS.md](IMPROVEMENTS.md)                       |
| Serverpod/Flutter use           | [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md)                         | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                 |
| Project ideas by domain         | [cookbook/README.md](cookbook/README.md)                                         | [PROJECT_CATALOG.md](cookbook/PROJECT_CATALOG.md)        |
| Public website and AI discovery | [Website](https://turkananation.github.io/pqcrypto/)                             | [../llms.txt](../llms.txt)                               |

## Documents

| Document                                                                         | Purpose                                                                              |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| [MLKEM_TESTING.md](MLKEM_TESTING.md)                                             | Checked-in ML-KEM KAT corpus, hashes, coverage, release gates, and claim boundary.   |
| [FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md)           | A-Z compliance and release plan for full FIPS 202 plus SP 800-185 support.           |
| [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md)                 | FIPS 204 implementation, validation, hardening, and release guide for ML-DSA.        |
| [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md)               | FIPS 205 implementation and release plan for SLH-DSA (SHAKE then SHA-2).             |
| [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)                                         | OpenSSL ML-KEM interop matrix, harness, platform notes, and results.                 |
| [ARCHITECTURE.md](ARCHITECTURE.md)                                               | Current module layout, API surface, data flow, and package boundaries.               |
| [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)                                         | Evidence-scoped FIPS 203/204/202/180-4/SP 800-185 status.                            |
| [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)                                     | Why we claim algorithm conformance but not CMVP/FIPS 140 module validation.          |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md)                                           | Current security posture, resolved issues, open risks, and audit priorities.         |
| [BUGS.md](BUGS.md)                                                               | Known bugs and regressions, especially ML-DSA blockers.                              |
| [IMPROVEMENTS.md](IMPROVEMENTS.md)                                               | Prioritized engineering improvements with current status.                            |
| [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)                                       | Cross-document tracker for open work and validation gates.                           |
| [ROADMAP.md](ROADMAP.md)                                                         | Release direction after 0.3.1.                                                       |
| [PERFORMANCE.md](PERFORMANCE.md)                                                 | Performance baseline, optimization ideas, and benchmark guidance.                    |
| [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md)                                     | Contributor setup, test commands, coding conventions, and security practices.        |
| [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md)                     | Guidance for SLH-DSA, HQC, FN-DSA, and future PQC work.                              |
| [SERVERPOD_FLUTTER_GUIDE.md](SERVERPOD_FLUTTER_GUIDE.md)                         | Example ML-KEM + ML-DSA handshake pattern for Serverpod and Flutter.                 |
| [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md) | Project-level Codex/Claude/Antigravity agent framework for PQC integration planning. |
| [cookbook/README.md](cookbook/README.md)                                         | Builder-facing project-idea catalog and reusable recipes across domains.             |
| [../tool/visibility/README.md](../tool/visibility/README.md)                     | Generated GitHub Pages, AI discovery files, and coding-agent rule surfaces.          |

## Verification Snapshot

The current local verification snapshot used for this documentation pass:

- `dart analyze` exits 0.
- The focused VM gates are green, including the ML-KEM KAT runner (1000
  vectors each at 512/768/1024) and the ML-DSA KAT runner (18 files;
  300 byte-exact key generations and 1800 byte-exact signatures that all
  verify, across ML-DSA-44/65/87 × {det, hedged} × {raw, pure, hashed}).
- The SLH-DSA gate is byte-exact on 1,248 ACVP cases (120 keyGen, 624 sigGen,
  504 sigVer) across all 12 sets, plus component/API/negative regressions.
  Optional verify-after-sign has focused coverage. The full `s`-set runner is
  intentionally expensive.
- The portable SLH-DSA benchmark records keygen/sign/verify for all 12 sets
  under VM JIT, compiled JavaScript, and compiled Wasm. Results and exact
  commands are in [PERFORMANCE.md](PERFORMANCE.md).
- The complete portable package suite is green under both `dart2js` and
  `dart2wasm` (217/217 each). The VM suite is green as a decomposed matrix:
  256/256 non-SLH-KAT tests plus all six per-parameter SLH-DSA ACVP gates.
- Package publication dry-run validates the 189 KB archive; its only warning is
  the expected uncommitted feature-worktree state.
- `dart format --set-exit-if-changed .` passes; the 12 files touched by this
  SLH-DSA milestone pass the configured Markdown lint. Repository-wide Markdown
  cleanup remains separate from the SLH-DSA evidence gate.
- The OpenSSL interop workflow is maintained separately in
  `.github/workflows/interop.yml` and `tool/openssl_interop/`.

Do not upgrade readiness wording unless a fresh verification run supports it.
The KAT corpora are described in `test/data/MLKEM/README.md` and
`test/data/MLDSA/README.md`.

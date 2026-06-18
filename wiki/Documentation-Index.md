# Documentation Index

A complete map of `pqcrypto`'s documentation. The wiki pages (linked by name)
are the friendly front door; the canonical, version-controlled documents live in
the repository's
[`doc/`](https://github.com/turkananation/pqcrypto/tree/main/doc) directory and
mirror the in-repo
[doc/INDEX.md](https://github.com/turkananation/pqcrypto/blob/main/doc/INDEX.md).

## Getting started

- [Home](Home) — overview and 60-second quickstart.
- [Installation](Installation) — add the package, platforms, setup.
- [Quickstart](Quickstart) — ML-KEM, ML-DSA, HashML-DSA, and SLH-DSA in minutes.
- [Cookbook](Cookbook) — project ideas and reusable recipes.
- [README](https://github.com/turkananation/pqcrypto/blob/main/README.md) — the
  pub.dev landing page.

## Algorithms

- [Cryptographic Algorithms](Cryptographic-Algorithms) — overview and
  comparison.
- [ML-KEM (FIPS 203)](ML-KEM) — key encapsulation.
- [ML-DSA (FIPS 204)](ML-DSA) — digital signatures.
- [SLH-DSA (FIPS 205)](SLH-DSA) — hash-based signatures.
- [MLKEM_TESTING.md](https://github.com/turkananation/pqcrypto/blob/main/doc/MLKEM_TESTING.md)
  — ML-KEM KAT corpus and gates.
- [MLDSA_FIPS204_RELEASE_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/MLDSA_FIPS204_RELEASE_GUIDE.md)
  — ML-DSA implementation and validation.
- [SLHDSA_FIPS205_RELEASE_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/SLHDSA_FIPS205_RELEASE_GUIDE.md)
  — SLH-DSA implementation and validation (all 12 sets).
- [ALGORITHM_EXPANSION_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ALGORITHM_EXPANSION_GUIDE.md)
  — future PQC directions.

## Architecture and design

- [Architecture](Architecture) and
  [ARCHITECTURE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ARCHITECTURE.md)
  — module layout and data flow.
- [Design Philosophy](Design-Philosophy) — the tenets.
- [Performance](Performance) and
  [PERFORMANCE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/PERFORMANCE.md)
  — baseline and guidance.
- [ENGINEERING_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ENGINEERING_GUIDE.md)
  — contributor setup and conventions.

## Assurance: security, compliance, validation

- [Security Posture](Security-Posture) and
  [SECURITY_AUDIT.md](https://github.com/turkananation/pqcrypto/blob/main/doc/SECURITY_AUDIT.md)
  — threat model and audit status.
- [FIPS Compliance](FIPS-Compliance),
  [FIPS_COMPLIANCE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_COMPLIANCE.md),
  and
  [FIPS_140_BOUNDARY.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_140_BOUNDARY.md)
  — claim boundary.
- [Validation & Interoperability](Validation-and-Interoperability) and
  [OPENSSL_INTEROP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/OPENSSL_INTEROP.md)
  — KAT and interop evidence.
- [SECURITY.md](https://github.com/turkananation/pqcrypto/blob/main/SECURITY.md)
  — vulnerability disclosure.

## Integration and tooling

- [Serverpod & Flutter](Serverpod-Integration) and
  [SERVERPOD_FLUTTER_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/SERVERPOD_FLUTTER_GUIDE.md)
  — full client/server blueprint.
- [Multi-Agent PQC Framework](Multi-Agent-Framework) and
  [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](https://github.com/turkananation/pqcrypto/blob/main/doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md)
  — agent planning framework.

## Cookbook (in repository)

- [Cookbook README](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/README.md)
- [Building Blocks](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/BUILDING_BLOCKS.md)
- [Project Catalog](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/PROJECT_CATALOG.md)
- [Future Releases](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/FUTURE_RELEASES.md)
- [project-ideas.yaml](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/project-ideas.yaml)
  (machine-readable, for AI agents)

## Project and process

- [Roadmap](Roadmap) and
  [ROADMAP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ROADMAP.md)
- [PROGRESS_TRACKER.md](https://github.com/turkananation/pqcrypto/blob/main/doc/PROGRESS_TRACKER.md),
  [BUGS.md](https://github.com/turkananation/pqcrypto/blob/main/doc/BUGS.md),
  [IMPROVEMENTS.md](https://github.com/turkananation/pqcrypto/blob/main/doc/IMPROVEMENTS.md)
- [FIPS202_SP800185_RELEASE_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS202_SP800185_RELEASE_GUIDE.md)
  — SHA-3 family workstream.
- [Contributing](Contributing),
  [CONTRIBUTING.md](https://github.com/turkananation/pqcrypto/blob/main/CONTRIBUTING.md),
  [CODE_OF_CONDUCT.md](https://github.com/turkananation/pqcrypto/blob/main/CODE_OF_CONDUCT.md)
- [CHANGELOG.md](https://github.com/turkananation/pqcrypto/blob/main/CHANGELOG.md),
  [RELEASE.md](https://github.com/turkananation/pqcrypto/blob/main/RELEASE.md),
  [LICENSE](https://github.com/turkananation/pqcrypto/blob/main/LICENSE) (MIT)

## API reference

- [pub.dev API docs](https://pub.dev/documentation/pqcrypto/latest/) — generated
  dartdoc, including the **Cookbook** topic.

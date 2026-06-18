---
name: pqcrypto-doc-sync
description: Evidence-scoped documentation workflow for the pqcrypto repository. Use when updating README.md, doc/ guides, test-data provenance, release roadmaps, interop docs, cookbook docs, generated-visibility manifests, or any claim about delivered ML-KEM, ML-DSA, SLH-DSA, FIPS 202, FIPS 180-4, OpenSSL/liboqs interop, validation evidence, package boundaries, or release readiness.
---

# pqcrypto Doc Sync

Use this skill to keep documentation synchronized with delivered code and
checked evidence. It complements `universal-pqc-framework`; use both when the
doc task touches multi-agent Serverpod/Flutter planning or framework claims.

## Workflow

1. Read the live evidence before editing:
   - `README.md`, `CHANGELOG.md`, `pubspec.yaml`
   - `lib/pqcrypto.dart` and the touched implementation folders under `lib/src/`
   - relevant tests under `test/`, including KAT/corpus runners
   - relevant tools under `tool/`, especially `openssl_interop`, `liboqs_interop`,
     `interop_common`, `bench`, and `visibility`
2. Classify the change:
   - algorithm/API state: ML-KEM, ML-DSA, SLH-DSA, FIPS 202, FIPS 180-4, SP 800-185
   - evidence state: KATs, unit tests, VM/web gates, OpenSSL/liboqs interop,
     benchmarks, publish dry-run
   - package boundary: runtime dependencies, FFI/tool-only code, publish surface
   - release state: current release vs future roadmap (per `pubspec.yaml` and
     `doc/ROADMAP.md`)
3. Update every hand-maintained document that repeats the affected fact. Search
   before and after with `rg`; do not rely on one entrypoint.
4. Keep generated outputs out of direct edits. For website, AI discovery files,
   Copilot/Cursor/Windsurf rules, update `tool/visibility/visibility_manifest.json`
   and run:

```bash
dart run tool/visibility/generate_visibility.dart
dart run tool/visibility/generate_visibility.dart --check
```

1. Keep `doc/issues/` private-local. Do not stage, link, or publish it.
2. Run the narrow verification gate that matches the claim. For docs-only work,
   at minimum run `dart analyze` when practical and any lightweight doc/tool
   checks touched by the edit. Do not invent fresh "green" claims without
   running the referenced command in the current checkout.

## Claim Rules

- Say "FIPS 203/204/205-aligned" only with the matching checked-in evidence.
- Say "OpenSSL/liboqs interop" only for provider surfaces present under
  `tool/` and keep them tool-only, unpublished, and outside runtime deps.
- Match release-state wording to `pubspec.yaml` and `doc/ROADMAP.md`; distinguish
  the current release from future/roadmap work. `pubspec.yaml` is the package
  version source of truth.
- Never claim CMVP/FIPS 140 validation, certification, hard constant-time Dart,
  or hard memory-erasure guarantees.
- Keep performance numbers tied to `doc/PERFORMANCE.md`, target, date, and
  measurement method.

## Common Sync Targets

- Algorithm/API changes: `README.md`, `doc/INDEX.md`, `doc/ARCHITECTURE.md`,
  `doc/FIPS_COMPLIANCE.md`, `doc/SECURITY_AUDIT.md`,
  `doc/PROGRESS_TRACKER.md`, `doc/ROADMAP.md`, `CHANGELOG.md`, cookbook docs.
- Interop changes: `README.md`, `doc/OPENSSL_INTEROP.md`,
  `tool/openssl_interop/README.md`, `tool/liboqs_interop/README.md`,
  `doc/INDEX.md`, `doc/ENGINEERING_GUIDE.md`, `doc/PERFORMANCE.md`.
- Corpus/KAT changes: the relevant `test/data/*/README.md`, release guide,
  tracker, compliance doc, and README validation section.
- Standards-foundation changes: `doc/FIPS202_SP800185_RELEASE_GUIDE.md`,
  `doc/FIPS_COMPLIANCE.md`, `doc/SECURITY_AUDIT.md`, `doc/ROADMAP.md`,
  `doc/ENGINEERING_GUIDE.md`, README, and cookbook "you supply" tables.

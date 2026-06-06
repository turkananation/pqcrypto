# Cookbook — project ideas and recipes

The **Cookbook** is a catalog of things you can build with `pqcrypto` across
every domain, plus the reusable, API-correct recipes the ideas are made of. It
lives in the repository under
[`doc/cookbook/`](https://github.com/turkananation/pqcrypto/tree/main/doc/cookbook)
and is the fastest way from "I have the library" to "I shipped something
correct."

| Resource                                                                                                    | What's inside                                                                       |
| ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [Cookbook README](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/README.md)               | Index + the "what the package gives you vs what you supply" table + claim boundary. |
| [Building Blocks](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/BUILDING_BLOCKS.md)      | The 10 reusable recipes (BB1–BB10) with exact-API code.                             |
| [Project Catalog](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/PROJECT_CATALOG.md)      | ~45 project ideas across 7 domains, each gated with caveats.                        |
| [Future Releases](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/FUTURE_RELEASES.md)      | Ideas unlocked by upcoming algorithms.                                              |
| [`project-ideas.yaml`](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/project-ideas.yaml) | Machine-readable manifest for AI agents and codegen tools.                          |

## The building blocks

Every project composes these ten recipes (full code in
[Building Blocks](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/BUILDING_BLOCKS.md)):

- **BB1 — Detached signatures**: tokens, signed records, document e-signing.
- **BB2 — Encrypt to a public key (KEM-DEM)**: the correct way to encrypt data
  with ML-KEM (shared secret → KDF → AEAD).
- **BB3 — Hybrid authenticated handshake**: classical + lattice + ML-DSA.
- **BB4 — Identity enrollment and key directory**: turn a key into an identity.
- **BB5 — Deterministic keys from a seed**: backup/restore and interop.
- **BB6 — Tamper-evident signed log**: hash-chained, signed audit trails.
- **BB7 — Signed software/firmware updates**: cheap on-device verification.
- **BB8 — Encrypted data at rest**: KEM-DEM applied to storage.
- **BB9 — Hybrid and dual signatures**: defense in depth during migration.
- **BB10 — Offloading heavy work**: isolates on mobile/desktop; web caveats.

## Ideas by domain

The [Project Catalog](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/PROJECT_CATALOG.md)
covers:

- **Servers & backends** — PQC handshakes, signed tokens/webhooks, update
  servers, transparency logs, sealed secrets, PKI directories.
- **Mobile (Flutter)** — E2E messaging, secure vaults, encrypted backup,
  offline signed records, document signing, key verification.
- **Desktop & CLI** — file encryption, artifact/commit signing, keyrings.
- **Embedded Linux / IoT** — update verification, device identity, signed
  telemetry, edge-to-cloud encryption, provenance.
- **Web** — in-browser E2E encryption and signing, interop demos.
- **Cross-language interop** — Dart ↔ OpenSSL/C/Python/Node/Go, hybrid-TLS
  components, migration harnesses.
- **Vertical industries** — fintech, healthcare, legal, govtech, supply chain,
  identity/credentials, media provenance (each with hard honesty flags).

## The one rule

Every idea leads with what the package genuinely does, then states plainly what
you must supply yourself (HKDF, AEAD, X25519, hashing, storage are **not** in the
package), then the caveats. An idea is not complete — and not safe to ship —
without its "you supply" list and its caveats.

See also: [Quickstart](Quickstart) · [ML-KEM](ML-KEM) · [ML-DSA](ML-DSA) ·
[Serverpod & Flutter](Serverpod-Integration).

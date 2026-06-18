# pqcrypto Cookbook — Project Ideas and Recipes

Last updated: 2026-06-16

This folder is a builder-facing catalog of things you can build with `pqcrypto`
across many domains — servers, mobile, desktop, CLI, embedded Linux, web,
cross-language interop, and vertical industries — plus the reusable code recipes
the ideas are made of.

It exists so a developer in **any** domain can find a concrete, correct starting
point that uses the package's real API, and ship it without accidentally
overclaiming security or building something the package was never meant to do.

> **How to read every page.** This catalog follows one rule throughout: lead
> with what the package genuinely does, then state plainly what you must supply
> yourself, then the caveats. An idea is not complete — and not safe to ship —
> without its "you supply" list and its caveats.

## Start here

| You want…                                 | Read                                                           |
| ----------------------------------------- | -------------------------------------------------------------- |
| The reusable code recipes (the backbone)  | [BUILDING_BLOCKS.md](BUILDING_BLOCKS.md)                       |
| A big list of project ideas, by domain    | [PROJECT_CATALOG.md](PROJECT_CATALOG.md)                       |
| Ideas unlocked by upcoming releases       | [FUTURE_RELEASES.md](FUTURE_RELEASES.md)                       |
| A machine-readable index (for AI agents)  | [project-ideas.yaml](project-ideas.yaml)                       |
| A full worked Serverpod + Flutter example | [../SERVERPOD_FLUTTER_GUIDE.md](../SERVERPOD_FLUTTER_GUIDE.md) |
| Proof of cross-implementation correctness | [../OPENSSL_INTEROP.md](../OPENSSL_INTEROP.md)                 |

Every project in [PROJECT_CATALOG.md](PROJECT_CATALOG.md) is composed from the
recipes in [BUILDING_BLOCKS.md](BUILDING_BLOCKS.md). Read the building blocks
once; then the catalog is just "which blocks, for which domain, with which
caveats."

## What pqcrypto gives you and what you supply

This is the single most important table in the cookbook. `pqcrypto` is a
**primitives** package: version `0.4.0` gives you ML-KEM, ML-DSA, and all 12
FIPS 205 SLH-DSA parameter sets. It is *not* a protocol, a TLS stack,
or an "encrypt my data" library on its own.

| Capability                                | In `pqcrypto`?           | Who provides it                                     |
| ----------------------------------------- | ------------------------ | --------------------------------------------------- |
| ML-KEM key encapsulation (FIPS 203)       | **Yes** — `PqcKem`       | The package                                         |
| ML-DSA digital signatures (FIPS 204)      | **Yes** — `MlDsa`        | The package                                         |
| SLH-DSA hash-based signatures (FIPS 205)  | **Yes** — `SlhDsa`       | The package                                         |
| A 32-byte ML-KEM shared secret            | **Yes**                  | The package (you still need a KDF + AEAD to use it) |
| Symmetric encryption of your data (AEAD)  | No                       | You — AES-GCM / ChaCha20-Poly1305 from your stack   |
| Key derivation (HKDF / KDF)               | No                       | You — HKDF from your stack                          |
| Classical key exchange (X25519, ECDH)     | No                       | You — for a hybrid handshake                        |
| Transcript / message hashing (SHA-256…)   | No (vendored internally) | You — a public hash from your stack                 |
| Keyed MAC (HMAC / KMAC)                   | No (KMAC planned, 0.6.0) | You — until SP 800-185 ships                        |
| Secure key storage, KMS/HSM, secrets mgmt | No                       | You — platform keystore / KMS / HSM                 |
| Random beyond `Random.secure()`           | No                       | You — your platform CSPRNG for nonces/salts         |
| Transport (TLS), sessions, replay windows | No                       | You — your server framework                         |

If an idea needs anything in the "You" column, the catalog says so explicitly on
that idea. The package vendors FIPS 202 SHA-3/SHAKE and FIPS 180-4 SHA-2
*internally* to implement ML-KEM, ML-DSA, and SLH-DSA, but **does not export
them** — so do not plan to call `pqcrypto` for your app's hashing or MAC today.
See [FUTURE_RELEASES.md](FUTURE_RELEASES.md) for what later versions add.

## The claim boundary (please honor it)

`pqcrypto` ships **algorithm/KAT-conformance and interoperability evidence** —
not a certification. Carry this wording into anything you build or publish:

- **Allowed:** "FIPS 203-aligned ML-KEM with checked-in KAT evidence",
  "FIPS 204-aligned ML-DSA, byte-exact on the checked-in KAT corpus",
  "OpenSSL interop A-G passes for ML-KEM-512/768/1024",
  "native-provider interop tooling covers ML-KEM, ML-DSA, and SLH-DSA outside
  the runtime package boundary", "FIPS 205-aligned SLH-DSA (all 12 sets) is
  byte-exact on the checked-in ACVP sample corpus", "best-effort zeroization in
  Dart".
- **Not allowed:** "FIPS validated", "CMVP validated", "certified",
  "constant-time guarantee", "memory is securely erased", or calling ML-KEM by
  itself "secure transport".

Two facts that trip up newcomers:

1. **ML-KEM is not authenticated transport.** It establishes a shared secret with
   whoever holds the public key. Without an authenticated public key and an AEAD
   layer on top, you have **not** built a secure channel.
2. **"Quantum-safe" does not mean "secure."** Post-quantum primitives only
   address the quantum threat to one part of your system. Authentication, key
   management, side channels, and your protocol design are still on you — and are
   usually the bigger risk.

See [../FIPS_140_BOUNDARY.md](../FIPS_140_BOUNDARY.md) and
[../SECURITY_AUDIT.md](../SECURITY_AUDIT.md) for the full posture.

## Algorithm and size quick reference

| Algorithm    | Security cat. | Public key | Secret key | Ct / Sig    | Shared secret |
| ------------ | ------------- | ---------- | ---------- | ----------- | ------------- |
| ML-KEM-512   | 1             | 800        | 1632       | 768 (ct)    | 32            |
| ML-KEM-768   | 3             | 1184       | 2400       | 1088 (ct)   | 32            |
| ML-KEM-1024  | 5             | 1568       | 3168       | 1568 (ct)   | 32            |
| ML-DSA-44    | 2             | 1312       | 2560       | 2420 (sig)  | —             |
| ML-DSA-65    | 3             | 1952       | 4032       | 3309 (sig)  | —             |
| ML-DSA-87    | 5             | 2592       | 4896       | 4627 (sig)  | —             |
| SLH-DSA-128s | 1             | 32         | 64         | 7856 (sig)  | —             |
| SLH-DSA-128f | 1             | 32         | 64         | 17088 (sig) | —             |
| SLH-DSA-192s | 3             | 48         | 96         | 16224 (sig) | —             |
| SLH-DSA-192f | 3             | 48         | 96         | 35664 (sig) | —             |
| SLH-DSA-256s | 5             | 64         | 128        | 29792 (sig) | —             |
| SLH-DSA-256f | 5             | 64         | 128        | 49856 (sig) | —             |

All sizes are in bytes; SLH-DSA size rows apply to both SHAKE and SHA2 variants
of the same level/speed profile. **Reject any input whose length is not exactly
the value in this table before doing crypto on it.** Sensible defaults for a new
project: **ML-KEM-768 + ML-DSA-65** (category 3, the same profile as the
Serverpod guide). Use 512/44 for tight budgets and 1024/87 for maximum margin.
Do not make SLH-DSA a per-request default without explicit latency and payload
budgeting.

## Platform feasibility at a glance

`pqcrypto` is pure Dart and runs everywhere Dart runs — but "runs" is not "runs
well everywhere."

- **Server / Dart VM (AOT):** fastest path. No special handling.
- **Mobile / desktop (Flutter):** offload key generation, signing, and
  encapsulation to an isolate (`compute()` / `Isolate.run`) so the UI stays
  responsive. See building block
  [BB10](BUILDING_BLOCKS.md#bb10-offloading-heavy-work).
- **Web (dart2js / dart2wasm):** it works and the web test gates are green, but
  **Flutter web does not run isolates on a separate thread** — `compute()` does
  not move CPU work off the main thread. Do heavy keygen sparingly, prefer
  `dart2wasm`, or generate long-term keys server-side.
- **Embedded:** this means **embedded Linux / single-board computers** (Dart AOT
  on ARM Linux, Flutter embedded). Bare-metal microcontrollers (Cortex-M class)
  have **no supported Dart toolchain** and are out of scope. On SBCs, *verify*
  and *decapsulate* are much cheaper than *sign* and *keygen* — design around
  that.

## For AI agents and codegen tools

[project-ideas.yaml](project-ideas.yaml) is the machine-readable companion to
this catalog. It encodes each building block and each idea with structured
`algos`, `building_blocks`, `you_supply`, `caveats`, `status`, and
`forbidden_claims` fields, plus a top-level `evidence_boundary`. If you are an
agent generating code from an idea here, you **must** carry that idea's
`you_supply` and `caveats` into the output — an idea is not safe to ship without
them.

## Related package docs

- [../INDEX.md](../INDEX.md) — documentation root.
- [../SERVERPOD_FLUTTER_GUIDE.md](../SERVERPOD_FLUTTER_GUIDE.md) — full handshake.
- [../OPENSSL_INTEROP.md](../OPENSSL_INTEROP.md) — interop evidence and use cases.
- [../UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](../UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md)
  — multi-agent planning framework.
- [../ARCHITECTURE.md](../ARCHITECTURE.md) — what is and is not in the package.

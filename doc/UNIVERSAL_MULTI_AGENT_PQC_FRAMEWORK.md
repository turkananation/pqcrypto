# Universal Multi-Agent PQC Framework

Last updated: 2026-06-05

This document is the canonical project-level setup for using `pqcrypto` with
multi-agent LLM workflows across Codex, Claude Code, and Antigravity. It is a
framework contract, not a production Serverpod/Flutter implementation.

The machine-readable companion is
[`tool/agent_framework/pqc_framework.yaml`](../tool/agent_framework/pqc_framework.yaml).
Native project wrappers live under:

- [`.codex/skills/universal-pqc-framework/SKILL.md`](../.codex/skills/universal-pqc-framework/SKILL.md)
- [`.claude/skills/universal-pqc-framework/SKILL.md`](../.claude/skills/universal-pqc-framework/SKILL.md)
- [`.gemini/antigravity/skills/universal-pqc-framework/SKILL.md`](../.gemini/antigravity/skills/universal-pqc-framework/SKILL.md)

All wrappers point back here. Do not fork the truth per tool.

## Evidence Boundary

Use this framework only inside the current package boundary:

| Area            | Contract                                                                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------- |
| Package         | `pqcrypto` 0.3.1, pure Dart, zero runtime dependencies.                                                    |
| ML-KEM          | ML-KEM-512/768/1024; checked-in KATs and OpenSSL interop evidence.                                         |
| ML-DSA          | ML-DSA-44/65/87; byte-exact checked-in KAT corpus across raw/pure/hashed and deterministic/hedged signing. |
| Certification   | No CMVP/FIPS 140 module validation claim.                                                                  |
| Memory/security | Dart side-channel resistance and zeroization are best-effort, not hard proofs.                             |

Allowed wording:

- "FIPS 203-aligned ML-KEM implementation with checked-in KAT evidence."
- "OpenSSL interop A-G passes for ML-KEM-512/768/1024."
- "FIPS 204-aligned ML-DSA implementation byte-exact on the checked-in KAT corpus."
- "Best-effort zeroization in Dart."

Forbidden wording:

- "FIPS validated", "CMVP validated", "certified", or equivalent certification
  language without an external validation record.
- "Constant-time Dart implementation" as a hard guarantee.
- "Memory is securely erased" as a hard guarantee.

## Agent Coordinate System

The framework uses four roles. They run in this order:

1. **Cryptographic Architect** defines primitives, byte contracts, transcript
   binding, HKDF inputs, and claim limits.
2. **SecOps & Infrastructure Engineer** defines KMS/HSM loading, rotation,
   break-glass eviction, and telemetry contracts.
3. **Distinguished Engineer** defines Serverpod models/endpoints/middleware,
   atomic key-bundle handling, replay defenses, cache purge semantics, and
   failure behavior.
4. **Client Integration Engineer** defines Flutter client flow, isolate
   offloading, secure local session handling, and re-handshake behavior.

Each role must consume the same evidence ledger and manifest. A later role may
not upgrade a claim from an earlier role.

## Primitive Profile

The default enterprise profile is hybrid. Do not design standalone PQC
handshakes.

| Primitive          | Required set                                                       | Integration size                 |
| ------------------ | ------------------------------------------------------------------ | -------------------------------- |
| Classical KEX      | X25519 or an approved equivalent supplied by the application stack | 32-byte shared secret            |
| Lattice KEM        | ML-KEM-768                                                         | pk=1184, ct=1088, sk=2400, ss=32 |
| Identity signature | ML-DSA-65                                                          | pk=1952, sk=4032, sig=3309       |
| Session key        | HKDF output                                                        | 32 bytes                         |

The session secret derivation contract is:

```text
ikm = ss_classical || ss_lattice
salt = deployment_salt || transcript_hash
info = "pqcrypto universal-pqc-framework v1" || role_context
k_session = HKDF-Extract-and-Expand(salt, ikm, info, 32)
```

Requirements:

- `ss_classical` and `ss_lattice` must both be present.
- The transcript hash must bind the server key id, server public keys, client
  ephemeral public material, ML-KEM ciphertext, nonce, timestamp, protocol
  version, and selected algorithms.
- HKDF implementation/provider selection is outside `pqcrypto`; fetch current
  docs for the chosen crypto/TLS/KMS library before implementation.
- Public keys must be authenticated. ML-KEM alone is not authenticated transport.

## Serverpod Contract Sketch

This repository is not a Serverpod app. The following is the contract future
Serverpod projects should implement and test.

`.spy.yaml` model sketches:

```yaml
class: PqcPublicKeyBundle
fields:
  keyId: String
  epoch: int
  mlKem768PublicKey: ByteData
  mlDsa65PublicKey: ByteData
  notBefore: DateTime
  expiresAt: DateTime
  signature: ByteData

class: PqcHandshakeRequest
fields:
  keyId: String
  clientNonce: ByteData
  clientTimestampMs: int
  clientX25519PublicKey: ByteData
  mlKem768Ciphertext: ByteData
  clientMlDsa65PublicKey: ByteData
  clientSignature: ByteData
  transcriptHash: ByteData

class: PqcHandshakeResponse
fields:
  accepted: bool
  sessionId: String?
  serverNonce: ByteData?
  expiresAt: DateTime?
  errorCode: String?
```

Endpoint and middleware rules:

- Endpoint methods extend `Endpoint` and accept `Session` first.
- Middleware is registered before `pod.start`.
- Reject malformed lengths before any decapsulation, verification, or cache
  mutation.
- Treat these lengths as hard filters:
  - ML-KEM-768 public key: 1184 bytes.
  - ML-KEM-768 ciphertext: 1088 bytes.
  - ML-DSA-65 public key: 1952 bytes.
  - ML-DSA-65 signature: 3309 bytes.
  - Nonce: 32 bytes.
  - Transcript hash: 32 bytes or the active hash output length.
- Reject client timestamps outside a 2000 ms acceptance window unless a project
  threat model justifies a different value.
- Reject nonce replay using a bounded sliding-window store.

## Key Lifecycle Contract

Long-term ML-KEM and ML-DSA secret keys must not be stored in plaintext on disk,
in environment variables, or in logs.

Interface requirements:

- Boot loads active key material from KMS/HSM into an immutable key bundle.
- AppRole or equivalent boot tokens are short lived, one use, and valid for no
  more than five minutes.
- Scheduled rotation target: 14 days.
- Metadata polling cadence: at most 12 hours unless the deployment chooses a
  stricter policy.
- Hard validation ceiling: 15 days. Past the ceiling, fail secure instead of
  running indefinitely on unvalidated key material.
- Emergency break-glass evicts key bundles, session mappings, replay windows,
  and local caches.

Provider-specific Vault, CloudHSM, or KMS configuration is deliberately not
hardcoded here. Fetch current provider documentation before implementation.

## Distinguished Engineering Rules

Server implementations must provide:

- immutable key bundle objects;
- copy-on-write construction of a complete replacement bundle before pointer
  swap;
- no endpoint access to partially initialized key state;
- best-effort zeroization of old `Uint8List` buffers before releasing
  references;
- strict length filtering before deserialization-to-crypto;
- replay defense before expensive cryptographic operations;
- circuit breakers and exponential backoff for KMS outages;
- fail-secure lockdown past the key validation ceiling; and
- atomic local cache purge plus gateway/session restart when distributed cache
  eviction cannot be confirmed.

Every method that touches secrets must have a `try`/`finally` plan for
best-effort cleanup and a logging plan that excludes secret bytes.

## Flutter Client Contract

Client implementations must:

- run ML-KEM encapsulation and ML-DSA signing off the UI isolate;
- authenticate the server public key bundle before using it;
- bind nonce, timestamp, algorithm ids, key id, and payload bytes into the
  signature/transcript hash;
- store only derived session state through secure local storage appropriate to
  the target platform;
- clear local session state and re-handshake when the server evicts a key or
  session; and
- convert `Uint8List` payloads into the active Serverpod-compatible binary field
  representation before transport.

## Native Tool Usage

The native wrappers are thin launch points:

- Codex: `.codex/skills/universal-pqc-framework/SKILL.md`
- Claude Code: `.claude/skills/universal-pqc-framework/SKILL.md`
- Antigravity: `.gemini/antigravity/skills/universal-pqc-framework/SKILL.md`

When any wrapper is invoked:

1. Read this document.
2. Read the manifest.
3. Identify which of the four roles is requested.
4. Emit role-specific output with explicit inputs, outputs, claim limits, and
   validation gates.
5. If implementation code is requested, fetch current docs for the relevant
   framework/library first and keep claims scoped to the evidence boundary.

## Implementation Milestones

1. **Tested vertical slice:** build a minimal Serverpod/Flutter project that
   exercises generated models, endpoint signature, middleware registration,
   authenticated server-key handling, strict byte filters, nonce/timestamp
   rejection, and re-handshake behavior.
2. **KMS/HSM integration:** add provider-specific lifecycle loading and
   rotation after fetching current provider documentation.
3. **Distributed eviction:** test cache purge semantics across local and
   distributed session stores.
4. **Agent output validation:** run Codex, Claude, and Antigravity wrappers
   against the same manifest and diff their generated plans for claim drift.

Wrappers and docs are not a substitute for Milestone 1.

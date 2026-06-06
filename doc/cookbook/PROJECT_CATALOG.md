# pqcrypto Project Catalog

Last updated: 2026-06-06

A broad catalog of things you can build with `pqcrypto` 0.3.1 today, grouped by
domain. Each idea is composed from the recipes in
[BUILDING_BLOCKS.md](BUILDING_BLOCKS.md) (referenced as **BB1**…**BB10**) and is
scoped to the package's real API and
[evidence boundary](README.md#the-claim-boundary-please-honor-it).

Ideas that need primitives or releases that do not exist yet are in
[FUTURE_RELEASES.md](FUTURE_RELEASES.md), not here.

## How to read an idea

Every entry has the same shape:

- **Pitch** — one line on what it is.
- **Platforms** — where it realistically runs.
- **Uses** — the parameter sets and building blocks it composes.
- **You supply** — what you must bring (because `pqcrypto` does not provide it).
- **Feasibility** — performance/effort reality.
- **Caveats** — the honest limits; an entry marked **Honesty flag** has a sharp
  failure mode you must not ignore.

Default profile when an idea does not say otherwise: **ML-KEM-768 + ML-DSA-65**.

---

## 1. Servers and backends

Dart server frameworks (Serverpod, Dart Frog, Shelf, Relic), gRPC services, and
long-running daemons. The Dart VM (AOT) is the fastest target, so the server is
the natural home for the heaviest operations.

### Hybrid PQC session handshake service

- **Pitch.** Add a post-quantum + classical authenticated key exchange in front
  of your API so session keys survive "harvest now, decrypt later."
- **Platforms.** Any Dart server; client on Flutter/web/CLI.
- **Uses.** ML-KEM-768 + ML-DSA-65; **BB3**, **BB4**.
- **You supply.** X25519, HKDF, AEAD for traffic, replay window, session store.
- **Feasibility.** Fully worked out, including Serverpod models and a Flutter
  client, in [../SERVERPOD_FLUTTER_GUIDE.md](../SERVERPOD_FLUTTER_GUIDE.md).
- **Caveats.** Authenticate the server key bundle before encapsulation; use AEAD
  for traffic; never use the raw shared secret as a traffic key.

### Stateless signed API / capability tokens

- **Pitch.** A PQC alternative to signed JWT/PASETO: short, signed tokens your
  services verify without a database round-trip.
- **Platforms.** Any Dart server; verifiers anywhere.
- **Uses.** ML-DSA-44 or 65; **BB1**.
- **You supply.** Token encoding, claim schema, clock/expiry handling, key
  rotation, a revocation/short-TTL strategy.
- **Feasibility.** Verify is fast and frequent; favor ML-DSA-44 if token size or
  verify throughput dominates. Note signatures are large (2420–3309 bytes) vs.
  classical tokens — size, not security, is the trade-off.
- **Caveats.** Put a versioned purpose in the context string (**BB1**); expire
  tokens; signatures are not encryption — do not put secrets in a token body.

### Signed webhook delivery and verification

- **Pitch.** Sign outbound webhooks so consumers can prove the payload really
  came from you and was not tampered with in transit or at a proxy.
- **Platforms.** Any Dart server; consumers in any language (see interop).
- **Uses.** ML-DSA-65; **BB1**.
- **You supply.** Canonical payload serialization, a published verification key,
  timestamp/nonce anti-replay.
- **Feasibility.** Straightforward; `hashSign` for large payloads.
- **Caveats.** Publish and pin the verification key out of band; sign a
  timestamp to bound replay.

### Software update / release distribution server

- **Pitch.** Sign releases, packages, or container manifests; clients verify
  before installing.
- **Platforms.** Dart server; clients incl. embedded Linux and CLI.
- **Uses.** ML-DSA-65/87; **BB7**.
- **You supply.** Vendor key custody (HSM), version/rollback metadata, delivery.
- **Feasibility.** Verify is cheap even on modest devices.
- **Caveats.** Sign the version and target id with the artifact to stop rollback
  replay; protect the signing key.

### Tamper-evident audit / transparency log

- **Pitch.** A signed, hash-chained event log that makes silent edits detectable
  — for compliance, security audit trails, or a public transparency log.
- **Platforms.** Dart server + durable storage.
- **Uses.** ML-DSA-44/65; **BB6**.
- **You supply.** A public hash, durable append-only storage, optional Merkle
  proofs and an external anchor.
- **Feasibility.** Signing per event is cheap with ML-DSA-44.
- **Caveats.** Tamper-evident, not tamper-proof; signer-key compromise rewrites
  history from that point. **Honesty flag:** logging people's activity is a
  surveillance capability — see [dual use](#a-note-on-dual-use-and-power).

### Sealed-secrets / config distribution service

- **Pitch.** Let a service (or CI) encrypt secrets *to* a vault key it cannot
  itself read; only an offline/KMS holder can decrypt.
- **Platforms.** Dart server; CI runners.
- **Uses.** ML-KEM-1024; **BB2**, **BB8**.
- **You supply.** HKDF, AEAD, vault secret-key custody (KMS/HSM).
- **Feasibility.** Encapsulation is fast; key custody is the real work.
- **Caveats.** KEM gives confidentiality, not authenticity — sign the sealed
  blob (**BB1**) if you must know who wrote it.

### Mutual application authentication (mTLS-style, in-app)

- **Pitch.** Both client and server prove identity with ML-DSA and agree a hybrid
  key, layered over an existing transport, when full mTLS is impractical.
- **Platforms.** Dart server + any client.
- **Uses.** ML-KEM-768 + ML-DSA-65; **BB3**, **BB4**.
- **You supply.** Enrollment/PKI, X25519, HKDF, AEAD.
- **Feasibility.** Reuses the handshake block.
- **Caveats.** This is application-layer auth, not a TLS replacement; do not
  describe it as TLS.

### License / entitlement server

- **Pitch.** Issue offline-verifiable signed licenses or feature entitlements.
- **Platforms.** Dart server; client verifies offline.
- **Uses.** ML-DSA-65; **BB1**, **BB5**.
- **You supply.** License schema, expiry, device binding, anti-rollback.
- **Feasibility.** Easy; offline verify is the point.
- **Caveats.** Signatures stop forgery, not copying; pair with device binding.

### Public-key directory / PKI microservice

- **Pitch.** Enroll, publish, rotate, and revoke user/device public keys with an
  authority-signed binding.
- **Platforms.** Dart server + storage.
- **Uses.** ML-DSA-65; **BB4**.
- **You supply.** Vetting, storage, revocation, authority-key custody.
- **Feasibility.** The directory is mostly app logic; crypto is a small part.
- **Caveats.** The authority key is your whole root of trust — guard it hardest.

---

## 2. Mobile (Flutter, iOS and Android)

Offload keygen/sign/encapsulate to an isolate (**BB10**) so the UI stays smooth.

### End-to-end encrypted messaging

- **Pitch.** Messages encrypted to the recipient's public key, with signed
  sender identity, so the server only sees ciphertext.
- **Platforms.** Flutter mobile (and desktop).
- **Uses.** ML-KEM-768 (encrypt) + ML-DSA-65 (identity); **BB2**, **BB4**, **BB10**.
- **You supply.** HKDF, AEAD, key directory/safety numbers, and — for forward
  secrecy — a ratchet/rekey scheme (not provided).
- **Feasibility.** Per-message encapsulation is fine on phones in an isolate.
- **Caveats.** **Honesty flag:** this is *not* Signal. Without a forward-secrecy
  ratchet, a stolen secret key decrypts past messages; design rekeying
  explicitly.

### Personal secure vault / password manager

- **Pitch.** Notes, credentials, and files encrypted to a device/vault key.
- **Platforms.** Flutter mobile and desktop.
- **Uses.** ML-KEM-1024; **BB8**, **BB10**.
- **You supply.** HKDF, AEAD, platform keystore for the secret key, a master
  unlock (passphrase/biometric).
- **Feasibility.** Excellent fit; encrypt/decrypt are quick.
- **Caveats.** Best-effort zeroization is not a hard memory-erasure guarantee.

### Client-side encrypted cloud backup

- **Pitch.** Encrypt on-device before upload so the backend stores only opaque
  blobs.
- **Platforms.** Flutter mobile/desktop.
- **Uses.** ML-KEM-1024; **BB8**.
- **You supply.** HKDF, AEAD, recovery-key handling (**BB5** for seed backup).
- **Feasibility.** Strong; "harvest now, decrypt later" is the reason to use PQC
  here.
- **Caveats.** Lose the secret/seed, lose the data — design recovery carefully.

### Offline-first signed field records

- **Pitch.** Collect data offline (inspections, surveys, civic/field reports),
  sign each record on-device, sync later; the server verifies provenance.
- **Platforms.** Flutter mobile.
- **Uses.** ML-DSA-65; **BB1**, **BB4**, **BB6**.
- **You supply.** Local store, sync, enrollment, canonical record encoding.
- **Feasibility.** Signing per record is cheap.
- **Caveats.** A signature proves the key signed it, not that the contents are
  *true*; enroll the signer (**BB4**).

### Mobile document / contract signing

- **Pitch.** Sign PDFs or agreements with an on-device identity key.
- **Platforms.** Flutter mobile/desktop.
- **Uses.** ML-DSA-65; **BB1** (`hashSign`), **BB4**.
- **You supply.** Document canonicalization, a signature container format, an
  identity-trust story.
- **Feasibility.** `hashSign` handles large documents.
- **Caveats.** Legal e-signature validity is a regulatory question, not a crypto
  one — `pqcrypto` is not a certified signing product.

### Contact-key verification (safety numbers)

- **Pitch.** Let two users compare a short fingerprint to confirm they hold each
  other's real public keys.
- **Platforms.** Flutter mobile.
- **Uses.** ML-DSA/ML-KEM public keys; **BB4**.
- **You supply.** A fingerprint encoding, a hash, QR/scan UI.
- **Feasibility.** Pure UX over public-key bytes.
- **Caveats.** Out-of-band verification is what defeats MITM; do not skip it.

### Secure peer-to-peer file transfer

- **Pitch.** Send a file directly to a nearby device, encrypted to its public key
  (bootstrapped by QR/NFC/local network).
- **Platforms.** Flutter mobile/desktop.
- **Uses.** ML-KEM-768; **BB2**, **BB10**.
- **You supply.** Transport, key exchange bootstrap, HKDF, AEAD.
- **Feasibility.** Good; chunk large files under the AEAD.
- **Caveats.** Authenticate the peer key (QR/NFC) or you may encrypt to an
  impostor.

### Encrypted push-notification payloads

- **Pitch.** Encrypt sensitive notification content to the device key so the push
  provider sees nothing useful.
- **Platforms.** Flutter mobile.
- **Uses.** ML-KEM-768; **BB2**.
- **You supply.** HKDF, AEAD, payload-size budget handling.
- **Feasibility.** Workable within push size limits for small payloads.
- **Caveats.** Push metadata (timing, device) is still visible; crypto does not
  hide it.

---

## 3. Desktop and CLI (Flutter desktop, Dart command-line)

### File / folder encryption tool

- **Pitch.** An `age`-style CLI: encrypt files to a recipient's public key.
- **Platforms.** Dart CLI (Linux/macOS/Windows), Flutter desktop.
- **Uses.** ML-KEM-768/1024; **BB2**, **BB8**.
- **You supply.** HKDF, AEAD, a file container format, key management.
- **Feasibility.** Excellent on the VM.
- **Caveats.** Stream large files through the AEAD; do not load multi-GB into RAM.

### Artifact / code signing CLI

- **Pitch.** Sign build outputs, release tarballs, or SBOMs; verify in CI.
- **Platforms.** Dart CLI; CI runners.
- **Uses.** ML-DSA-65/87; **BB1**, **BB7**.
- **You supply.** Signature container, key custody, CI verify step.
- **Feasibility.** Drop-in for release pipelines.
- **Caveats.** Protect the signing key; sign versioned metadata.

### Git commit / tag signer

- **Pitch.** Attach PQC signatures to commits/tags and verify them in CI for a
  post-quantum provenance trail.
- **Platforms.** Dart CLI.
- **Uses.** ML-DSA-65; **BB1**.
- **You supply.** Git plumbing integration, key distribution.
- **Feasibility.** Practical as an out-of-band signature store.
- **Caveats.** Git's native signing expects specific formats; you are building a
  side-channel of trust, document it.

### Secrets distribution / sealed config tool

- **Pitch.** `kubeseal`-style: developers encrypt secrets to a cluster vault key.
- **Platforms.** Dart CLI.
- **Uses.** ML-KEM-1024; **BB2**, **BB8**.
- **You supply.** HKDF, AEAD, vault key custody.
- **Feasibility.** Strong.
- **Caveats.** Authenticity needs a signature (**BB1**).

### PQC keyring / keychain manager

- **Pitch.** Generate, store, rotate, and export ML-KEM/ML-DSA keys with a clean
  CLI/UX.
- **Platforms.** Dart CLI, Flutter desktop.
- **Uses.** all sets; **BB4**, **BB5**.
- **You supply.** OS keystore integration, export formats, backup.
- **Feasibility.** Mostly app logic around the keygen API.
- **Caveats.** The seed equals the key (**BB5**) — protect backups.

---

## 4. Embedded and IoT

**Scope, stated honestly.** "Embedded" here means **embedded Linux and
single-board computers** — Dart AOT on ARM Linux, Flutter embedded. Bare-metal
microcontrollers (Cortex-M class) have **no supported Dart toolchain** and are
out of scope for this pure-Dart package. On SBCs, *verify* and *decapsulate* are
much cheaper than *sign* and *keygen*; design with that asymmetry. **Benchmark on
your target hardware before committing.**

### On-device update signature verification

- **Pitch.** Devices verify a vendor-signed firmware/app image before applying.
- **Platforms.** Embedded Linux / SBC.
- **Uses.** ML-DSA-65; **BB7**.
- **You supply.** Pinned vendor key in the image, rollback protection.
- **Feasibility.** Verify is light — a good first PQC step for a fleet.
- **Caveats.** Sign version + model id; guard the vendor key.

### Device identity and fleet enrollment

- **Pitch.** Each device holds an ML-DSA identity and proves it by signing
  server challenges.
- **Platforms.** Embedded Linux / SBC; gateway/server backend.
- **Uses.** ML-DSA-65; **BB4**, **BB1**.
- **You supply.** Provisioning, enrollment authority, secure key storage on the
  device (TPM/secure element if available).
- **Feasibility.** Sign-on-challenge is occasional; affordable.
- **Caveats.** Key storage on the device is the weak point — without secure
  hardware the identity can be cloned.

### Signed sensor telemetry / data integrity

- **Pitch.** Sign sensor readings at the edge so the backend can verify they were
  not altered in transit or storage.
- **Platforms.** Edge SBC + backend.
- **Uses.** ML-DSA-44 (light) ; **BB1**, **BB6**.
- **You supply.** Batching (sign batches, not every reading), time source.
- **Feasibility.** Batch to amortize signing cost; ML-DSA-44 keeps it light.
- **Caveats.** Integrity is not confidentiality — add **BB2** if the data is
  sensitive. **Honesty flag:** signed behavioral/biometric telemetry is a
  surveillance and coercion substrate; see [dual use](#a-note-on-dual-use-and-power).

### Edge-to-cloud payload encryption (MQTT/CoAP)

- **Pitch.** Encrypt message payloads to a cloud key over lightweight IoT
  transports.
- **Platforms.** Edge SBC + broker/cloud.
- **Uses.** ML-KEM-512/768; **BB2**, **BB3**.
- **You supply.** HKDF, AEAD, the transport binding, session caching.
- **Feasibility.** Cache the KEM result and rekey periodically rather than per
  message; ciphertext (768–1088 B) is large for tiny MTUs.
- **Caveats.** Mind payload sizes on constrained links.

### Supply-chain provenance / device birth certificates

- **Pitch.** Sign a device's manufacturing record so its origin can be verified
  later.
- **Platforms.** Factory tooling + field verify.
- **Uses.** ML-DSA-65; **BB1**, **BB4**.
- **You supply.** Manufacturing data schema, authority key custody.
- **Feasibility.** Sign once at birth; verify anywhere.
- **Caveats.** Provenance proves origin claims, not that hardware is untampered.

---

## 5. Web (Flutter web, Dart web, PWAs)

**Scope, stated honestly.** `pqcrypto` runs on `dart2js` and `dart2wasm` and the
web test gates are green — but **Flutter web does not run isolates on a separate
thread**, so heavy keygen blocks the main thread (**BB10**). Prefer `dart2wasm`,
keep heavy operations rare, or move long-term keygen server-side. Encapsulation,
signing, and verification of small inputs are usually fine.

### Browser-based end-to-end encryption

- **Pitch.** Encrypt notes/messages/files in the browser before they reach your
  server.
- **Platforms.** Flutter web / Dart web (PWA).
- **Uses.** ML-KEM-768; **BB2**.
- **You supply.** HKDF, AEAD (WebCrypto via interop, or a Dart AEAD), key
  storage (IndexedDB + care).
- **Feasibility.** Per-message work is fine; avoid frequent keygen on the UI
  thread.
- **Caveats.** Browser key storage is exposed to XSS — your app's web security is
  the real boundary.

### Client-side document signing in the browser

- **Pitch.** Sign documents in-page with a key the server never sees.
- **Platforms.** Flutter web / Dart web.
- **Uses.** ML-DSA-65; **BB1** (`hashSign`).
- **You supply.** Key storage, document canonicalization.
- **Feasibility.** Signing a hash is quick.
- **Caveats.** Same XSS/key-storage caveat as above.

### PQC interop demo against an OpenSSL/WebCrypto backend

- **Pitch.** A live demo proving a Dart web client and an OpenSSL-based server
  derive the same ML-KEM shared secret.
- **Platforms.** Web client + any OpenSSL server.
- **Uses.** ML-KEM-512/768/1024; **BB2**; see
  [../OPENSSL_INTEROP.md](../OPENSSL_INTEROP.md).
- **You supply.** The server, HKDF, AEAD.
- **Feasibility.** Encodings are byte-identical, so no conversion is needed.
- **Caveats.** A demo is not a hardened deployment.

---

## 6. Cross-language interop and polyglot systems

Backed by the verified OpenSSL interop suite (A–G, all three ML-KEM levels) in
[../OPENSSL_INTEROP.md](../OPENSSL_INTEROP.md). This is *correctness/wire*
evidence — public keys, ciphertexts, and 64-byte seeds are byte-identical across
implementations.

### Dart client ↔ OpenSSL/C server key exchange

- **Pitch.** A Dart/Flutter app encapsulates to a key generated by an
  OpenSSL/C/Python/Node/Go backend, and both derive the identical secret.
- **Platforms.** Any Dart client + any OpenSSL-backed server.
- **Uses.** ML-KEM-512/768/1024; **BB2**, **BB3**.
- **You supply.** The non-Dart side, HKDF, AEAD.
- **Feasibility.** Proven by Tests C/D in the interop doc.
- **Caveats.** Only public keys/ciphertexts/seeds cross the wire — never expanded
  private keys.

### Hybrid TLS-adjacent ML-KEM component

- **Pitch.** Provide the ML-KEM half of an `X25519MLKEM768`-style hybrid in a
  Dart service interoperating with OpenSSL peers.
- **Platforms.** Dart server.
- **Uses.** ML-KEM-768; **BB3**.
- **You supply.** X25519, the TLS/transport stack, HKDF.
- **Feasibility.** The ML-KEM encodings and secret match OpenSSL.
- **Caveats.** **Honesty flag:** this is a *component*, not a TLS stack; do not
  claim "PQC TLS."

### Migration / dual-stack validation harness

- **Pitch.** Prove byte-level equivalence between `pqcrypto` and your existing
  OpenSSL stack before cutover.
- **Platforms.** CI / tooling.
- **Uses.** seed-based keygen; **BB5**; interop suite.
- **You supply.** The comparison harness around both stacks.
- **Feasibility.** The deterministic seed path makes this exact.
- **Caveats.** Validates functional equivalence, not side-channel parity.

### Cross-implementation regression guard

- **Pitch.** Run the interop suite in CI so a change that breaks wire
  compatibility is caught immediately.
- **Platforms.** CI.
- **Uses.** interop harness in `tool/openssl_interop/`.
- **You supply.** CI wiring (an example workflow already exists in the repo).
- **Feasibility.** Already implemented; reuse it.
- **Caveats.** Needs OpenSSL ≥ 3.5.

---

## 7. Vertical industries

These reuse the same blocks; the domain adds requirements `pqcrypto` does not
address (regulatory validation, privacy law, audit, coercion-resistance).

### Fintech: signed transactions and authorization

- **Pitch.** Sign payment instructions/settlement records; PQC-protect key
  exchange for partner APIs.
- **Uses.** ML-DSA-65/87 + ML-KEM-768; **BB1**, **BB3**, **BB6**.
- **You supply.** Ledger, idempotency, regulatory controls, HSM custody.
- **Caveats.** No CMVP/FIPS 140 validation here — financial compliance regimes
  often require validated modules; this package does not satisfy that.

### Healthcare: encrypted records and signed events

- **Pitch.** Encrypt records at rest to a vault key; sign clinical events and
  consent receipts.
- **Uses.** ML-KEM-1024 + ML-DSA-65; **BB8**, **BB1**, **BB6**.
- **You supply.** Access control, audit, HKDF, AEAD, legal compliance
  (HIPAA/GDPR are your responsibility).
- **Caveats.** Crypto is one control among many; de-identification and access
  policy matter more for most threats.

### Legal and notarization

- **Pitch.** E-signatures, signed timestamps, and notarized document hashes.
- **Uses.** ML-DSA-65; **BB1**, **BB6**.
- **You supply.** Trusted timestamp source, identity vetting, archival format.
- **Caveats.** Legal validity is a jurisdiction question, not a crypto guarantee.

### Govtech and civic technology

- **Pitch.** Sign official records and citizen-facing receipts; encrypt
  submissions; keep verifiable audit trails for civic data.
- **Uses.** ML-DSA-65 + ML-KEM-768; **BB1**, **BB2**, **BB6**, **BB4**.
- **You supply.** Identity, storage, transparency, governance.
- **Caveats.** **Honesty flag — e-voting.** A signature scheme does **not** make
  an election system. Coercion-resistance, ballot secrecy, end-to-end
  verifiability, and dispute resolution are unsolved by ML-DSA/ML-KEM. Do not
  build or market a voting system on these primitives alone; treat "verifiable
  receipt" claims with extreme suspicion. See
  [dual use](#a-note-on-dual-use-and-power).

### Supply chain and product authenticity

- **Pitch.** Sign SBOMs, bills of materials, and product authenticity tags.
- **Uses.** ML-DSA-65; **BB1**, **BB7**, **BB4**.
- **You supply.** Item identity, scanning UX, registry.
- **Caveats.** Signatures bind data to a key, not goods to reality — pair with
  physical anti-tamper.

### Identity and verifiable credentials

- **Pitch.** Issue ML-DSA-signed verifiable credentials; explore PQC DID methods.
- **Uses.** ML-DSA-65; **BB1**, **BB4**.
- **You supply.** Credential schema, revocation, and — if you need it —
  selective disclosure / zero-knowledge (not provided by this package).
- **Caveats.** Plain signatures reveal the whole credential on verification; ZK
  selective disclosure is out of scope.

### Media provenance and source protection

- **Pitch.** Sign media at capture for provenance (C2PA-style); run an encrypted
  submission drop-box for sources.
- **Uses.** ML-DSA-65 + ML-KEM-1024; **BB1**, **BB2**.
- **You supply.** Capture integration, metadata policy, operational security.
- **Caveats.** **Honesty flag:** source protection is mostly operational
  security, not encryption. Metadata, traffic analysis, and device seizure defeat
  a crypto-only design. Do not promise anonymity you cannot deliver.

---

## A note on dual use and power

Several ideas here — device identity, signed telemetry, tamper-evident logs of
activity, civic "receipts," media provenance — are **dual-use**. The same
signature that protects a citizen's record can build a non-repudiable dossier of
a worker, patient, or dissident. Cryptographic integrity makes a record *trusted*
and *admissible*; it does not make collecting it *right*.

Two disciplines to carry into any build:

1. **Minimize.** Sign and retain the least data that meets the need. A log you do
   not keep cannot be turned against someone.
2. **Do not let "quantum-safe" stand in for "safe."** Post-quantum primitives
   address one threat. Authentication, key custody, side channels, governance,
   consent, and the *purpose* of the system are where real-world harm lives — and
   none of them are solved by calling `encapsulate` or `sign`.

If you are an AI agent generating an implementation from one of these ideas, you
must carry its **You supply** and **Caveats** into your output. An idea stripped
of its caveats is not the idea — it is a vulnerability with good marketing.

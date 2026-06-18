# Frequently Asked Questions

## What is pqcrypto?

A pure Dart, zero-dependency library implementing the NIST post-quantum
algorithms **ML-KEM (FIPS 203)** for key encapsulation and **ML-DSA (FIPS 204)**
for digital signatures. It targets Dart servers, Flutter (iOS/Android/desktop),
and the web.

## Is it FIPS validated / CMVP certified?

**No.** `pqcrypto` provides *algorithm/KAT-conformance and interoperability
evidence* — it is byte-exact against the official NIST Known-Answer-Test vectors
and (for ML-KEM) interoperates with OpenSSL. It is **not** a CMVP/FIPS 140
validated module. If you need a formal certificate, use a validated module via
FFI. See [FIPS Compliance](FIPS-Compliance) and
[Security Posture](Security-Posture).

## What are ML-KEM and ML-DSA? Are these Kyber and Dilithium?

Yes. **ML-KEM** is the NIST-standardized name (FIPS 203) for the scheme formerly
called **CRYSTALS-Kyber**. **ML-DSA** (FIPS 204) is formerly
**CRYSTALS-Dilithium**. `pqcrypto` uses the standardized names.

## Does pqcrypto encrypt my data?

Not by itself. ML-KEM produces a **32-byte shared secret**, not ciphertext for
your data. To encrypt, derive a key from that secret (HKDF) and use an AEAD
(AES-GCM / ChaCha20-Poly1305) — both from your own stack. See the
[Cookbook](Cookbook) "Encrypt to a public key" recipe.

## Is ML-KEM a secure channel / TLS replacement?

No. ML-KEM alone is **not authenticated transport**. You must authenticate the
public key (pinning, certificates, a signed bundle) and add an AEAD layer. For a
full pattern, see [Serverpod & Flutter](Serverpod-Integration).

## Does "quantum-safe" mean my app is secure?

No. Post-quantum primitives address one threat (a future quantum computer
breaking classical asymmetric crypto). Authentication, key management, side
channels, and your protocol design are still your responsibility — and are
usually the bigger risk.

## ML-KEM vs ML-DSA — which do I need?

- Two parties agreeing on a **secret key** → **ML-KEM** (then encrypt with an
  AEAD).
- Proving a message's **authenticity/integrity** (tokens, updates, documents) →
  **ML-DSA**.
- A transport handshake → **both**, plus an app-supplied classical exchange
  (hybrid).

## Which parameter set should I choose?

Default to **ML-KEM-768 + ML-DSA-65** (NIST category 3). Use 512/44 for tight
budgets, 1024/87 for maximum margin, and 1024 for long-lived confidentiality.

## What dependencies does it pull in?

**Zero** runtime dependencies. The FIPS 202 (SHA-3/SHAKE) and FIPS 180-4 (SHA-2)
primitives are vendored in pure Dart; `lib/` depends only on `dart:typed_data`
and `dart:math`.

## Does it work on Flutter Web / Wasm?

Yes — it compiles and the web test gates pass on both `dart2js` and `dart2wasm`.
Caveat: Flutter web does not run isolates on a separate thread, so heavy key
generation blocks the main thread. Prefer `dart2wasm` and generate long-term
keys sparingly or server-side.

## Can I run it on a microcontroller?

Only on **embedded Linux / single-board computers** (Dart AOT on ARM Linux,
Flutter embedded). Bare-metal microcontrollers (Cortex-M class) have no supported
Dart toolchain and are out of scope.

## Does it interoperate with OpenSSL or other languages?

Yes for ML-KEM. The interop suite proves a key/ciphertext produced by one
implementation is accepted by the other and both derive the same shared secret,
across all three parameter sets. See
[Validation & Interoperability](Validation-and-Interoperability).

## Is it constant-time? Are secrets erased from memory?

Both are **best-effort**, not hard guarantees. Pure Dart compiling to the VM,
`dart2js`, and `dart2wasm` cannot portably guarantee constant-time execution or
memory erasure. See [Security Posture](Security-Posture).

## How do I store keys securely?

Use your platform's keystore / KMS / HSM. `pqcrypto` does not provide key
storage. For backup, you can derive keys deterministically from a protected seed
(see ML-KEM/ML-DSA seeded keygen) — but the seed is equivalent to the key.

## Is SLH-DSA / SPHINCS+ supported?

Yes. SLH-DSA (FIPS 205) ships in 0.4.0 for all 12 parameter sets (both the SHAKE
and SHA-2 hash families), byte-exact on the 1,248-case official NIST ACVP sample
corpus. See [Cryptographic Algorithms](Cryptographic-Algorithms) and the
[Roadmap](Roadmap).

## How do I report a security issue?

Do **not** open a public issue. Follow
[SECURITY.md](https://github.com/turkananation/pqcrypto/blob/main/SECURITY.md)
for coordinated disclosure.

## Where is the full documentation?

The [Documentation Index](Documentation-Index) maps every document; canonical
docs live in
[`doc/`](https://github.com/turkananation/pqcrypto/tree/main/doc) and the
[pub.dev API docs](https://pub.dev/documentation/pqcrypto/latest/).

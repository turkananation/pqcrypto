# pqcrypto Building Blocks

Last updated: 2026-06-06

These are the reusable recipes that every project in
[PROJECT_CATALOG.md](PROJECT_CATALOG.md) is composed from. Learn the ten blocks
once; then a "project" is just a named combination of blocks for a domain, with
that domain's caveats.

**How to read the code.** Lines that call `pqcrypto` use the **real, current
API** and are correct as written. Lines marked `// you supply` are illustrative
placeholders for code you bring from your own crypto/storage stack — `pqcrypto`
does not provide them (see the gives-vs-supply table in
[README.md](README.md#what-pqcrypto-gives-you-and-what-you-supply)).
Treat every snippet as a sketch to adapt, not a drop-in library.

All snippets assume:

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';
```

Block index:

- [BB1 Detached signatures](#bb1-detached-signatures)
- [BB2 Encrypt to a public key](#bb2-encrypt-to-a-public-key)
- [BB3 Hybrid authenticated handshake](#bb3-hybrid-authenticated-handshake)
- [BB4 Identity enrollment and key directory](#bb4-identity-enrollment-and-key-directory)
- [BB5 Deterministic keys from a seed](#bb5-deterministic-keys-from-a-seed)
- [BB6 Tamper-evident signed log](#bb6-tamper-evident-signed-log)
- [BB7 Signed software and firmware updates](#bb7-signed-software-and-firmware-updates)
- [BB8 Encrypted data at rest](#bb8-encrypted-data-at-rest)
- [BB9 Hybrid and dual signatures](#bb9-hybrid-and-dual-signatures)
- [BB10 Offloading heavy work](#bb10-offloading-heavy-work)

---

## BB1 Detached signatures

**What it does.** Proves a message came from the holder of a secret key and was
not modified. The output is a *detached* signature you store or send alongside
the message.

**Use it for.** Signed tokens, signed webhooks, document/contract e-signing,
signed records, signed releases — anywhere you need integrity and
non-repudiation.

```dart
final params = DilithiumParams.mlDsa65;

// A domain-separation context. Use a distinct, versioned string PER USE so a
// signature minted for one purpose can never be replayed as another.
final ctx = Uint8List.fromList(utf8.encode('myapp/invoice-signature/v1'));

// Key generation (do this once; persist the keys securely — see BB5/BB8).
final (pk, sk) = MlDsa.generateKeyPair(params); // hedged, uses Random.secure()

// Sign. Signing is hedged by default (recommended). For a small message:
final message = Uint8List.fromList(utf8.encode('canonical invoice bytes'));
final sig = MlDsa.sign(sk, message, params, ctx: ctx);

// Verify. Returns false (never throws) on any malformed/forged input.
final ok = MlDsa.verify(pk, message, sig, params, ctx: ctx);
```

**For large payloads** (files, multi-MB documents) use the pre-hash variant so
you are not buffering the whole message through the lattice signer:

```dart
final sig = MlDsa.hashSign(sk, bigPayload, params, ctx: ctx);
final ok = MlDsa.hashVerify(pk, bigPayload, sig, params, ctx: ctx);
```

**You supply.** A *canonical* byte encoding of the message (both signer and
verifier must serialize it identically — see BB6's framing helper), and a way to
distribute and trust the public key (see BB4).

**Caveats.**

- A signature is only as meaningful as your trust in the public key. A
  self-provided key proves nothing about identity (BB4).
- `signDeterministic` exists but is discouraged: deterministic ML-DSA is harder
  to protect against fault/side-channel attacks. Prefer the hedged default.
- The context string is at most 255 bytes.

---

## BB2 Encrypt to a public key

**What it does.** Lets anyone encrypt data *to* a recipient's public key such
that only the holder of the matching secret key can read it. This is the recipe
people *think* "ML-KEM" means — but ML-KEM only gives you a **shared secret**;
you must combine it with a KDF and an AEAD (the "DEM") to actually encrypt data.
This pattern is KEM-DEM hybrid public-key encryption.

```dart
final kem = PqcKem.kyber768;

// --- Sender: has the recipient's ML-KEM public key ---
(Uint8List ct, Uint8List sealed) encryptTo(
  Uint8List recipientPk,
  Uint8List plaintext,
) {
  final (ct, ss) = kem.encapsulate(recipientPk); // pqcrypto: ct + 32-byte secret

  // Derive a fresh data key from the shared secret. NEVER use `ss` directly as
  // an AEAD key — always run it through a KDF with a domain/label.
  final key = hkdf(ss, salt: ct, info: 'myapp/kem-dem/v1', length: 32); // you supply
  final nonce = randomBytes(12);                                        // you supply
  final box = aeadSeal(key, nonce, plaintext, aad: ct);                // you supply

  return (ct, concatBytes([nonce, box])); // send both ct and sealed payload
}

// --- Recipient: holds the ML-KEM secret key ---
Uint8List decrypt(Uint8List sk, Uint8List ct, Uint8List sealed) {
  final ss = kem.decapsulate(sk, ct); // pqcrypto: recovers the same 32-byte secret
  final key = hkdf(ss, salt: ct, info: 'myapp/kem-dem/v1', length: 32);  // you supply
  final nonce = sealed.sublist(0, 12);
  final box = sealed.sublist(12);
  return aeadOpen(key, nonce, box, aad: ct);                            // you supply
}
```

**You supply.** HKDF (or another KDF), an AEAD (AES-GCM or ChaCha20-Poly1305),
and a CSPRNG for the nonce. All are in standard Dart crypto packages; none are in
`pqcrypto`.

**Caveats.**

- This gives **confidentiality to the key holder**, not sender authentication.
  Anyone can encrypt to a public key. If you need to know *who* sent it, also
  sign the ciphertext with BB1, or use the authenticated handshake (BB3).
- Bind `ct` into the KDF and/or the AEAD's associated data (as above) so the
  ciphertext cannot be transplanted onto a different encapsulation.

---

## BB3 Hybrid authenticated handshake

**What it does.** Establishes a mutually understood session key that is secure if
**either** the classical algorithm (X25519) **or** the lattice algorithm
(ML-KEM) holds — the conservative "hybrid" posture recommended during the PQC
transition — and authenticates the exchange with ML-DSA so it is not a
man-in-the-middle's session.

This is the full pattern documented end-to-end (with Serverpod models, endpoint
guards, replay windows, and a Flutter client) in
[../SERVERPOD_FLUTTER_GUIDE.md](../SERVERPOD_FLUTTER_GUIDE.md). The essence:

```dart
final kem = PqcKem.kyber768;
final dsa = DilithiumParams.mlDsa65;
final ctx = Uint8List.fromList(utf8.encode('myapp/handshake/v1'));

// Client encapsulates to the server's authenticated ML-KEM public key,
// and also runs an app-supplied X25519 exchange.
final (ct, ssLattice) = kem.encapsulate(serverKemPk);   // pqcrypto
final ssClassical = x25519(clientEphSk, serverX25519Pk); // you supply

// Bind everything that matters into one canonical transcript, then sign it.
final transcript = lengthPrefixed([
  utf8Bytes('myapp/handshake/v1'),
  utf8Bytes('ML-KEM-768'), utf8Bytes('ML-DSA-65'),
  serverKemPk, clientEphX25519Pk, ct, clientNonce, uint64(timestampMs),
]); // framing helper is in BB6
final sig = MlDsa.sign(clientIdentitySk, transcript, dsa, ctx: ctx); // pqcrypto

// Both sides derive the same session key from BOTH secrets.
final sessionKey = hkdf(
  concatBytes([ssClassical, ssLattice]),       // ikm = classical || lattice
  salt: hash(transcript), info: 'myapp/session/v1', length: 32,
); // you supply (HKDF + hash)
```

**You supply.** X25519 (or another classical KEX), HKDF, a transcript hash, an
AEAD for traffic after the handshake, plus the server-side replay window,
timestamp checks, and session storage.

**Caveats.**

- The server's public-key bundle **must be authenticated** before encapsulation
  (pinning, a certificate chain, or a signed-metadata channel). ML-KEM to an
  unauthenticated key is an exchange with an attacker.
- A client ML-DSA key is only an *identity* after enrollment/attestation (BB4) —
  on its own it is just a key.
- Never use the raw ML-KEM shared secret as a traffic key; always derive through
  the KDF that also mixes the classical secret.

---

## BB4 Identity enrollment and key directory

**What it does.** Turns "a public key" into "a trusted identity." Devices/users
generate ML-DSA identity keys; a directory publishes them; clients trust them
because an **enrollment authority** vouches for them — not because the key signs
itself.

```dart
final dsa = DilithiumParams.mlDsa65;

// On the device/user: create a long-lived identity key.
final (identityPk, identitySk) = MlDsa.generateKeyPair(dsa);

// Enrollment: the AUTHORITY (a key clients already trust) signs a binding of
// {subject, identityPk, validity} after verifying the subject out of band.
final binding = lengthPrefixed([
  utf8Bytes('myapp/enrollment/v1'),
  utf8Bytes(subjectId), identityPk, uint64(notBeforeMs), uint64(expiresAtMs),
]); // framing helper in BB6
final authoritySig = MlDsa.sign(authoritySk, binding, dsa,
    ctx: utf8Bytes('myapp/enrollment/v1'));

// A client trusts identityPk only if the authority's signature verifies
// against the authority's PINNED public key.
final trusted = MlDsa.verify(authorityPk, binding, authoritySig, dsa,
    ctx: utf8Bytes('myapp/enrollment/v1'));
```

**You supply.** The out-of-band proof that the subject really controls the key
(account login, attestation, in-person check), directory storage, and a
**revocation** mechanism (revocation lists, short expiry + re-enrollment).

**Caveats.**

- The authority key is your root of trust — protect it (KMS/HSM, offline) far
  more carefully than any device key.
- Enrollment is the hard part, not the signing. A signed key with no real
  vetting is theater.
- Revocation is not provided by signatures; design it explicitly.

---

## BB5 Deterministic keys from a seed

**What it does.** Reproducibly derives a keypair from a stored high-entropy seed.
Useful for backup/restore, KMS-held seeds, and cross-implementation interop.

```dart
final kem = PqcKem.kyber768;
final dsa = DilithiumParams.mlDsa65;

// ML-KEM from a 64-byte seed (d || z). With the SAME 64-byte seed, OpenSSL
// derives the byte-identical public key — see OPENSSL_INTEROP.md.
final seed64 = randomBytes(64);              // you supply secure entropy/storage
final (kemPk, kemSk) = kem.generateKeyPair(seed64);

// ML-DSA from a 32-byte seed (xi).
final seed32 = randomBytes(32);              // you supply secure entropy/storage
final (dsaPk, dsaSk) = MlDsa.generateKeyPairSeeded(dsa, seed32);
```

**You supply.** Secure generation, storage, and backup of the seed (a platform
keystore, KMS/HSM, or a user-held recovery phrase).

**Caveats.**

- **The seed is equivalent to the secret key.** Anyone with the seed can
  reproduce the keys. Protect it exactly as you would the secret key.
- Deterministic keygen is for backup/interop, not a substitute for a CSPRNG when
  you just need a fresh key — use `generateKeyPair()` for that.

---

## BB6 Tamper-evident signed log

**What it does.** Builds an append-only log where any modification or reordering
of past entries is detectable: each entry signs over the previous entry's hash,
forming a chain.

```dart
final dsa = DilithiumParams.mlDsa44; // verify/sign small records; 44 is light
final ctx = Uint8List.fromList(utf8.encode('myapp/audit-log/v1'));

Uint8List appendEntry(Uint8List signerSk, Uint8List prevHash, Uint8List payload) {
  final framed = lengthPrefixed([prevHash, payload, uint64(nowMs())]);
  final sig = MlDsa.sign(signerSk, framed, dsa, ctx: ctx); // pqcrypto
  // store {framed, sig}; next entry's prevHash = hash(framed || sig)
  return hash(concatBytes([framed, sig])); // you supply the hash
}
```

The framing helpers used across these blocks (keep ONE copy shared by all
writers and readers):

```dart
Uint8List lengthPrefixed(List<Uint8List> fields) {
  final out = <Uint8List>[];
  for (final f in fields) {
    out.add(uint32(f.length));
    out.add(f);
  }
  return concatBytes(out);
}

Uint8List concatBytes(List<Uint8List> chunks) {
  final total = chunks.fold<int>(0, (s, c) => s + c.length);
  final out = Uint8List(total);
  var off = 0;
  for (final c in chunks) {
    out.setRange(off, off + c.length, c);
    off += c.length;
  }
  return out;
}

Uint8List uint32(int v) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.big);
Uint8List uint64(int v) =>
    Uint8List(8)..buffer.asByteData().setUint64(0, v, Endian.big);
Uint8List utf8Bytes(String s) => Uint8List.fromList(utf8.encode(s));
```

**You supply.** A public hash function (e.g. SHA-256 from your stack), durable
storage, and — for efficient inclusion proofs — a Merkle tree if you need one.

**Caveats.**

- This is tamper-**evident**, not tamper-**proof**. It detects edits; it does not
  prevent them, and it does not provide confidentiality.
- If the signer's key is compromised, the attacker can rewrite history from that
  point. Consider co-signing to an external transparency log or anchor.
- Integrity logging of *people's activity* is a surveillance capability. Log the
  minimum, and read the ethics note in
  [PROJECT_CATALOG.md](PROJECT_CATALOG.md#a-note-on-dual-use-and-power).

---

## BB7 Signed software and firmware updates

**What it does.** A vendor signs an artifact; a device verifies the signature
against an embedded vendor key before installing. Verification is cheap, so this
suits embedded-Linux devices well.

```dart
final dsa = DilithiumParams.mlDsa65;
final ctx = Uint8List.fromList(utf8.encode('myapp/firmware/v1'));

// --- Build server (vendor) ---
Uint8List signRelease(Uint8List vendorSk, Uint8List artifact, int version) {
  final framed = lengthPrefixed([uint64(version), artifact]);
  return MlDsa.hashSign(vendorSk, framed, dsa, ctx: ctx); // pre-hash: large file
}

// --- Device ---
bool acceptUpdate(Uint8List vendorPk, Uint8List artifact, int version, Uint8List sig) {
  if (version <= installedVersion) return false; // you supply: rollback guard
  final framed = lengthPrefixed([uint64(version), artifact]);
  return MlDsa.hashVerify(vendorPk, framed, sig, dsa, ctx: ctx); // pqcrypto
}
```

**You supply.** Secure embedding/pinning of the vendor public key in the device
image, monotonic version/rollback protection, and the delivery channel.

**Caveats.**

- Sign the **version** (and ideally a hardware/model id) alongside the artifact,
  or an attacker can replay an old, validly-signed but vulnerable image.
- Protect the vendor signing key in an HSM; its compromise is catastrophic.
- Consider BB9 (dual signatures) for long-lived devices that must survive a
  single algorithm being broken.

---

## BB8 Encrypted data at rest

**What it does.** BB2 applied to storage: encrypt records/files to a vault public
key whose secret key lives offline or in a KMS/HSM, so the running app can write
secrets it cannot itself read back.

```dart
final kem = PqcKem.kyber1024; // long-term data at rest → highest margin

Uint8List sealRecord(Uint8List vaultPk, Uint8List record) {
  final (ct, ss) = kem.encapsulate(vaultPk);                 // pqcrypto
  final key = hkdf(ss, salt: ct, info: 'myapp/at-rest/v1', length: 32); // you supply
  final nonce = randomBytes(12);                             // you supply
  final box = aeadSeal(key, nonce, record, aad: ct);         // you supply
  return concatBytes([ct, nonce, box]); // store this blob
}
```

**You supply.** HKDF, AEAD, CSPRNG, and — critically — secure custody of the
vault secret key (KMS/HSM, offline media). Optionally per-record keys.

**Caveats.**

- Choose ML-KEM-1024 for data with a long confidentiality lifetime ("harvest
  now, decrypt later" is the whole reason to use PQC at rest).
- Best-effort zeroization in Dart is not a guarantee that plaintext leaves no
  trace in memory; do not rely on it for a hard memory-erasure requirement.

---

## BB9 Hybrid and dual signatures

**What it does.** Signs with two independent schemes so a forgery requires
breaking **both**. During the PQC transition this is the conservative posture for
high-value, long-lived signatures, and it smooths migration.

```dart
final dsa = DilithiumParams.mlDsa65;
final ctx = Uint8List.fromList(utf8.encode('myapp/dual-sign/v1'));

({Uint8List pqc, Uint8List classical}) dualSign(
  Uint8List mlDsaSk, Object classicalSk, Uint8List message) {
  final pqcSig = MlDsa.sign(mlDsaSk, message, dsa, ctx: ctx); // pqcrypto
  final classicalSig = ed25519Sign(classicalSk, message);     // you supply
  return (pqc: pqcSig, classical: classicalSig);
}

// Accept ONLY if both verify.
bool dualVerify(Uint8List mlDsaPk, Object classicalPk, Uint8List message,
    Uint8List pqcSig, Uint8List classicalSig) {
  final a = MlDsa.verify(mlDsaPk, message, pqcSig, dsa, ctx: ctx); // pqcrypto
  final b = ed25519Verify(classicalPk, message, classicalSig);     // you supply
  return a && b;
}
```

**You supply.** A classical signature scheme (Ed25519/ECDSA). A second
**post-quantum** scheme (SLH-DSA) is planned — see
[FUTURE_RELEASES.md](FUTURE_RELEASES.md).

**Caveats.**

- Decide your combiner policy explicitly: require-both (max safety) vs.
  accept-either (max availability during migration). They have opposite failure
  modes.
- Bind the same canonical message into both signatures.

---

## BB10 Offloading heavy work

**What it does.** Keeps UIs responsive by running key generation, signing, and
encapsulation off the main thread.

```dart
import 'dart:isolate';

// Dart VM / Flutter mobile & desktop: real background thread.
final (pk, sk) = await Isolate.run(() =>
    MlDsa.generateKeyPair(DilithiumParams.mlDsa65));

// Flutter equivalent: compute(buildHandshakeRequest, input);
```

**You supply.** Isolate-sendable input/output types, and a policy for handling
secret-key material crossing the isolate boundary.

**Caveats.**

- **Flutter web does not run isolates on a separate thread.** `compute()` keeps
  the same API but does not move CPU off the main thread; heavy keygen will jank
  the page. Prefer `dart2wasm`, do keygen rarely, or generate long-term keys
  server-side.
- Passing a secret key into a worker isolate **copies** sensitive bytes. For
  hardened apps, prefer a dedicated long-lived crypto isolate or a
  platform-backed signing service over copying keys per call.

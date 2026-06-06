# Quickstart

Get running with `pqcrypto` in a few minutes. The API is identical on Dart
servers, Flutter, and the web. First, [install the package](Installation).

```dart
import 'package:pqcrypto/pqcrypto.dart';
```

## 1. Key encapsulation with ML-KEM

ML-KEM (FIPS 203, formerly Kyber) lets two parties agree on a shared secret over
an insecure channel. The receiver publishes a public key; the sender
*encapsulates* to it; both end up with the same 32-byte secret.

```dart
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  final kem = PqcKem.kyber768; // or .kyber512 / .kyber1024

  // Receiver generates a key pair and publishes the public key.
  final (publicKey, secretKey) = kem.generateKeyPair();

  // Sender encapsulates to the public key -> ciphertext + shared secret.
  final (ciphertext, senderSecret) = kem.encapsulate(publicKey);

  // Receiver decapsulates the ciphertext -> the identical shared secret.
  final receiverSecret = kem.decapsulate(secretKey, ciphertext);

  // senderSecret == receiverSecret (32 bytes).
}
```

`generateKeyPair`, `encapsulate`, and `decapsulate` return Dart **records**, so
you destructure them with `final (a, b) = ...`.

> **A shared secret is not encryption.** To actually encrypt data you derive a
> key from the shared secret (HKDF) and use an AEAD (AES-GCM /
> ChaCha20-Poly1305) — neither is in this package. See the
> [Cookbook](Cookbook) recipe "Encrypt to a public key."

## 2. Digital signatures with ML-DSA

ML-DSA (FIPS 204, formerly Dilithium) proves a message's authenticity and
integrity. Signing is **hedged by default** (fresh entropy from
`Random.secure()`), which is the recommended, side-channel-friendlier mode.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  final params = DilithiumParams.mlDsa65; // or mlDsa44 / mlDsa87

  final (publicKey, secretKey) = MlDsa.generateKeyPair(params);

  final message = Uint8List.fromList(utf8.encode('Authorize transfer #1000'));
  // A context string scopes the signature to one purpose (max 255 bytes).
  final ctx = Uint8List.fromList(utf8.encode('transactions/v1'));

  final signature = MlDsa.sign(secretKey, message, params, ctx: ctx);

  final isValid = MlDsa.verify(publicKey, message, signature, params, ctx: ctx);
  // verify returns false (never throws) on any malformed or forged input.
}
```

The argument order is positional: `sign(secretKey, message, params, ...)` and
`verify(publicKey, message, signature, params, ...)`, with `ctx` named.

## 3. Signing large payloads (HashML-DSA)

For large files, use `hashSign` / `hashVerify`. They pre-hash the message with
the FIPS 204 approved hash for the chosen security level (SHA-256 for 44,
SHA-384 for 65, SHA-512 for 87) — you pass the **message**, not a digest; the
pre-hash happens inside.

```dart
final signature = MlDsa.hashSign(secretKey, largePayload, params, ctx: ctx);
final ok = MlDsa.hashVerify(publicKey, largePayload, signature, params, ctx: ctx);
```

## Choosing parameters

| Goal                               | ML-KEM      | ML-DSA    |
| ---------------------------------- | ----------- | --------- |
| Sensible default (NIST category 3) | `kyber768`  | `mlDsa65` |
| Smallest / fastest (lower margin)  | `kyber512`  | `mlDsa44` |
| Maximum margin (category 5)        | `kyber1024` | `mlDsa87` |

For long-lived confidentiality ("harvest now, decrypt later"), prefer
`kyber1024`.

## Next steps

- [Cookbook](Cookbook) — full project recipes (encrypt-to-public-key, hybrid
  handshake, signed updates, at-rest encryption, and more).
- [ML-KEM (FIPS 203)](ML-KEM) and [ML-DSA (FIPS 204)](ML-DSA) — algorithm
  details, sizes, and caveats.
- [Serverpod & Flutter](Serverpod-Integration) — a full client/server blueprint.
- [Security Posture](Security-Posture) — what is and is not guaranteed.

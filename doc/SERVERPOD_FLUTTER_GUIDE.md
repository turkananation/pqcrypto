# Serverpod and Flutter ML-KEM + ML-DSA Integration Guide

Last updated: 2026-06-16

This guide shows an evidence-scoped pattern for combining `pqcrypto` with a
Serverpod backend and a Flutter client. It uses:

- **ML-KEM-768** for a lattice shared secret.
- **ML-DSA-65** for signing handshake transcripts and identity payloads.
- An application-supplied classical key exchange such as X25519.
- An application-supplied HKDF implementation to combine the classical and
  lattice shared secrets.

This is a protocol and implementation sketch for downstream apps. This package
does not claim CMVP/FIPS 140 module validation, hard constant-time Dart
execution, or hard memory-erasure guarantees. Public keys must be authenticated;
ML-KEM by itself is not authenticated transport, and an ML-DSA public key only
identifies someone if your app already trusts or enrolls that key.

## Dependencies

Add `pqcrypto` to the Serverpod server package and the Flutter client package:

```yaml
dependencies:
  pqcrypto: ^0.4.0
```

No `pointycastle` dependency is needed. `pqcrypto` vendors the FIPS 202
SHA3/SHAKE and FIPS 180-4 SHA-2 implementations used by ML-KEM and ML-DSA and
has no third-party runtime dependencies.

Serverpod-specific notes from the current docs:

- endpoint classes extend `Endpoint`;
- endpoint methods return typed `Future`s and accept `Session` first;
- `.spy.yaml` model files under `lib/` generate serializable Dart classes;
- `ByteData` is a supported model and endpoint type; and
- run `serverpod generate` after model or endpoint changes.

Flutter-specific notes from the current docs:

- use `compute()` or isolates for CPU-heavy work on mobile and desktop;
- isolate work cannot touch UI state directly; and
- Flutter web does not run isolates in a separate thread, so `compute()` does
  not remove CPU work from the web main thread.

## Use The Agent Framework First

Before implementing the full stack, use the project-level framework so humans
and LLMs work from the same contracts:

- canonical doc:
  [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md)
- machine-readable manifest:
  [`../tool/agent_framework/pqc_framework.yaml`](../tool/agent_framework/pqc_framework.yaml)
- native Codex wrapper:
  [`../.codex/skills/universal-pqc-framework/SKILL.md`](../.codex/skills/universal-pqc-framework/SKILL.md)
- native Claude Code wrapper:
  [`../.claude/skills/universal-pqc-framework/SKILL.md`](../.claude/skills/universal-pqc-framework/SKILL.md)
- native Antigravity wrapper:
  [`../.gemini/antigravity/skills/universal-pqc-framework/SKILL.md`](../.gemini/antigravity/skills/universal-pqc-framework/SKILL.md)

Recommended role order:

1. **Cryptographic Architect:** byte contracts, transcript fields, HKDF inputs,
   context strings, and misuse rules.
2. **SecOps & Infrastructure Engineer:** KMS/HSM loading, key ids, rotation,
   break-glass eviction, and telemetry.
3. **Distinguished Engineer:** Serverpod models, strict filters, replay
   windows, atomic key-bundle swaps, and failure behavior.
4. **Client Integration Engineer:** Flutter isolate flow, local session state,
   generated client calls, and re-handshake behavior.

Prompt examples:

```text
Use the universal-pqc-framework skill. Act as the Cryptographic Architect.
Define the transcript fields and HKDF input contract for Serverpod + Flutter
using ML-KEM-768, ML-DSA-65, and app-supplied X25519. Keep claims scoped to
pqcrypto evidence.
```

```text
Use the universal-pqc-framework skill. Act as the Distinguished Engineer.
Turn the manifest byte contracts into Serverpod .spy.yaml models, endpoint
guards, replay rejection, and key-bundle hot-swap rules. Treat this repo as a
contract source, not a completed Serverpod app.
```

```text
Use the universal-pqc-framework skill. Act as the Client Integration Engineer.
Build the Flutter handshake service around generated Serverpod client methods,
offloading ML-KEM encapsulation and ML-DSA signing with compute().
```

## Byte Contracts

The default enterprise profile uses ML-KEM-768 and ML-DSA-65:

| Field                     | Exact length |
| ------------------------- | ------------ |
| ML-KEM-768 public key     | 1184 bytes   |
| ML-KEM-768 secret key     | 2400 bytes   |
| ML-KEM-768 ciphertext     | 1088 bytes   |
| ML-KEM shared secret      | 32 bytes     |
| ML-DSA-65 public key      | 1952 bytes   |
| ML-DSA-65 secret key      | 4032 bytes   |
| ML-DSA-65 signature       | 3309 bytes   |
| Recommended nonce         | 32 bytes     |
| Recommended session key   | 32 bytes     |
| ML-DSA context max length | 255 bytes    |

Reject malformed byte lengths before decapsulation, signature verification, key
derivation, cache writes, or database writes.

## Protocol Sketch

1. Server loads an active immutable key bundle containing an ML-KEM-768 keypair,
   an ML-DSA-65 keypair, key id, epoch, validity window, and trust metadata.
2. Client fetches the public key bundle and authenticates it through a pinned
   trust anchor, certificate chain, signed metadata channel, or another
   application trust mechanism. Do not trust a self-signed bundle just because
   the bundle contains an ML-DSA public key.
3. Client computes an application-supplied classical shared secret, for example
   X25519, and encapsulates to the server ML-KEM-768 public key.
4. Client builds a canonical transcript that binds protocol version, algorithm
   ids, key id, server public keys, client public material, ML-KEM ciphertext,
   nonce, and timestamp.
5. Client signs the transcript with its ML-DSA-65 identity key.
6. Server validates the key id, validity window, exact byte lengths, timestamp
   window, nonce replay status, and ML-DSA signature before decapsulation.
7. Both sides derive the session key with an application HKDF provider:

```text
ikm = ss_classical || ss_lattice
salt = deployment_salt || transcript_hash
info = "pqcrypto serverpod flutter v1" || key_id || role
session_key = HKDF-Extract-and-Expand(salt, ikm, info, 32)
```

`pqcrypto` intentionally does not provide X25519, HKDF, TLS, storage, or AEAD
traffic encryption APIs. Choose those from the application stack and fetch their
current docs before implementation.

## Package-Only Handshake Core

The package-level primitives are simple to compose. The runnable
[`example/main.dart`](../example/main.dart) includes a complete version of this
flow.

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

final kem = PqcKem.kyber768;
final dsaParams = DilithiumParams.mlDsa65;
final dsaContext = Uint8List.fromList(utf8.encode('serverpod-handshake-v1'));

final (serverKemPk, serverKemSk) = kem.generateKeyPair();
final (clientDsaPk, clientDsaSk) = MlDsa.generateKeyPair(dsaParams);

final (ciphertext, clientLatticeSecret) = kem.encapsulate(serverKemPk);
final transcript = buildCanonicalTranscript([
  utf8Bytes('pqcrypto/serverpod/v1'),
  utf8Bytes('ML-KEM-768'),
  utf8Bytes('ML-DSA-65'),
  serverKemPk,
  clientDsaPk,
  ciphertext,
]);

final clientSignature = MlDsa.sign(
  clientDsaSk,
  transcript,
  dsaParams,
  ctx: dsaContext,
);

final signatureOk = MlDsa.verify(
  clientDsaPk,
  transcript,
  clientSignature,
  dsaParams,
  ctx: dsaContext,
);

final serverLatticeSecret = kem.decapsulate(serverKemSk, ciphertext);
```

For large application messages, prefer `MlDsa.hashSign` and
`MlDsa.hashVerify`. For a small handshake transcript, direct `sign` and
`verify` are appropriate.

## Serverpod Models

Create model files under your Serverpod server `lib/` directory, then run
`serverpod generate`.

`lib/src/protocol/pqc_public_key_bundle.spy.yaml`:

```yaml
class: PqcPublicKeyBundle
fields:
  keyId: String
  epoch: int
  mlKem768PublicKey: ByteData
  mlDsa65PublicKey: ByteData
  notBefore: DateTime
  expiresAt: DateTime
  trustSignature: ByteData
```

`trustSignature` should be produced by a deployment trust anchor that the client
already knows how to verify. It is not useful if the only verification key is
the untrusted `mlDsa65PublicKey` inside the same bundle.

`lib/src/protocol/pqc_handshake_request.spy.yaml`:

```yaml
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
```

`lib/src/protocol/pqc_handshake_response.spy.yaml`:

```yaml
class: PqcHandshakeResponse
fields:
  accepted: bool
  sessionId: String?
  serverNonce: ByteData?
  expiresAt: DateTime?
  errorCode: String?
```

## Server Key Manager Sketch

This development sketch generates keys in memory so the API shape is clear. A
production app should load long-term keys from KMS/HSM-backed storage, use
immutable key-bundle snapshots, and zeroize retired secret buffers on a
best-effort basis before releasing references.

```dart
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

class ActivePqcKeyBundle {
  ActivePqcKeyBundle({
    required this.keyId,
    required this.epoch,
    required this.notBefore,
    required this.expiresAt,
    required this.mlKemPublicKey,
    required this.mlKemSecretKey,
    required this.mlDsaPublicKey,
    required this.mlDsaSecretKey,
    required this.trustSignature,
  });

  final String keyId;
  final int epoch;
  final DateTime notBefore;
  final DateTime expiresAt;
  final Uint8List mlKemPublicKey;
  final Uint8List mlKemSecretKey;
  final Uint8List mlDsaPublicKey;
  final Uint8List mlDsaSecretKey;
  final Uint8List trustSignature;
}

class PqcKeyManager {
  PqcKeyManager._();

  static final instance = PqcKeyManager._();

  final kem = PqcKem.kyber768;
  final dsaParams = DilithiumParams.mlDsa65;

  late ActivePqcKeyBundle _active;

  ActivePqcKeyBundle get active => _active;

  void initializeForDevelopment() {
    final (kemPk, kemSk) = kem.generateKeyPair();
    final (dsaPk, dsaSk) = MlDsa.generateKeyPair(dsaParams);

    _active = ActivePqcKeyBundle(
      keyId: 'dev-key-1',
      epoch: 1,
      notBefore: DateTime.now().toUtc(),
      expiresAt: DateTime.now().toUtc().add(const Duration(days: 14)),
      mlKemPublicKey: kemPk,
      mlKemSecretKey: kemSk,
      mlDsaPublicKey: dsaPk,
      mlDsaSecretKey: dsaSk,
      trustSignature: Uint8List(0), // Replace with deployment trust signature.
    );
  }

  Uint8List decapsulate(Uint8List ciphertext) {
    return kem.decapsulate(_active.mlKemSecretKey, ciphertext);
  }

  bool verifyClientTranscript({
    required Uint8List clientPublicKey,
    required Uint8List transcript,
    required Uint8List signature,
    required Uint8List context,
  }) {
    return MlDsa.verify(
      clientPublicKey,
      transcript,
      signature,
      dsaParams,
      ctx: context,
    );
  }
}
```

## Serverpod Endpoint Sketch

This code shows where the checks belong. Replace placeholder functions such as
`buildHandshakeTranscript`, `transcriptHash32`, `deriveX25519Secret`,
`hkdfSessionKey`, and `storeSession` with your audited application providers.

```dart
import 'dart:math';
import 'dart:typed_data';
import 'package:serverpod/serverpod.dart';

class PqcEndpoint extends Endpoint {
  static final _dsaContext = Uint8List.fromList(
    'pqcrypto-serverpod-handshake-v1'.codeUnits,
  );

  Future<PqcPublicKeyBundle> getPublicKeyBundle(Session session) async {
    final active = PqcKeyManager.instance.active;
    return PqcPublicKeyBundle(
      keyId: active.keyId,
      epoch: active.epoch,
      mlKem768PublicKey: _toByteData(active.mlKemPublicKey),
      mlDsa65PublicKey: _toByteData(active.mlDsaPublicKey),
      notBefore: active.notBefore,
      expiresAt: active.expiresAt,
      trustSignature: _toByteData(active.trustSignature),
    );
  }

  Future<PqcHandshakeResponse> establishSession(
    Session session,
    PqcHandshakeRequest request,
  ) async {
    try {
      final active = PqcKeyManager.instance.active;
      if (request.keyId != active.keyId) {
        return _reject('unknown-key-id');
      }

      final clientNonce = _copyBytes(request.clientNonce);
      final clientX25519PublicKey = _copyBytes(request.clientX25519PublicKey);
      final ciphertext = _copyBytes(request.mlKem768Ciphertext);
      final clientDsaPublicKey = _copyBytes(request.clientMlDsa65PublicKey);
      final clientSignature = _copyBytes(request.clientSignature);
      final transcriptHash = _copyBytes(request.transcriptHash);

      _requireLength(clientNonce, 32, 'clientNonce');
      _requireLength(ciphertext, 1088, 'mlKem768Ciphertext');
      _requireLength(clientDsaPublicKey, 1952, 'clientMlDsa65PublicKey');
      _requireLength(clientSignature, 3309, 'clientSignature');
      _requireLength(transcriptHash, 32, 'transcriptHash');

      final nowMs = DateTime.now().toUtc().millisecondsSinceEpoch;
      if ((nowMs - request.clientTimestampMs).abs() > 2000) {
        return _reject('timestamp-window');
      }
      if (await nonceSeenOrStore(clientNonce, request.clientTimestampMs)) {
        return _reject('nonce-replay');
      }

      final transcript = buildHandshakeTranscript(
        keyId: request.keyId,
        clientTimestampMs: request.clientTimestampMs,
        clientNonce: clientNonce,
        clientX25519PublicKey: clientX25519PublicKey,
        mlKem768PublicKey: active.mlKemPublicKey,
        mlDsa65PublicKey: active.mlDsaPublicKey,
        mlKem768Ciphertext: ciphertext,
        clientMlDsa65PublicKey: clientDsaPublicKey,
      );

      if (!constantTimeBytesEqual(transcriptHash32(transcript), transcriptHash)) {
        return _reject('transcript-hash');
      }

      final signatureOk = PqcKeyManager.instance.verifyClientTranscript(
        clientPublicKey: clientDsaPublicKey,
        transcript: transcript,
        signature: clientSignature,
        context: _dsaContext,
      );
      if (!signatureOk) {
        return _reject('client-signature');
      }

      final ssLattice = PqcKeyManager.instance.decapsulate(ciphertext);
      final ssClassical = await deriveX25519Secret(clientX25519PublicKey);
      final sessionKey = await hkdfSessionKey(
        ssClassical: ssClassical,
        ssLattice: ssLattice,
        transcriptHash: transcriptHash,
        keyId: request.keyId,
      );

      final sessionId = await storeSession(sessionKey);
      final serverNonce = secureRandomBytes(32);
      return PqcHandshakeResponse(
        accepted: true,
        sessionId: sessionId,
        serverNonce: _toByteData(serverNonce),
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
        errorCode: null,
      );
    } on ArgumentError catch (error) {
      session.log('PQC handshake rejected: $error');
      return _reject('bad-request');
    } catch (error) {
      session.log('PQC handshake failed: $error');
      return _reject('internal-error');
    }
  }
}

PqcHandshakeResponse _reject(String code) {
  return PqcHandshakeResponse(
    accepted: false,
    sessionId: null,
    serverNonce: null,
    expiresAt: null,
    errorCode: code,
  );
}

Uint8List _copyBytes(ByteData data) {
  final view = data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
  return Uint8List.fromList(view);
}

ByteData _toByteData(Uint8List bytes) => ByteData.sublistView(bytes);

void _requireLength(Uint8List bytes, int expected, String field) {
  if (bytes.length != expected) {
    throw ArgumentError('$field must be $expected bytes, got ${bytes.length}');
  }
}
```

Server ordering matters: reject replay and malformed lengths before expensive
cryptographic work, but verify transcript and signature before accepting or
storing any derived session state.

## Flutter Client Sketch

The client should offload ML-KEM encapsulation and ML-DSA signing on mobile and
desktop. On web, `compute()` preserves the same API shape but does not move the
work to another thread.

```dart
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:your_app_client/your_app_client.dart';

class PqcClientSecurityService {
  PqcClientSecurityService(this.client);

  final Client client;

  Future<void> establishSession() async {
    final bundle = await client.pqc.getPublicKeyBundle();
    await verifyTrustedServerBundle(bundle);

    final x25519 = await createX25519HandshakeMaterial();
    final clientIdentity = await loadOrCreateMlDsa65Identity();
    final clientNonce = secureRandomBytes(32);
    final timestampMs = DateTime.now().toUtc().millisecondsSinceEpoch;

    final output = await compute(
      buildPqcHandshakeRequest,
      ClientHandshakeInput(
        keyId: bundle.keyId,
        timestampMs: timestampMs,
        clientNonce: clientNonce,
        clientX25519PublicKey: x25519.publicKey,
        serverMlKem768PublicKey: _copyBytes(bundle.mlKem768PublicKey),
        serverMlDsa65PublicKey: _copyBytes(bundle.mlDsa65PublicKey),
        clientMlDsa65PublicKey: clientIdentity.publicKey,
        clientMlDsa65SecretKey: clientIdentity.secretKey,
      ),
    );

    final response = await client.pqc.establishSession(output.request);
    if (!response.accepted) {
      await clearLocalPqcSession();
      throw StateError('PQC handshake rejected: ${response.errorCode}');
    }

    final sessionKey = await hkdfSessionKey(
      ssClassical: x25519.sharedSecret,
      ssLattice: output.mlKemSharedSecret,
      transcriptHash: output.transcriptHash,
      keyId: bundle.keyId,
    );

    await storeLocalPqcSession(
      sessionId: response.sessionId!,
      sessionKey: sessionKey,
      expiresAt: response.expiresAt!,
    );
  }
}

ClientHandshakeOutput buildPqcHandshakeRequest(ClientHandshakeInput input) {
  final kem = PqcKem.kyber768;
  final params = DilithiumParams.mlDsa65;
  final context = Uint8List.fromList('pqcrypto-serverpod-handshake-v1'.codeUnits);

  final (ciphertext, sharedSecret) = kem.encapsulate(
    input.serverMlKem768PublicKey,
  );

  final transcript = buildHandshakeTranscript(
    keyId: input.keyId,
    clientTimestampMs: input.timestampMs,
    clientNonce: input.clientNonce,
    clientX25519PublicKey: input.clientX25519PublicKey,
    mlKem768PublicKey: input.serverMlKem768PublicKey,
    mlDsa65PublicKey: input.serverMlDsa65PublicKey,
    mlKem768Ciphertext: ciphertext,
    clientMlDsa65PublicKey: input.clientMlDsa65PublicKey,
  );
  final transcriptHash = transcriptHash32(transcript);

  final signature = MlDsa.sign(
    input.clientMlDsa65SecretKey,
    transcript,
    params,
    ctx: context,
  );

  return ClientHandshakeOutput(
    request: PqcHandshakeRequest(
      keyId: input.keyId,
      clientNonce: _toByteData(input.clientNonce),
      clientTimestampMs: input.timestampMs,
      clientX25519PublicKey: _toByteData(input.clientX25519PublicKey),
      mlKem768Ciphertext: _toByteData(ciphertext),
      clientMlDsa65PublicKey: _toByteData(input.clientMlDsa65PublicKey),
      clientSignature: _toByteData(signature),
      transcriptHash: _toByteData(transcriptHash),
    ),
    mlKemSharedSecret: sharedSecret,
    transcriptHash: transcriptHash,
  );
}
```

`ClientHandshakeInput`, `ClientHandshakeOutput`, `createX25519HandshakeMaterial`,
`hkdfSessionKey`, secure local storage, and trust-bundle verification are app
code. Keep them small, testable, and explicit because they define your real
security boundary. Ensure the values you pass to `compute()` and return from it
are isolate-sendable for your target platforms. Passing the ML-DSA secret key to
a worker isolate copies sensitive bytes; production apps may prefer a dedicated
crypto isolate or platform-backed signing service.

## Transcript Builder

Use length-prefixed binary fields so transcript parsing is unambiguous. Keep one
canonical builder shared by the server and client.

```dart
import 'dart:convert';
import 'dart:typed_data';

Uint8List buildHandshakeTranscript({
  required String keyId,
  required int clientTimestampMs,
  required Uint8List clientNonce,
  required Uint8List clientX25519PublicKey,
  required Uint8List mlKem768PublicKey,
  required Uint8List mlDsa65PublicKey,
  required Uint8List mlKem768Ciphertext,
  required Uint8List clientMlDsa65PublicKey,
}) {
  return lengthPrefixFields([
    utf8Bytes('pqcrypto/serverpod/flutter/v1'),
    utf8Bytes('ML-KEM-768'),
    utf8Bytes('ML-DSA-65'),
    utf8Bytes(keyId),
    uint64(clientTimestampMs),
    clientNonce,
    clientX25519PublicKey,
    mlKem768PublicKey,
    mlDsa65PublicKey,
    mlKem768Ciphertext,
    clientMlDsa65PublicKey,
  ]);
}

Uint8List lengthPrefixFields(List<Uint8List> fields) {
  final chunks = <Uint8List>[];
  for (final field in fields) {
    chunks.add(uint32(field.length));
    chunks.add(field);
  }
  return concatBytes(chunks);
}

Uint8List concatBytes(List<Uint8List> chunks) {
  final total = chunks.fold<int>(0, (sum, chunk) => sum + chunk.length);
  final out = Uint8List(total);
  var offset = 0;
  for (final chunk in chunks) {
    out.setRange(offset, offset + chunk.length, chunk);
    offset += chunk.length;
  }
  return out;
}

Uint8List uint32(int value) {
  return Uint8List(4)..buffer.asByteData().setUint32(0, value, Endian.big);
}

Uint8List uint64(int value) {
  return Uint8List(8)..buffer.asByteData().setUint64(0, value, Endian.big);
}

Uint8List utf8Bytes(String value) => Uint8List.fromList(utf8.encode(value));
```

Choose a transcript hash from your application crypto provider and use the same
function on both sides. Do not call non-exported `pqcrypto` internals from an
application package.

## Production Checklist

- Authenticate the server public-key bundle before encapsulation.
- Treat client ML-DSA public keys as identities only after enrollment,
  attestation, account binding, or certificate validation.
- Enforce the exact byte lengths before crypto operations.
- Use a 2000 ms timestamp window unless your threat model justifies a different
  value.
- Store nonces in a bounded replay window and reject duplicates before
  decapsulation.
- Combine classical and lattice shared secrets with HKDF; never use the raw
  ML-KEM shared secret directly as an application traffic key.
- Use AEAD for application traffic after the handshake.
- Do not log keys, shared secrets, signatures over private material, or derived
  session keys.
- Implement key rotation with immutable bundle swaps and best-effort zeroization
  of retired secret buffers.
- On break-glass eviction, clear server session mappings, replay windows, and
  client local session state, then force re-handshake.

## Verification Before Release

Run the package example and the focused regression gates before publishing docs
that reference this flow:

```bash
dart run example/main.dart
dart analyze
dart test test/kat_evaluator_test.dart
dart test test/mldsa_kat_test.dart
dart run tool/agent_framework/check_setup.dart
npx markdownlint-cli2 "**/*.md"
```

For a real Serverpod app, also run:

```bash
serverpod generate
dart test
```

and add app-level tests for generated model round trips, byte-length rejection,
nonce replay rejection, signature failure, key eviction, and client
re-handshake.

## Related Docs

- [UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md](UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md)
- [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md)
- [MLKEM_TESTING.md](MLKEM_TESTING.md)
- [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md)
- [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

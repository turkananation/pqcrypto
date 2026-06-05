# Serverpod & Flutter Integration Guide

This document is the canonical integration guide for coupling `pqcrypto` with a Dart backend (Serverpod) and a Flutter client. It is authored with a zero-trust, enterprise-first mindset.

## 🏗️ 1. The Hybrid Handshake Protocol

Lattice-based cryptography is relatively new compared to elliptic-curve cryptography (ECC). To mitigate the risk of an undiscovered mathematical flaw in FIPS 203 (ML-KEM), you **must** use a hybrid key exchange. 

The protocol flow:
1. **Bootstrap:** The Serverpod backend loads an immutable Key Bundle (containing an ML-KEM-768 public/secret key, an ML-DSA-65 identity key, and a rotation epoch) from a hardware security module (HSM) or KMS.
2. **Client Init:** The Flutter client generates an ephemeral classical key (e.g., X25519) and an ephemeral nonce.
3. **Encapsulation:** The client uses the server's ML-KEM public key to encapsulate a lattice shared secret.
4. **Transcript Binding:** The client computes a deterministic hash of the entire communication transcript to prevent man-in-the-middle downgrade attacks.
5. **Authentication:** The client signs this transcript hash using its ML-DSA-65 identity key.
6. **Key Derivation:** The server verifies the transcript and signature, decapsulates the ML-KEM secret, and merges it with the X25519 secret via HKDF (`ss_classical || ss_lattice`).

## 🛡️ 2. Serverpod Payload Contracts (`.spy.yaml`)

Your API boundaries must be strictly typed. Create the following Serverpod models. The `ByteData` fields represent the raw binary structures.

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

### 2.1 Hard Byte-Length Filtering
Before allocating memory for cryptographic operations, the Serverpod `Endpoint` **must** enforce strict length validations. Failure to do this exposes the server to buffer exhaustion and denial-of-service (DoS).

```dart
void _requireLength(Uint8List bytes, int expected, String field) {
  if (bytes.length != expected) {
    throw ArgumentError('Malformed $field: Expected $expected bytes, got ${bytes.length}');
  }
}

// In your Endpoint:
_requireLength(ciphertext, 1088, 'mlKem768Ciphertext');
_requireLength(clientDsaPublicKey, 1952, 'clientMlDsa65PublicKey');
_requireLength(clientSignature, 3309, 'clientSignature');
```

## 🔒 3. Replay Defenses & Timing Windows

A stolen, intercepted ML-KEM ciphertext can be submitted repeatedly. 

1. **Timestamp Window:** The `clientTimestampMs` must be validated against the server's UTC clock. A `2000ms` window is standard. Anything outside this window is immediately rejected.
2. **Nonce Caching:** Store the 32-byte `clientNonce` in Serverpod's Redis instance with a TTL of 2000ms. If a nonce is seen twice, terminate the handshake.

## 🧬 4. Transcript Serialization

The `transcriptHash` must unambiguously bind the session parameters. Use length-prefixed encoding to prevent collision vulnerabilities where an attacker shifts bytes between adjacent fields.

```dart
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
```

## 📱 5. Flutter Isolate Offloading

Lattice cryptography operates on polynomial rings using the Number Theoretic Transform (NTT). This is CPU-intensive. On mobile devices, executing ML-KEM encapsulation and ML-DSA signing on the main thread will cause UI stutter (jank).

**You must offload this to a worker isolate using `compute()`:**

```dart
Future<void> establishSession() async {
  // 1. Fetch public materials...
  
  // 2. Offload the heavy cryptography to a background isolate
  final output = await compute(
    _buildPqcHandshakeRequest,
    ClientHandshakeInput(
      keyId: serverBundle.keyId,
      timestampMs: DateTime.now().toUtc().millisecondsSinceEpoch,
      clientNonce: secureRandomBytes(32),
      // ... pass required keys
    ),
  );
  
  // 3. Send over the network
  final response = await client.pqc.establishSession(output.request);
}
```

*Note: On Flutter Web (`dart2js` / `dart2wasm`), `compute()` executes sequentially because web workers do not share memory natively. Design your web UI with loading states to account for this synchronous execution.*

## ⚠️ 6. Key Manager Distillation (Zeroization)

Once the `sessionKey` is derived via HKDF, the underlying `ss_classical` and `ss_lattice` buffers **must** be zeroized. In Dart, you cannot force the Garbage Collector to wipe memory, but you can explicitly zero out the `Uint8List` indices before the variables fall out of scope. 

```dart
try {
  sessionKey = await hkdfSessionKey(...);
} finally {
  secureZero(ss_lattice);
  secureZero(ss_classical);
}
```

# Serverpod & Flutter Integration Guide

Because `pqcrypto` is pure Dart, it naturally bridges the gap between Flutter clients and Dart backends like [Serverpod](https://serverpod.dev/).

This guide illustrates a highly secure, post-quantum handshake architecture combining our ML-KEM-768 and ML-DSA-65 algorithms with Serverpod.

## 🏗️ The Hybrid Handshake Architecture

In enterprise deployments, post-quantum algorithms should always be paired with classical algorithms (like X25519) to ensure hybrid security.

1. **Client Identity & Key Material:** The Flutter client generates an ephemeral X25519 key and holds an ML-DSA-65 identity key.
2. **Server Identity:** The Serverpod backend holds a long-term ML-KEM-768 key and an ML-DSA-65 signing key, rotated via a KMS/HSM.
3. **Encapsulation:** The client encapsulates a shared secret to the server's ML-KEM public key.
4. **Transcript Binding:** The client binds the classical material, the ML-KEM ciphertext, nonces, and timestamps into a canonical transcript.
5. **Authentication:** The client signs this transcript using its ML-DSA-65 key.
6. **Verification & Derivation:** The server verifies the signature, decapsulates the ML-KEM secret, and derives a final session key using HKDF (`ss_classical || ss_lattice`).

## 🛡️ Defining Byte Contracts in Serverpod

To securely pass this data over the network, you must enforce strict byte length constraints before any cryptographic operations. In Serverpod, define your payloads in `.spy.yaml` files:

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

### Server Endpoint Validation

In your `Endpoint`, validate the exact lengths of the incoming buffers. **Do not** attempt to decode or process malformed byte arrays:

```dart
_requireLength(ciphertext, 1088, 'mlKem768Ciphertext');
_requireLength(clientDsaPublicKey, 1952, 'clientMlDsa65PublicKey');
_requireLength(clientSignature, 3309, 'clientSignature');
```

You must also enforce replay defenses (tracking `clientNonce` in Redis) and a strict timestamp window (e.g., 2000 ms) before running `kem.decapsulate()`.

## 📱 Flutter Client Offloading

Cryptographic operations like ML-KEM encapsulation and ML-DSA signing are CPU-intensive. In a Flutter application, these must be offloaded from the UI isolate to prevent frame drops.

```dart
final output = await compute(
  buildPqcHandshakeRequest,
  ClientHandshakeInput(
    // ... Pass public keys and nonces
  ),
);
```

> **Note on Flutter Web:** The `compute()` function does not currently spawn a separate thread in Dart Web. On web targets, execution will block the main thread.

## 📖 Further Reading
For a complete, copy-pasteable implementation sketch of the Serverpod Endpoint, Key Manager, and Flutter Client Service, please view the canonical [SERVERPOD_FLUTTER_GUIDE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/SERVERPOD_FLUTTER_GUIDE.md) in the repository docs.

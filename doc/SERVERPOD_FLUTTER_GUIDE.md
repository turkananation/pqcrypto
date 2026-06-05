# Serverpod and Flutter ML-KEM Integration Guide

Last updated: 2026-06-05

This guide shows a defense-in-depth ML-KEM session establishment pattern between
a Flutter client and a Serverpod backend. It is an example protocol sketch, not
a complete authenticated transport design.

## Dependencies

Add `pqcrypto` to the server and client packages:

```yaml
dependencies:
  pqcrypto: ^0.2.1
```

No `pointycastle` dependency is needed. `pqcrypto` vendors its FIPS 202
SHA3/SHAKE implementation and has no third-party runtime dependencies.

## Protocol Sketch

1. Server owns an ML-KEM decapsulation keypair.
2. Client fetches the server public key.
3. Client encapsulates to that public key.
4. Client sends the ciphertext to the server.
5. Server decapsulates and both parties derive the same 32-byte shared secret.
6. Application code feeds that secret into an authenticated symmetric protocol.

Use ML-KEM as a key agreement component. It does not authenticate the server by
itself.

## Server Key Manager

```dart
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

class KeyManager {
  KeyManager._();

  static final instance = KeyManager._();

  final KyberKem kem = PqcKem.kyber768;

  late final Uint8List publicKey;
  late final Uint8List _secretKey;

  void initialize() {
    final (pk, sk) = kem.generateKeyPair();
    publicKey = pk;
    _secretKey = sk;
  }

  Uint8List decapsulate(Uint8List ciphertext) {
    return kem.decapsulate(_secretKey, ciphertext);
  }
}
```

Production systems should load long-term private material from secure storage or
generate ephemeral keys according to the application protocol.

## Serverpod Endpoint

```dart
import 'dart:typed_data';
import 'package:serverpod/serverpod.dart';
import '../services/key_manager.dart';

class CryptoEndpoint extends Endpoint {
  Future<List<int>> getServerPublicKey(Session session) async {
    return KeyManager.instance.publicKey.toList();
  }

  Future<bool> establishSecureSession(
    Session session,
    List<int> ciphertextBytes,
  ) async {
    try {
      final ciphertext = Uint8List.fromList(ciphertextBytes);
      final sharedSecret = KeyManager.instance.decapsulate(ciphertext);

      // Store only according to your authenticated session design.
      // Avoid logging sharedSecret or other secret material.
      session.log('ML-KEM session established');
      return sharedSecret.length == 32;
    } on ArgumentError catch (error) {
      session.log('ML-KEM input rejected: $error');
      return false;
    }
  }
}
```

## Flutter Client

```dart
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:your_app_client/your_app_client.dart';

class PqcService {
  PqcService(this.client);

  final Client client;
  final KyberKem kem = PqcKem.kyber768;

  Future<Uint8List> performHandshake() async {
    final pkBytes = await client.crypto.getServerPublicKey();
    final serverPublicKey = Uint8List.fromList(pkBytes);

    final (ciphertext, sharedSecret) = kem.encapsulate(serverPublicKey);
    final accepted = await client.crypto.establishSecureSession(
      ciphertext.toList(),
    );

    if (!accepted) {
      throw StateError('Server rejected ML-KEM session setup');
    }

    return sharedSecret;
  }
}
```

## Security Requirements

- Use HTTPS/TLS. ML-KEM here is not a replacement for authenticated transport.
- Authenticate the server public key. A raw KEM public key is vulnerable to
  man-in-the-middle substitution.
- Do not log shared secrets, ciphertext-derived secrets, or private keys.
- Bind the derived key to a session transcript before using it for application
  encryption.
- Prefer AEAD algorithms such as AES-GCM or ChaCha20-Poly1305 for subsequent
  traffic encryption.
- Rotate or expire derived session material according to your threat model.

## Related Docs

- [MLKEM_TESTING.md](MLKEM_TESTING.md)
- [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md)
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

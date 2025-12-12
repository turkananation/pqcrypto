# ⚡ Integrating pqcrypto's ML-KEM with Serverpod & Flutter

This guide demonstrates how to establish a **Post-Quantum Secure Session** between a **Flutter Client** and a **Serverpod Backend** using `pqcrypto`.

We will implement a standard **KEM (Key Encapsulation Mechanism)** flow:
1.  **Server** holds a static (or ephemeral) ML-KEM Keypair.
2.  **Client** fetches Server's Public Key.
3.  **Client** Encapsulates a Shared Secret and sends Ciphertext to Server.
4.  **Server** Decapsulates using Secret Key.
5.  Both parties now share a 32-byte secret for symmetric encryption (e.g., AES-GCM).

---

## 1. 📦 Dependencies

Add `pqcrypto` to both your generic Client/Server implementations.

**server/pubspec.yaml** AND **flutter_app/pubspec.yaml**:
```yaml
dependencies:
  # ... other deps
  pqcrypto: ^0.1.0
  pointycastle: ^4.0.0
```

---

## 2. 🖥️ Server-Side Implementation

### A. Key Manager (Singleton)

Create a service to manage the server's long-term identity keys. In production, load these from secure storage (Hashicorp Vault, AWS KMS, or local secure file).

`lib/src/services/key_manager.dart`:
```dart
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';

class KeyManager {
  // Singleton instance
  static final KeyManager _instance = KeyManager._internal();
  factory KeyManager() => _instance;
  KeyManager._internal();

  late final Uint8List publicKey;
  late final Uint8List _secretKey;
  final kem = PqcKem.kyber768; // NIST Level 3

  void initialize() {
    print('🔐 Generating PQC Server Keys...');
    // In PROD: Load from disk/DB!
    final pair = kem.generateKeyPair();
    publicKey = pair.$1;
    _secretKey = pair.$2;
    print('✅ Server Keys Ready: PK is ${publicKey.length} bytes');
  }

  Uint8List decapsulate(Uint8List ciphertext) {
    return kem.decapsulate(_secretKey, ciphertext);
  }
}
```

**Initialize on Server Start:**
Update `lib/server.dart` -> `run()`:
```dart
void run(List<String> args) async {
  // ...
  KeyManager().initialize(); // <--- Init Poly/Keys
  await pod.start();
}
```

### B. The Endpoint

Create an endpoint to exchange keys.

`lib/src/endpoints/crypto_endpoint.dart`:
```dart
import 'dart:typed_data';
import 'package:serverpod/serverpod.dart';
import '../services/key_manager.dart';

class CryptoEndpoint extends Endpoint {
  
  /// 1. Client requests Server's Public Key
  Future<List<int>> getServerPublicKey(Session session) async {
    return KeyManager().publicKey.toList();
  }

  /// 2. Client sends Ciphertext -> Server returns nothing (just sets up session)
  /// In a real app, you might return a session token encrypted with the shared secret to prove possession.
  Future<bool> establishSecureSession(Session session, List<int> ciphertextList) async {
    try {
      final ciphertext = Uint8List.fromList(ciphertextList);
      
      // Decapsulate to get the 32-byte Shared Secret
      final sharedSecret = KeyManager().decapsulate(ciphertext);
      
      print('🔒 SECURE SESSION ESTABLISHED');
      print('   Shared Secret: ${sharedSecret.sublist(0, 8)}...');

      // TODO: Save 'sharedSecret' to a cache (Redis/Memory) linked to this user's session ID
      // await sessionCache.set(session.id, sharedSecret);

      return true;
    } catch (e) {
      print('❌ Key Exchange Failed: $e');
      return false;
    }
  }
}
```

---

## 3. 📱 Flutter Client Implementation

### A. The Handshake Logic

`lib/services/pqc_service.dart`:
```dart
import 'dart:typed_data';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:your_app_client/your_app_client.dart'; // Serverpod Gen Client

class PqcService {
  final Client client; // Serverpod Client
  final kem = PqcKem.kyber768;

  PqcService(this.client);

  Future<Uint8List> performHandshake() async {
    // 1. Fetch Server PK
    final pkList = await client.crypto.getServerPublicKey();
    final serverPk = Uint8List.fromList(pkList);

    // 2. Encapsulate (Client generates secret)
    final (ciphertext, sharedSecret) = kem.encapsulate(serverPk);

    // 3. Send Ciphertext to Server
    final success = await client.crypto.establishSecureSession(ciphertext.toList());

    if (!success) {
      throw Exception("Server rejected key exchange");
    }

    print('✅ PQC Handshake Complete!');
    return sharedSecret; // Use this for AES-256
  }
}
```

### B. Usage in Widget

```dart
void _connect() async {
    final pqc = PqcService(client);
    final secret = await pqc.performHandshake();
    
    // Use `secret` with a package like `encrypt` for AES-GCM
    // AES(key: secret).encrypt("Hello Quantum World");
}
```

---

## 🔒 Security Considerations

1.  **Transport Layer**: **ALWAYS** use this over **HTTPS (TLS 1.3)**. PQC is a defense-in-depth layer against "Harvest Now, Decrypt Later" attacks on TLS.
2.  **Authentication**: The KEM exchange is anonymous by default. You must sign the Public Key (using conventional ECDSA or post-quantum ML-DSA) to prevent Man-in-the-Middle (MitM) attacks.
3.  **Symmetric Algo**: The `32-byte` shared secret is perfect for `AES-256-GCM` or `ChaCha20-Poly1305`.

---

# Quickstart Guide

This guide will get you up and running with `pqcrypto` in minutes. Whether you are building a pure Dart backend or a Flutter mobile application, the API is identical and seamless.

## Installation

Add `pqcrypto` to your `pubspec.yaml`:

```bash
dart pub add pqcrypto
```

## 1. Key Encapsulation (ML-KEM)

ML-KEM (formerly Kyber) is used to securely establish a shared secret between two parties over an insecure channel.

```dart
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  // 1. Generate a key pair for the receiver (Alice)
  final aliceKeyPair = MlKem.generateKeyPair(MlKemParameterSpec.mlKem768);

  // 2. Sender (Bob) uses Alice's public key to encapsulate a secret
  final encapsulation = MlKem.encapsulate(aliceKeyPair.publicKey);
  
  // Bob sends the ciphertext to Alice...
  final ciphertext = encapsulation.ciphertext;
  final bobSharedSecret = encapsulation.sharedSecret;

  // 3. Alice uses her secret key to decapsulate the ciphertext
  final aliceSharedSecret = MlKem.decapsulate(
    ciphertext: ciphertext,
    secretKey: aliceKeyPair.secretKey,
  );

  // Success! Both parties now have the identical secure byte array.
}
```

## 2. Digital Signatures (ML-DSA)

ML-DSA (formerly Dilithium) is used to mathematically prove the authenticity and integrity of a message.

```dart
import 'dart:convert';
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  final message = utf8.encode('Authorize transaction: $1000');

  // 1. Generate signing keys
  final keyPair = MlDsa.generateKeyPair(MlDsaParameterSpec.mlDsa65);

  // 2. Sign the message (Hedged by default for security)
  final signature = MlDsa.sign(
    message: message,
    secretKey: keyPair.secretKey,
    context: utf8.encode('transactions-v1'), // Optional domain separation
  );

  // 3. Verify the signature
  final isValid = MlDsa.verify(
    message: message,
    signature: signature,
    publicKey: keyPair.publicKey,
    context: utf8.encode('transactions-v1'),
  );

  print('Signature valid: $isValid');
}
```

## 3. HashML-DSA (Pre-Hashed Signatures)

If you are signing extremely large files, use `hashSign` to avoid loading the entire file into memory at once.

```dart
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  // ... generate keys ...
  
  // The pre-hash must match the specification (e.g. SHA-384 for ML-DSA-65)
  final fileHash = computeLargeFileHash(); 

  final signature = MlDsa.hashSign(
    preHash: fileHash,
    secretKey: keyPair.secretKey,
    oid: MlDsaOid.sha384, // Explicitly declare the hash used
  );
}
```

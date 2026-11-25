/// HMAC-SHA-256 and HMAC-SHA-512 for internal standards implementations.
///
/// The construction follows FIPS 198-1 / RFC 2104. It is intentionally not
/// exported from the package root.
library;

import 'dart:typed_data';

import 'sha2.dart';
import 'zeroize.dart';

typedef _Digest = Uint8List Function(Uint8List message);

/// Returns HMAC-SHA-256([key], [message]).
Uint8List hmacSha256(Uint8List key, Uint8List message) =>
    _hmac(key, message, blockLength: 64, digest: sha256);

/// Returns HMAC-SHA-512([key], [message]).
Uint8List hmacSha512(Uint8List key, Uint8List message) =>
    _hmac(key, message, blockLength: 128, digest: sha512);

Uint8List _hmac(
  Uint8List key,
  Uint8List message, {
  required int blockLength,
  required _Digest digest,
}) {
  final keyBlock = Uint8List(blockLength);
  final innerInput = Uint8List(blockLength + message.length);
  Uint8List? hashedKey;
  Uint8List? innerDigest;
  Uint8List? outerInput;

  try {
    if (key.length > blockLength) {
      hashedKey = digest(key);
      keyBlock.setRange(0, hashedKey.length, hashedKey);
    } else {
      keyBlock.setRange(0, key.length, key);
    }

    for (var i = 0; i < blockLength; i++) {
      final byte = keyBlock[i];
      innerInput[i] = byte ^ 0x36;
    }
    innerInput.setRange(blockLength, innerInput.length, message);
    innerDigest = digest(innerInput);

    outerInput = Uint8List(blockLength + innerDigest.length);
    for (var i = 0; i < blockLength; i++) {
      outerInput[i] = keyBlock[i] ^ 0x5c;
    }
    outerInput.setRange(blockLength, outerInput.length, innerDigest);
    return digest(outerInput);
  } finally {
    secureZero(keyBlock);
    secureZero(innerInput);
    if (hashedKey != null) secureZero(hashedKey);
    if (innerDigest != null) secureZero(innerDigest);
    if (outerInput != null) secureZero(outerInput);
  }
}

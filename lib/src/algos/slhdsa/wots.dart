import 'dart:typed_data';

import '../../common/zeroize.dart';
import 'address.dart';
import 'hashing.dart';
import 'params.dart';
import 'util.dart';

/// FIPS 205 Algorithms 5-8: WOTS+ chaining, key generation, signing, and
/// public-key recovery.
final class SlhDsaWots {
  SlhDsaWots(this.hashes) : params = hashes.params;

  final SlhDsaHashFunctions hashes;
  final SlhDsaParams params;

  /// FIPS 205 Algorithm 5.
  Uint8List chain(
    Uint8List input,
    int start,
    int steps,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireN(input, 'input');
    _requireN(publicSeed, 'publicSeed');
    if (start < 0 || start >= params.w) {
      throw RangeError.range(start, 0, params.w - 1, 'start');
    }
    if (steps < 0 || start + steps >= params.w) {
      throw RangeError.range(steps, 0, params.w - 1 - start, 'steps');
    }

    return _chainInPlace(input, start, steps, publicSeed, address.copy());
  }

  /// FIPS 205 Algorithm 6.
  Uint8List publicKey(
    Uint8List secretSeed,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');

    final wotsAddress = address.copy();
    final keyPair = wotsAddress.getKeyPairAddress();
    final secretAddress = wotsAddress.copy()
      ..setTypeAndClear(AdrsType.wotsPrf)
      ..setKeyPairAddress(keyPair);
    final publicKeyElements = Uint8List(params.len * params.n);

    try {
      for (var i = 0; i < params.len; i++) {
        secretAddress.setChainAddress(i);
        final secret = hashes.prf(publicSeed, secretSeed, secretAddress);
        try {
          wotsAddress
            ..setTypeAndClear(AdrsType.wotsHash)
            ..setKeyPairAddress(keyPair)
            ..setChainAddress(i);
          final endpoint = _chainInPlace(
            secret,
            0,
            params.w - 1,
            publicSeed,
            wotsAddress,
          );
          try {
            publicKeyElements.setRange(
              i * params.n,
              (i + 1) * params.n,
              endpoint,
            );
          } finally {
            secureZero(endpoint);
          }
        } finally {
          secureZero(secret);
        }
      }

      final publicKeyAddress = address.copy()
        ..setTypeAndClear(AdrsType.wotsPk)
        ..setKeyPairAddress(keyPair);
      return hashes.tLen(publicSeed, publicKeyAddress, publicKeyElements);
    } finally {
      secureZero(publicKeyElements);
    }
  }

  /// FIPS 205 Algorithm 7.
  Uint8List sign(
    Uint8List message,
    Uint8List secretSeed,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireN(message, 'message');
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');

    final digits = _messageDigits(message);
    final wotsAddress = address.copy();
    final keyPair = wotsAddress.getKeyPairAddress();
    final secretAddress = wotsAddress.copy()
      ..setTypeAndClear(AdrsType.wotsPrf)
      ..setKeyPairAddress(keyPair);
    final signature = Uint8List(params.wotsSignatureBytes);

    for (var i = 0; i < params.len; i++) {
      secretAddress.setChainAddress(i);
      final secret = hashes.prf(publicSeed, secretSeed, secretAddress);
      try {
        wotsAddress
          ..setTypeAndClear(AdrsType.wotsHash)
          ..setKeyPairAddress(keyPair)
          ..setChainAddress(i);
        final element = _chainInPlace(
          secret,
          0,
          digits[i],
          publicSeed,
          wotsAddress,
        );
        try {
          signature.setRange(i * params.n, (i + 1) * params.n, element);
        } finally {
          secureZero(element);
        }
      } finally {
        secureZero(secret);
      }
    }
    return signature;
  }

  /// FIPS 205 Algorithm 8.
  Uint8List publicKeyFromSignature(
    Uint8List signature,
    Uint8List message,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireLength(signature, params.wotsSignatureBytes, 'signature');
    _requireN(message, 'message');
    _requireN(publicSeed, 'publicSeed');

    final digits = _messageDigits(message);
    final wotsAddress = address.copy();
    final keyPair = wotsAddress.getKeyPairAddress();
    final publicKeyElements = Uint8List(params.len * params.n);

    try {
      for (var i = 0; i < params.len; i++) {
        wotsAddress
          ..setTypeAndClear(AdrsType.wotsHash)
          ..setKeyPairAddress(keyPair)
          ..setChainAddress(i);
        final element = _chainInPlace(
          Uint8List.sublistView(signature, i * params.n, (i + 1) * params.n),
          digits[i],
          params.w - 1 - digits[i],
          publicSeed,
          wotsAddress,
        );
        try {
          publicKeyElements.setRange(i * params.n, (i + 1) * params.n, element);
        } finally {
          secureZero(element);
        }
      }

      final publicKeyAddress = address.copy()
        ..setTypeAndClear(AdrsType.wotsPk)
        ..setKeyPairAddress(keyPair);
      return hashes.tLen(publicSeed, publicKeyAddress, publicKeyElements);
    } finally {
      secureZero(publicKeyElements);
    }
  }

  Uint8List _chainInPlace(
    Uint8List input,
    int start,
    int steps,
    Uint8List publicSeed,
    Adrs address,
  ) {
    var current = Uint8List.fromList(input);
    for (var j = start; j < start + steps; j++) {
      address.setHashAddress(j);
      final next = hashes.f(publicSeed, address, current);
      secureZero(current);
      current = next;
    }
    return current;
  }

  List<int> _messageDigits(Uint8List message) {
    final messageDigits = base2b(message, params.lgW, params.len1);
    var checksum = 0;
    for (final digit in messageDigits) {
      checksum += params.w - 1 - digit;
    }

    final checksumBits = params.len2 * params.lgW;
    checksum <<= (8 - checksumBits % 8) % 8;
    final checksumBytes = toByte(
      BigInt.from(checksum),
      (checksumBits + 7) ~/ 8,
    );
    final digits = List<int>.filled(params.len, 0);
    digits.setRange(0, params.len1, messageDigits);
    digits.setRange(
      params.len1,
      params.len,
      base2b(checksumBytes, params.lgW, params.len2),
    );
    return digits;
  }

  void _requireN(Uint8List value, String name) {
    _requireLength(value, params.n, name);
  }

  void _requireLength(Uint8List value, int length, String name) {
    if (value.length != length) {
      throw ArgumentError.value(
        value.length,
        '$name.length',
        'must be exactly $length',
      );
    }
  }
}

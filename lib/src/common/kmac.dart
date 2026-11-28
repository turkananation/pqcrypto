/// KMAC128, KMAC256, KMACXOF128, and KMACXOF256 from NIST SP 800-185.
///
/// Fixed-output [Kmac128] and [Kmac256] append `right_encode(L)`.
/// [KmacXof128] and [KmacXof256] append `right_encode(0)`. The function-name
/// string is `KMAC`. Public output length is in bytes. This is not HMAC.
///
/// Not a CMVP or FIPS 140 claim.
library;

import 'dart:typed_data';

import 'keccak_parameters.dart';
import 'sp800_185.dart';
import 'zeroize.dart';

/// ASCII `KMAC`. Not a secret.
final Uint8List _functionName = Uint8List.fromList(const <int>[
  0x4b,
  0x4d,
  0x41,
  0x43,
]);

const int _minimumTagBytes = 8;

typedef _CShakeHash =
    Uint8List Function(
      Uint8List message, {
      required int outputLength,
      Uint8List? functionName,
      Uint8List? customization,
    });

/// KMAC128 from NIST SP 800-185.
///
/// [minimumRecommendedKeyBytes] is 16 and [minimumRecommendedTagBytes] is 8.
/// A shorter key or tag is allowed unless [Kmac128.mac] is called with
/// `checked: true`, which rejects it before any output. Keccak-f[1600] stays
/// on the 32-bit lane implementation in `keccak.dart`.
final class Kmac128 {
  Kmac128._();

  static const int minimumRecommendedKeyBytes = 16;

  static const int minimumRecommendedTagBytes = _minimumTagBytes;

  /// Returns [outputLength] bytes of KMAC128.
  ///
  /// A negative [outputLength] throws [RangeError] before any output.
  /// [customization] defaults to empty. [checked] enforces
  /// [minimumRecommendedKeyBytes] and [minimumRecommendedTagBytes].
  static Uint8List mac(
    Uint8List key,
    Uint8List message, {
    required int outputLength,
    Uint8List? customization,
    bool checked = false,
  }) {
    return _kmac(
      key,
      message,
      outputLength: outputLength,
      customization: customization,
      checked: checked,
      minimumKeyBytes: minimumRecommendedKeyBytes,
      rateBytes: Fips202Parameters.shake128.rateBytes,
      xof: false,
      hash: CShake128.hash,
    );
  }
}

/// KMAC256 from NIST SP 800-185.
///
/// Same contract as [Kmac128]. [minimumRecommendedKeyBytes] is 32.
final class Kmac256 {
  Kmac256._();

  static const int minimumRecommendedKeyBytes = 32;

  static const int minimumRecommendedTagBytes = _minimumTagBytes;

  /// Returns [outputLength] bytes of KMAC256.
  static Uint8List mac(
    Uint8List key,
    Uint8List message, {
    required int outputLength,
    Uint8List? customization,
    bool checked = false,
  }) {
    return _kmac(
      key,
      message,
      outputLength: outputLength,
      customization: customization,
      checked: checked,
      minimumKeyBytes: minimumRecommendedKeyBytes,
      rateBytes: Fips202Parameters.shake256.rateBytes,
      xof: false,
      hash: CShake256.hash,
    );
  }
}

/// KMACXOF128 from NIST SP 800-185.
///
/// Same key and tag guidance as [Kmac128]. The encoded length is
/// `right_encode(0)`, not `right_encode(L)`.
final class KmacXof128 {
  KmacXof128._();

  static const int minimumRecommendedKeyBytes =
      Kmac128.minimumRecommendedKeyBytes;

  static const int minimumRecommendedTagBytes = _minimumTagBytes;

  /// Returns [outputLength] bytes of KMACXOF128.
  static Uint8List mac(
    Uint8List key,
    Uint8List message, {
    required int outputLength,
    Uint8List? customization,
    bool checked = false,
  }) {
    return _kmac(
      key,
      message,
      outputLength: outputLength,
      customization: customization,
      checked: checked,
      minimumKeyBytes: minimumRecommendedKeyBytes,
      rateBytes: Fips202Parameters.shake128.rateBytes,
      xof: true,
      hash: CShake128.hash,
    );
  }
}

/// KMACXOF256 from NIST SP 800-185.
///
/// Same contract as [KmacXof128]. [minimumRecommendedKeyBytes] is 32.
final class KmacXof256 {
  KmacXof256._();

  static const int minimumRecommendedKeyBytes =
      Kmac256.minimumRecommendedKeyBytes;

  static const int minimumRecommendedTagBytes = _minimumTagBytes;

  /// Returns [outputLength] bytes of KMACXOF256.
  static Uint8List mac(
    Uint8List key,
    Uint8List message, {
    required int outputLength,
    Uint8List? customization,
    bool checked = false,
  }) {
    return _kmac(
      key,
      message,
      outputLength: outputLength,
      customization: customization,
      checked: checked,
      minimumKeyBytes: minimumRecommendedKeyBytes,
      rateBytes: Fips202Parameters.shake256.rateBytes,
      xof: true,
      hash: CShake256.hash,
    );
  }
}

Uint8List _kmac(
  Uint8List key,
  Uint8List message, {
  required int outputLength,
  required Uint8List? customization,
  required bool checked,
  required int minimumKeyBytes,
  required int rateBytes,
  required bool xof,
  required _CShakeHash hash,
}) {
  if (outputLength < 0) {
    throw RangeError.range(outputLength, 0, null, 'outputLength');
  }
  final outputBits = _exactOutputBits(outputLength);
  if (checked) {
    if (key.length < minimumKeyBytes) {
      throw ArgumentError.value(
        key.length,
        'key',
        'shorter than minimumRecommendedKeyBytes',
      );
    }
    if (outputLength < _minimumTagBytes) {
      throw ArgumentError.value(
        outputLength,
        'outputLength',
        'shorter than minimumRecommendedTagBytes',
      );
    }
  }

  Uint8List? encodedKey;
  Uint8List? paddedKey;
  Uint8List? encodedLength;
  Uint8List? input;
  try {
    encodedKey = encodeString(key);
    paddedKey = bytepad(encodedKey, rateBytes);
    encodedLength = rightEncode(xof ? 0 : outputBits);
    input = _concat3(paddedKey, message, encodedLength);
    return hash(
      input,
      outputLength: outputLength,
      functionName: _functionName,
      customization: customization,
    );
  } finally {
    secureZero(encodedKey);
    secureZero(paddedKey);
    secureZero(encodedLength);
    secureZero(input);
  }
}

int _exactOutputBits(int outputLength) {
  if (outputLength == 0) return 0;
  if (outputLength.bitLength + 3 > 2040) {
    throw ArgumentError.value(
      outputLength,
      'outputLength',
      'bit length must satisfy 0 <= L < 2^2040',
    );
  }
  final bits = outputLength * 8;
  if (bits ~/ 8 != outputLength) {
    throw ArgumentError.value(
      outputLength,
      'outputLength',
      'bit length is not exact',
    );
  }
  return bits;
}

Uint8List _concat3(Uint8List first, Uint8List second, Uint8List third) {
  final out = Uint8List(first.length + second.length + third.length);
  var offset = 0;
  out.setRange(offset, offset + first.length, first);
  offset += first.length;
  out.setRange(offset, offset + second.length, second);
  offset += second.length;
  out.setRange(offset, offset + third.length, third);
  return out;
}

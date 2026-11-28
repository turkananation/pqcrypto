/// TupleHash128, TupleHash256, TupleHashXOF128, and TupleHashXOF256.
///
/// Each element is `encode_string`, including empty elements. Fixed-output
/// [TupleHash128] and [TupleHash256] append `right_encode(L)`.
/// [TupleHashXof128] and [TupleHashXof256] append `right_encode(0)`. The
/// function-name string is `TupleHash`. Public output length is in bytes.
///
/// Not a CMVP or FIPS 140 claim.
library;

import 'dart:typed_data';

import 'keccak_parameters.dart';
import 'sp800_185.dart';
import 'zeroize.dart';

/// ASCII `TupleHash`. Not a secret.
final Uint8List _functionName = Uint8List.fromList(const <int>[
  0x54,
  0x75,
  0x70,
  0x6c,
  0x65,
  0x48,
  0x61,
  0x73,
  0x68,
]);

typedef _CShakeHash =
    Uint8List Function(
      Uint8List message, {
      required int outputLength,
      Uint8List? functionName,
      Uint8List? customization,
    });

/// TupleHash128 from NIST SP 800-185.
final class TupleHash128 {
  TupleHash128._();

  /// Returns [outputLength] bytes of TupleHash128 over [elements].
  ///
  /// A negative [outputLength] throws [RangeError] before any output.
  /// Empty elements are encoded. [customization] defaults to empty.
  static Uint8List hash(
    List<Uint8List> elements, {
    required int outputLength,
    Uint8List? customization,
  }) {
    return _tupleHash(
      elements,
      outputLength: outputLength,
      customization: customization,
      rateBytes: Fips202Parameters.shake128.rateBytes,
      xof: false,
      hash: CShake128.hash,
    );
  }
}

/// TupleHash256 from NIST SP 800-185.
///
/// Same contract as [TupleHash128]. The rate is 136 bytes.
final class TupleHash256 {
  TupleHash256._();

  /// Returns [outputLength] bytes of TupleHash256 over [elements].
  static Uint8List hash(
    List<Uint8List> elements, {
    required int outputLength,
    Uint8List? customization,
  }) {
    return _tupleHash(
      elements,
      outputLength: outputLength,
      customization: customization,
      rateBytes: Fips202Parameters.shake256.rateBytes,
      xof: false,
      hash: CShake256.hash,
    );
  }
}

/// TupleHashXOF128 from NIST SP 800-185.
///
/// Same tuple encoding as [TupleHash128]. The encoded length is
/// `right_encode(0)`.
final class TupleHashXof128 {
  TupleHashXof128._();

  /// Returns [outputLength] bytes of TupleHashXOF128 over [elements].
  static Uint8List hash(
    List<Uint8List> elements, {
    required int outputLength,
    Uint8List? customization,
  }) {
    return _tupleHash(
      elements,
      outputLength: outputLength,
      customization: customization,
      rateBytes: Fips202Parameters.shake128.rateBytes,
      xof: true,
      hash: CShake128.hash,
    );
  }
}

/// TupleHashXOF256 from NIST SP 800-185.
///
/// Same contract as [TupleHashXof128]. The rate is 136 bytes.
final class TupleHashXof256 {
  TupleHashXof256._();

  /// Returns [outputLength] bytes of TupleHashXOF256 over [elements].
  static Uint8List hash(
    List<Uint8List> elements, {
    required int outputLength,
    Uint8List? customization,
  }) {
    return _tupleHash(
      elements,
      outputLength: outputLength,
      customization: customization,
      rateBytes: Fips202Parameters.shake256.rateBytes,
      xof: true,
      hash: CShake256.hash,
    );
  }
}

Uint8List _tupleHash(
  List<Uint8List> elements, {
  required int outputLength,
  required Uint8List? customization,
  required int rateBytes,
  required bool xof,
  required _CShakeHash hash,
}) {
  if (outputLength < 0) {
    throw RangeError.range(outputLength, 0, null, 'outputLength');
  }
  final outputBits = _exactOutputBits(outputLength);
  final encoded = <Uint8List>[];
  Uint8List? encodedLength;
  Uint8List? input;
  try {
    var total = 0;
    for (final element in elements) {
      final piece = encodeString(element);
      encoded.add(piece);
      total += piece.length;
    }
    encodedLength = rightEncode(xof ? 0 : outputBits);
    total += encodedLength.length;
    input = Uint8List(total);
    var offset = 0;
    for (final piece in encoded) {
      input.setRange(offset, offset + piece.length, piece);
      offset += piece.length;
    }
    input.setRange(offset, offset + encodedLength.length, encodedLength);
    return hash(
      input,
      outputLength: outputLength,
      functionName: _functionName,
      customization: customization,
    );
  } finally {
    for (final piece in encoded) {
      secureZero(piece);
    }
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

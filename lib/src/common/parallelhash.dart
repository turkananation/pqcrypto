/// ParallelHash128, ParallelHash256, and their XOF forms.
///
/// Each block is cSHAKE with an empty function name and customization, so
/// that step is SHAKE. The outer call uses the function-name string
/// `ParallelHash`. Blocks are hashed in order. This is the SP 800-185
/// transcript, not a claim that the first release is faster than SHAKE.
///
/// Public output length is in bytes. Not a CMVP or FIPS 140 claim.
library;

import 'dart:typed_data';

import 'sp800_185.dart';
import 'zeroize.dart';

/// ASCII `ParallelHash`. Not a secret.
final Uint8List _functionName = Uint8List.fromList(const <int>[
  0x50, 0x61, 0x72, 0x61, 0x6c, 0x6c, 0x65, 0x6c, //
  0x48, 0x61, 0x73, 0x68,
]);

const int _innerBytes128 = 32;
const int _innerBytes256 = 64;

typedef _CShakeHash =
    Uint8List Function(
      Uint8List message, {
      required int outputLength,
      Uint8List? functionName,
      Uint8List? customization,
    });

/// ParallelHash128 from NIST SP 800-185.
///
/// [hash] takes [blockSize] in bytes. `blockSize <= 0` throws [ArgumentError]
/// before any output. The inner digest is 32 bytes.
final class ParallelHash128 {
  ParallelHash128._();

  /// Returns [outputLength] bytes of ParallelHash128.
  ///
  /// A negative [outputLength] throws [RangeError] before any output.
  /// [customization] defaults to empty.
  static Uint8List hash(
    Uint8List message, {
    required int blockSize,
    required int outputLength,
    Uint8List? customization,
  }) {
    return _parallelHash(
      message,
      blockSize: blockSize,
      outputLength: outputLength,
      customization: customization,
      innerBytes: _innerBytes128,
      xof: false,
      hash: CShake128.hash,
    );
  }
}

/// ParallelHash256 from NIST SP 800-185.
///
/// Same contract as [ParallelHash128]. The inner digest is 64 bytes.
final class ParallelHash256 {
  ParallelHash256._();

  /// Returns [outputLength] bytes of ParallelHash256.
  static Uint8List hash(
    Uint8List message, {
    required int blockSize,
    required int outputLength,
    Uint8List? customization,
  }) {
    return _parallelHash(
      message,
      blockSize: blockSize,
      outputLength: outputLength,
      customization: customization,
      innerBytes: _innerBytes256,
      xof: false,
      hash: CShake256.hash,
    );
  }
}

/// ParallelHashXOF128 from NIST SP 800-185.
///
/// Same block rules as [ParallelHash128]. The encoded output length is
/// `right_encode(0)`.
final class ParallelHashXof128 {
  ParallelHashXof128._();

  /// Returns [outputLength] bytes of ParallelHashXOF128.
  static Uint8List hash(
    Uint8List message, {
    required int blockSize,
    required int outputLength,
    Uint8List? customization,
  }) {
    return _parallelHash(
      message,
      blockSize: blockSize,
      outputLength: outputLength,
      customization: customization,
      innerBytes: _innerBytes128,
      xof: true,
      hash: CShake128.hash,
    );
  }
}

/// ParallelHashXOF256 from NIST SP 800-185.
///
/// Same contract as [ParallelHashXof128]. The inner digest is 64 bytes.
final class ParallelHashXof256 {
  ParallelHashXof256._();

  /// Returns [outputLength] bytes of ParallelHashXOF256.
  static Uint8List hash(
    Uint8List message, {
    required int blockSize,
    required int outputLength,
    Uint8List? customization,
  }) {
    return _parallelHash(
      message,
      blockSize: blockSize,
      outputLength: outputLength,
      customization: customization,
      innerBytes: _innerBytes256,
      xof: true,
      hash: CShake256.hash,
    );
  }
}

Uint8List _parallelHash(
  Uint8List message, {
  required int blockSize,
  required int outputLength,
  required Uint8List? customization,
  required int innerBytes,
  required bool xof,
  required _CShakeHash hash,
}) {
  if (blockSize <= 0) {
    throw ArgumentError.value(blockSize, 'blockSize', 'must be positive');
  }
  if (outputLength < 0) {
    throw RangeError.range(outputLength, 0, null, 'outputLength');
  }
  final outputBits = _exactOutputBits(outputLength);
  final blocks = message.isEmpty
      ? 0
      : (message.length + blockSize - 1) ~/ blockSize;

  Uint8List? encodedBlockSize;
  Uint8List? encodedCount;
  Uint8List? encodedLength;
  Uint8List? input;
  final inners = <Uint8List>[];
  try {
    encodedBlockSize = leftEncode(blockSize);
    encodedCount = rightEncode(blocks);
    encodedLength = rightEncode(xof ? 0 : outputBits);
    final total =
        encodedBlockSize.length +
        (blocks * innerBytes) +
        encodedCount.length +
        encodedLength.length;
    input = Uint8List(total);
    var offset = 0;
    input.setRange(0, encodedBlockSize.length, encodedBlockSize);
    offset = encodedBlockSize.length;
    for (var i = 0; i < blocks; i++) {
      final start = i * blockSize;
      final end = start + blockSize < message.length
          ? start + blockSize
          : message.length;
      final inner = hash(
        Uint8List.sublistView(message, start, end),
        outputLength: innerBytes,
      );
      inners.add(inner);
      input.setRange(offset, offset + inner.length, inner);
      offset += inner.length;
    }
    input.setRange(offset, offset + encodedCount.length, encodedCount);
    offset += encodedCount.length;
    input.setRange(offset, offset + encodedLength.length, encodedLength);
    return hash(
      input,
      outputLength: outputLength,
      functionName: _functionName,
      customization: customization,
    );
  } finally {
    secureZero(encodedBlockSize);
    secureZero(encodedCount);
    secureZero(encodedLength);
    for (final inner in inners) {
      secureZero(inner);
    }
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

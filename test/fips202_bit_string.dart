import 'dart:typed_data';

/// Test-only FIPS 202 bit string: a byte buffer plus a bit length.
///
/// [bytes] is packed in absorption order. The first bit is the least
/// significant bit of the first byte. [bitLength] counts the valid bits.
/// This type is not exported from `package:pqcrypto/pqcrypto.dart`. The
/// public hash APIs stay byte-only.
final class BitString {
  const BitString(this.bytes, this.bitLength);

  final Uint8List bytes;
  final int bitLength;

  /// Packs [bits] in the order NIST prints them for absorption.
  factory BitString.fromAbsorptionBits(String bits) {
    final packed = Uint8List((bits.length + 7) >> 3);
    for (var i = 0; i < bits.length; i++) {
      switch (bits.codeUnitAt(i)) {
        case 0x30:
          break;
        case 0x31:
          packed[i >> 3] |= 1 << (i & 7);
          break;
        default:
          throw FormatException('message bit is not 0 or 1');
      }
    }
    return BitString(packed, bits.length);
  }

  /// Absorption-order bits, one entry per bit, each entry 0 or 1.
  List<int> absorptionBits() {
    if (bitLength < 0) {
      throw ArgumentError.value(bitLength, 'bitLength', 'must be >= 0');
    }
    final byteLength = (bitLength + 7) >> 3;
    if (bytes.length < byteLength) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'need $byteLength bytes for $bitLength bits',
      );
    }
    return <int>[
      for (var i = 0; i < bitLength; i++) (bytes[i >> 3] >> (i & 7)) & 1,
    ];
  }
}

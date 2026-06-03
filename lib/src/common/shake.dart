import 'dart:typed_data';

import 'keccak.dart';

class Shake128 {
  /// Absorb input and squeeze output bytes.
  static Uint8List shake(Uint8List input, int outputLength) =>
      shake128(input, outputLength);
}

class Shake256 {
  static Uint8List shake(Uint8List input, int outputLength) =>
      shake256(input, outputLength);
}

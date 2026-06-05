import 'dart:typed_data';

import 'keccak.dart';

class Shake128 {
  /// Absorb input and squeeze [outputLength] output bytes (one-shot).
  static Uint8List shake(Uint8List input, int outputLength) =>
      shake128(input, outputLength);

  /// Incremental SHAKE128 XOF for unbounded rejection sampling.
  static KeccakXof xof(Uint8List input) => shake128Xof(input);
}

class Shake256 {
  /// Absorb input and squeeze [outputLength] output bytes (one-shot).
  static Uint8List shake(Uint8List input, int outputLength) =>
      shake256(input, outputLength);

  /// Incremental SHAKE256 XOF for unbounded rejection sampling.
  static KeccakXof xof(Uint8List input) => shake256Xof(input);
}

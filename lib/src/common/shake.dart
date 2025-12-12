import 'dart:typed_data';
import 'package:pointycastle/export.dart';

class Shake128 {
  /// Absorb input and squeeze output bytes.
  static Uint8List shake(Uint8List input, int outputLength) {
    final shake = SHAKEDigest(128); // SHAKE128
    shake.update(input, 0, input.length);
    final out = Uint8List(outputLength);
    shake.doFinal(out, 0);
    return out;
  }
}

import 'dart:typed_data';

import 'package:pqcrypto/src/common/zeroize.dart';
import 'package:test/test.dart';

void main() {
  test('zeroization helpers overwrite each supported typed buffer', () {
    final bytes = Uint8List.fromList(<int>[1, 2, 3]);
    final signedWords = Int32List.fromList(<int>[-1, 2, -3]);
    final unsignedWords = Uint32List.fromList(<int>[1, 0xffffffff, 3]);

    secureZero(bytes);
    secureZeroInt32(signedWords);
    secureZeroUint32(unsignedWords);

    expect(bytes, everyElement(0));
    expect(signedWords, everyElement(0));
    expect(unsignedWords, everyElement(0));
  });

  test('zeroization helpers accept null', () {
    expect(() => secureZero(null), returnsNormally);
    expect(() => secureZeroInt32(null), returnsNormally);
    expect(() => secureZeroUint32(null), returnsNormally);
  });
}

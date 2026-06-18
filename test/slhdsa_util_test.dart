import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/util.dart';
import 'package:test/test.dart';

List<int> _referenceBase2b(Uint8List input, int b, int outputLength) {
  return List<int>.generate(outputLength, (outputIndex) {
    var value = 0;
    for (var bit = 0; bit < b; bit++) {
      final bitIndex = outputIndex * b + bit;
      final byte = input[bitIndex ~/ 8];
      value = (value << 1) | ((byte >> (7 - bitIndex % 8)) & 1);
    }
    return value;
  });
}

void main() {
  group('toInt/toByte', () {
    test('known big-endian encodings', () {
      expect(
        toInt(Uint8List.fromList(<int>[0x01, 0x23, 0x45])),
        BigInt.from(0x012345),
      );
      expect(toByte(BigInt.from(0x012345), 3), equals(<int>[0x01, 0x23, 0x45]));
      expect(toByte(BigInt.zero, 0), isEmpty);
      expect(toInt(Uint8List(0)), BigInt.zero);
    });

    test('exhaustive two-byte round-trip', () {
      for (var value = 0; value <= 0xffff; value++) {
        final encoded = toByte(BigInt.from(value), 2);
        expect(toInt(encoded), BigInt.from(value));
      }
    });

    test('values beyond JavaScript exact-int range remain exact', () {
      final value = BigInt.parse('fedcba9876543210', radix: 16);
      final encoded = toByte(value, 8);
      expect(
        encoded,
        equals(<int>[0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
      );
      expect(toInt(encoded), value);
    });

    test('invalid values and lengths are rejected', () {
      expect(() => toByte(BigInt.from(-1), 1), throwsArgumentError);
      expect(() => toByte(BigInt.zero, -1), throwsRangeError);
      expect(() => toByte(BigInt.from(0x100), 1), throwsRangeError);
      expect(() => toByte(BigInt.one, 0), throwsRangeError);
    });
  });

  group('base2b', () {
    test('known WOTS+ and FORS extractions', () {
      final input = Uint8List.fromList(<int>[0xab, 0xcd, 0xef]);
      expect(base2b(input, 4, 6), equals(<int>[10, 11, 12, 13, 14, 15]));
      expect(base2b(input, 6, 4), equals(<int>[42, 60, 55, 47]));
      expect(base2b(input, 12, 2), equals(<int>[0xabc, 0xdef]));
    });

    test('matches independent bit-by-bit reference across widths', () {
      final input = Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 73 + 19) & 0xff),
      );
      for (var b = 1; b <= 16; b++) {
        final outputLength = (input.length * 8) ~/ b;
        expect(
          base2b(input, b, outputLength),
          equals(_referenceBase2b(input, b, outputLength)),
          reason: 'b=$b',
        );
      }
    });

    test('empty output and invalid requests', () {
      expect(base2b(Uint8List(0), 4, 0), isEmpty);
      expect(() => base2b(Uint8List(1), 0, 1), throwsArgumentError);
      expect(() => base2b(Uint8List(1), 17, 1), throwsArgumentError);
      expect(() => base2b(Uint8List(1), 4, -1), throwsRangeError);
      expect(() => base2b(Uint8List(1), 5, 2), throwsArgumentError);
    });
  });

  group('genLen2/truncN', () {
    test('FIPS 205 sets all derive len2 = 3', () {
      for (final n in <int>[16, 24, 32]) {
        expect(genLen2(n, 4), 3, reason: 'n=$n');
      }
    });

    test('genLen2 validates inputs', () {
      expect(() => genLen2(0, 4), throwsArgumentError);
      expect(() => genLen2(16, 0), throwsArgumentError);
      expect(() => genLen2(16, 9), throwsArgumentError);
    });

    test('truncN returns an independent leftmost-byte copy', () {
      final input = Uint8List.fromList(<int>[1, 2, 3, 4]);
      final output = truncN(input, 2);
      expect(output, equals(<int>[1, 2]));
      output[0] = 9;
      expect(input, equals(<int>[1, 2, 3, 4]));
      expect(truncN(input, 0), isEmpty);
      expect(truncN(input, input.length), equals(input));
    });

    test('truncN rejects invalid lengths', () {
      final input = Uint8List(2);
      expect(() => truncN(input, -1), throwsRangeError);
      expect(() => truncN(input, 3), throwsRangeError);
    });
  });
}

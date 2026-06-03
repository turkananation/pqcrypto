import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/kyber/pack.dart';
import 'package:pqcrypto/src/common/poly.dart';

void main() {
  group('FIPS 203 Serialization', () {
    test('compress/decompress round-trip', () {
      // Test various compression levels
      for (final d in [1, 4, 5, 10, 11]) {
        for (int x = 0; x < 3329; x += 100) {
          final compressed = Pack.compress(x, d);
          final decompressed = Pack.decompress(compressed, d);

          // Compression is modulo q, so values near q can wrap back to 0.
          final error = _modularDistance(x, decompressed);
          expect(
            error <= _compressionErrorLimit(d),
            isTrue,
            reason:
                'd=$d, x=$x, compressed=$compressed, decompressed=$decompressed, error=$error',
          );
        }
      }
    });

    test('ByteEncode12/ByteDecode12 round-trip', () {
      final coeffs = List<int>.generate(256, (i) => (i * 13) % 3329);
      final poly = Poly(coeffs);

      final encoded = Pack.byteEncode12(poly);
      expect(encoded.length, 384);

      final decoded = Pack.byteDecode12(encoded);
      expect(decoded.coeffs, equals(poly.coeffs));
    });

    test('CompressAndEncode10/DecodeAndDecompress10 round-trip', () {
      final coeffs = List<int>.generate(256, (i) => (i * 17) % 3329);
      final poly = Poly(coeffs);

      final encoded = Pack.compressAndEncode10(poly);
      expect(encoded.length, 320);

      final decoded = Pack.decodeAndDecompress10(encoded);

      // Check all coefficients within compression error
      for (int i = 0; i < 256; i++) {
        _expectCompressionClose(poly.coeffs[i], decoded.coeffs[i], 10, 'i=$i');
      }
    });

    test('CompressAndEncode4/DecodeAndDecompress4 round-trip', () {
      final coeffs = List<int>.generate(256, (i) => (i * 19) % 3329);
      final poly = Poly(coeffs);

      final encoded = Pack.compressAndEncode4(poly);
      expect(encoded.length, 128);

      final decoded = Pack.decodeAndDecompress4(encoded);

      // Check all coefficients within compression error
      for (int i = 0; i < 256; i++) {
        _expectCompressionClose(poly.coeffs[i], decoded.coeffs[i], 4, 'i=$i');
      }
    });

    test('CompressAndEncode1/DecodeAndDecompress1 round-trip', () {
      final coeffs = List<int>.generate(256, (i) => i < 128 ? 0 : 1665);
      final poly = Poly(coeffs);

      final encoded = Pack.compressAndEncode1(poly);
      expect(encoded.length, 32);

      final decoded = Pack.decodeAndDecompress1(encoded);

      // For 1-bit compression, values map to 0 or ⌈q/2⌋
      for (int i = 0; i < 256; i++) {
        final expected = i < 128 ? 0 : 1665;
        expect(decoded.coeffs[i], expected);
      }
    });

    test('CompressAndEncode11/DecodeAndDecompress11 round-trip', () {
      final coeffs = List<int>.generate(256, (i) => (i * 23) % 3329);
      final poly = Poly(coeffs);

      final encoded = Pack.compressAndEncode11(poly);
      expect(encoded.length, 352);

      final decoded = Pack.decodeAndDecompress11(encoded);

      // Check all coefficients within compression error (should be very small for d=11)
      for (int i = 0; i < 256; i++) {
        _expectCompressionClose(poly.coeffs[i], decoded.coeffs[i], 11, 'i=$i');
      }
    });

    test('CompressAndEncode5/DecodeAndDecompress5 round-trip', () {
      final coeffs = List<int>.generate(256, (i) => (i * 29) % 3329);
      final poly = Poly(coeffs);

      final encoded = Pack.compressAndEncode5(poly);
      expect(encoded.length, 160);

      final decoded = Pack.decodeAndDecompress5(encoded);

      // Check all coefficients within compression error
      for (int i = 0; i < 256; i++) {
        _expectCompressionClose(poly.coeffs[i], decoded.coeffs[i], 5, 'i=$i');
      }
    });

    test('compression round-trip handles modular wrap boundary cases', () {
      for (final case_ in [
        (d: 1, x: 2500),
        (d: 4, x: (170 * 19) % Pack.q),
        (d: 5, x: (113 * 29) % Pack.q),
        (d: 10, x: Pack.q - 1),
        (d: 11, x: Pack.q - 1),
      ]) {
        final compressed = Pack.compress(case_.x, case_.d);
        final decompressed = Pack.decompress(compressed, case_.d);
        _expectCompressionClose(
          case_.x,
          decompressed,
          case_.d,
          'd=${case_.d}, x=${case_.x}, compressed=$compressed',
        );
      }
    });
  });
}

int _compressionErrorLimit(int d) {
  final denominator = 1 << (d + 1);
  return (Pack.q + denominator - 1) ~/ denominator;
}

int _modularDistance(int a, int b) {
  final distance = (a - b).abs();
  return distance <= Pack.q - distance ? distance : Pack.q - distance;
}

void _expectCompressionClose(int expected, int actual, int d, String context) {
  final error = _modularDistance(expected, actual);
  expect(
    error <= _compressionErrorLimit(d),
    isTrue,
    reason:
        '$context, d=$d, expected=$expected, actual=$actual, error=$error, '
        'limit=${_compressionErrorLimit(d)}',
  );
}

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

          // Should be approximately equal (within compression error)
          final error = (x - decompressed).abs();
          expect(
            error <= (3329 ~/ (1 << d)) + 1,
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
        final error = (poly.coeffs[i] - decoded.coeffs[i]).abs();
        expect(error < 10, isTrue, reason: 'i=$i, error=$error');
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
        final error = (poly.coeffs[i] - decoded.coeffs[i]).abs();
        expect(error < 250, isTrue, reason: 'i=$i, error=$error');
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
        final error = (poly.coeffs[i] - decoded.coeffs[i]).abs();
        expect(
          error <= 2,
          isTrue,
          reason: 'i=$i, error=$error',
        ); // 3329 / 2048 ≈ 1.6
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
        final error = (poly.coeffs[i] - decoded.coeffs[i]).abs();
        expect(
          error < 150,
          isTrue,
          reason: 'i=$i, error=$error',
        ); // 3329 / 32 ≈ 104
      }
    });
  });
}

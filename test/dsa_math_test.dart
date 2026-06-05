import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/poly.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  group('Dilithium Math', () {
    test('Modulus constant is correct', () {
      expect(q, 8380417);
    });

    test('DilithiumPoly reduce works', () {
      final coeffs = Int32List(n);
      coeffs[0] = q + 5;
      coeffs[1] = -5;
      final poly = DilithiumPoly(coeffs);
      poly.reduce();

      expect(poly.coeffs[0], 5);
      expect(poly.coeffs[1], q - 5);
    });

    test('DilithiumPoly addition works', () {
      final p1 = DilithiumPoly.zero();
      p1.coeffs[0] = q - 10;
      final p2 = DilithiumPoly.zero();
      p2.coeffs[0] = 20;

      final res = p1 + p2;
      expect(res.coeffs[0], 10); // (q-10 + 20) % q = 10
    });

    test('DilithiumPoly multiplication limits (JS safe)', () {
      final p1 = DilithiumPoly.zero();
      p1.coeffs[0] = q - 1;
      final p2 = DilithiumPoly.zero();
      p2.coeffs[0] = q - 1;

      final res = p1.pointwiseMul(p2);
      expect(res.coeffs[0], 1); // (-1 * -1) % q = 1
    });
  });
}

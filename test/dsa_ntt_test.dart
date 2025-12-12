import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/poly.dart';
import 'package:pqcrypto/src/algos/dilithium/ntt.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart'; // for q

void main() {
  group('Dilithium NTT', () {
    test('NTT Round Trip (All Zeros)', () {
      final p = DilithiumPoly.zero();
      DilithiumNTT.ntt(p);
      bool allZero = p.coeffs.every((c) => c == 0);
      expect(allZero, isTrue, reason: "NTT(0) should be 0");

      DilithiumNTT.invNtt(p);
      allZero = p.coeffs.every((c) => c == 0);
      expect(allZero, isTrue, reason: "InvNTT(0) should be 0");
    });

    test('NTT Round Trip (Random)', () {
      final rng = Random();
      final coeffs = Int32List(256);
      for (int i = 0; i < 256; i++) {
        coeffs[i] = rng.nextInt(q);
      }
      final original = Int32List.fromList(coeffs);

      final p = DilithiumPoly(coeffs);

      // Forward
      DilithiumNTT.ntt(p);

      // Check it changed
      bool changed = false;
      for (int i = 0; i < 256; i++) {
        if (p.coeffs[i] != original[i]) changed = true;
      }
      expect(changed, isTrue, reason: "NTT should transform coefficients");

      // Inverse
      DilithiumNTT.invNtt(p);

      // Check for strict equality
      for (int i = 0; i < 256; i++) {
        expect(p.coeffs[i], original[i], reason: "Mismatch at index $i");
      }
    });
  });
}

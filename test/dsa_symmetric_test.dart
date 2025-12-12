import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/symmetric.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  group('Dilithium Symmetric', () {
    test('CRH Output Length', () {
      final seed = Uint8List(32);
      final hash = DilithiumSymmetric.crh(seed);
      expect(hash.length, 64);
    });

    test('ExpandA generates correct structure', () {
      final rho = Uint8List(32);
      rho.fillRange(0, 32, 42); // Seed

      final k = 4;
      final l = 4;

      final A = DilithiumSymmetric.expandA(rho, k, l);

      expect(A.length, k);
      for (int i = 0; i < k; i++) {
        expect(A[i].length, l);
        for (int j = 0; j < l; j++) {
          final poly = A[i][j];
          expect(poly.coeffs.length, 256);
          // Check range
          for (final c in poly.coeffs) {
            expect(c >= 0 && c < q, isTrue);
          }
        }
      }
    });

    test('ExpandS generates bounded coefficients (eta=2)', () {
      final rho = Uint8List(32); // Seed
      final k = 4;
      final l = 4;
      final eta = 2;

      final (s1, s2) = DilithiumSymmetric.expandS(rho, k, l, eta);

      expect(s1.length, l);
      expect(s2.length, k);

      // Check s1 bounds
      for (int i = 0; i < l; i++) {
        for (final c in s1[i].coeffs) {
          expect(
            c >= -eta && c <= eta,
            isTrue,
            reason: "s1 coeff out of bounds",
          );
        }
      }

      // Check s2 bounds
      for (int i = 0; i < k; i++) {
        for (final c in s2[i].coeffs) {
          expect(
            c >= -eta && c <= eta,
            isTrue,
            reason: "s2 coeff out of bounds",
          );
        }
      }
    });

    test('ExpandS generates bounded coefficients (eta=4)', () {
      final rho = Uint8List(32);
      final k = 6;
      final l = 5;
      final eta = 4;

      final (s1, s2) = DilithiumSymmetric.expandS(rho, k, l, eta);

      for (int i = 0; i < l; i++) {
        for (final c in s1[i].coeffs) {
          expect(c >= -eta && c <= eta, isTrue);
        }
      }
    });
  });
}

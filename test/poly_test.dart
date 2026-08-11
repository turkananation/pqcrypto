import 'package:pqcrypto/src/algos/kyber/poly.dart';
import 'package:test/test.dart';

void main() {
  group('Poly.barrettReduce', () {
    test('returns canonical residues for boundary values', () {
      const cases = {
        -1997400: 0,
        -2 * Poly.q - 1: Poly.q - 1,
        -2 * Poly.q: 0,
        -Poly.q - 1: Poly.q - 1,
        -Poly.q: 0,
        -1: Poly.q - 1,
        0: 0,
        1: 1,
        Poly.q - 1: Poly.q - 1,
        Poly.q: 0,
        Poly.q + 1: 1,
        2 * Poly.q: 0,
        2 * Poly.q + 1: 1,
      };

      for (final entry in cases.entries) {
        expect(
          Poly.barrettReduce(entry.key),
          entry.value,
          reason: 'a=${entry.key}',
        );
      }
    });

    test('matches canonical modulo over a representative range', () {
      for (var a = -2000000; a <= 2000000; a += 997) {
        final reduced = Poly.barrettReduce(a);
        expect(reduced, inInclusiveRange(0, Poly.q - 1), reason: 'a=$a');
        expect(reduced, _canonicalMod(a), reason: 'a=$a');
      }
    });

    test('covers the field multiplication input range', () {
      for (var a = 0; a < Poly.q; a += 101) {
        for (var b = 0; b < Poly.q; b += 103) {
          final product = a * b;
          expect(Poly.barrettReduce(product), _canonicalMod(product));
        }
      }
    });
  });
}

int _canonicalMod(int value) => value % Poly.q;

import 'dart:math';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/rounding.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  group('Power2Round (d=13)', () {
    const twoD = 1 << 13, half = 1 << 12;
    for (final r in [0, 1, half, half + 1, twoD - 1, twoD, q - 1, 1234567]) {
      test('reconstructs r=$r', () {
        final (r1, r0) = power2Round(r);
        expect(r1 * twoD + r0, r, reason: 'r1*2^d + r0 == r');
        expect(r0 > -half && r0 <= half, isTrue, reason: 'r0 centered');
      });
    }
  });

  group('Decompose / HighBits / LowBits', () {
    for (final gamma2 in [95232, 261888]) {
      final alpha = 2 * gamma2;
      test('exhaustive division equivalence (alpha=$alpha)', () {
        final m = (q - 1) ~/ alpha;
        for (int r = 0; r < q; r++) {
          final expected = _divisionDecompose(r, alpha);
          final actual = decompose(r, alpha);
          // Avoid allocating matchers for every successful coefficient.
          if (actual != expected ||
              decompose(r - q, alpha) != expected ||
              decompose(r + q, alpha) != expected) {
            fail(
              'decompose mismatch: r=$r alpha=$alpha expected=$expected '
              'actual=$actual',
            );
          }
          final (r1, r0) = expected;
          final hinted = (r1 + (r0 > 0 ? 1 : -1) + m) % m;
          if (useHint(0, r, alpha) != r1 || useHint(1, r, alpha) != hinted) {
            fail('useHint mismatch: r=$r alpha=$alpha');
          }
        }
      });

      test('signed int32 normalization (alpha=$alpha)', () {
        final rng = Random(alpha);
        final values = [
          -2147483648,
          -2147483647,
          2147483646,
          2147483647,
          -q - 1,
          -q,
          -1,
          0,
          q - 1,
          q,
          2 * q,
          for (int i = 0; i < 10000; i++) rng.nextInt(1 << 30) * 4 - 2147483648,
        ];
        for (final r in values) {
          expect(
            decompose(r, alpha),
            _divisionDecompose(r, alpha),
            reason: 'r=$r alpha=$alpha',
          );
        }
      });

      test('reconstructs across the range (alpha=$alpha)', () {
        final rng = Random(alpha);
        for (int t = 0; t < 4000; t++) {
          final r = rng.nextInt(q);
          final (r1, r0) = decompose(r, alpha);
          // FIPS 204: r == r1*alpha + r0 (mod q), with the q-1 boundary folded
          // into r1 == 0.
          final recon = (r1 * alpha + r0) % q;
          expect((recon - r) % q, 0, reason: 'r=$r');
          expect(r0 > -gamma2 && r0 <= gamma2, isTrue, reason: 'r0 bound r=$r');
          expect(highBits(r, alpha), r1);
          expect(lowBits(r, alpha), r0);
        }
      });

      test('q-1 boundary special case (alpha=$alpha)', () {
        final (r1, _) = decompose(q - 1, alpha);
        expect(r1, 0, reason: 'high bits collapse to 0 at q-1');
      });
    }
  });

  group('MakeHint / UseHint consistency', () {
    for (final gamma2 in [95232, 261888]) {
      final alpha = 2 * gamma2;
      final m = (q - 1) ~/ alpha; // UseHint modulus (errata upper bound)
      test('UseHint(MakeHint(z,r),r) == HighBits(r+z) (alpha=$alpha)', () {
        final rng = Random(gamma2 ^ 0x55);
        for (int t = 0; t < 5000; t++) {
          final r = rng.nextInt(q);
          final z = rng.nextInt(2 * gamma2 + 1) - gamma2; // |z| <= gamma2
          final h = makeHint(z, r, alpha);
          final recovered = useHint(h, r, alpha);
          final expected = highBits((r + z) % q, alpha);
          expect(recovered, expected, reason: 'r=$r z=$z');
          expect(
            recovered >= 0 && recovered < m,
            isTrue,
            reason: 'UseHint within [0, m) = [0,$m)',
          );
        }
      });
    }
  });
}

// Independent, pre-fix division/remainder oracle; test code only.
(int, int) _divisionDecompose(int r, int alpha) {
  r %= q;
  int r0 = r % alpha;
  if (r0 > (alpha >> 1)) r0 -= alpha;
  if (r - r0 == q - 1) return (0, r0 - 1);
  return ((r - r0) ~/ alpha, r0);
}

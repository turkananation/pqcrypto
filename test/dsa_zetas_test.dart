import 'dart:math';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/ntt.dart';
import 'package:pqcrypto/src/algos/dilithium/poly.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

int _powMod(int base, int exp, int mod) {
  int r = 1;
  base %= mod;
  while (exp > 0) {
    if (exp & 1 == 1) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1;
  }
  return r;
}

int _brv8(int x) {
  int r = 0;
  for (int i = 0; i < 8; i++) {
    r = (r << 1) | ((x >> i) & 1);
  }
  return r;
}

void main() {
  group('FIPS 204 Appendix B NTT', () {
    test('zetas[k] == 1753^brv8(k) mod q', () {
      const zeta = 1753;
      for (int k = 0; k < 256; k++) {
        final expected = _powMod(zeta, _brv8(k), q);
        expect(DilithiumNTT.zetas[k], expected, reason: 'zetas[$k]');
      }
    });

    test('NTT round-trip is identity', () {
      final rng = Random(0xD5A);
      final a = DilithiumPoly.zero();
      for (int i = 0; i < 256; i++) {
        a.coeffs[i] = rng.nextInt(q);
      }
      final b = DilithiumPoly.zero()..coeffs.setAll(0, a.coeffs);
      DilithiumNTT.ntt(b);
      DilithiumNTT.invNtt(b);
      for (int i = 0; i < 256; i++) {
        expect(b.coeffs[i] % q, a.coeffs[i], reason: 'coeff $i');
      }
    });

    test('invNTT(NTT(a) o NTT(b)) == negacyclic a*b mod q', () {
      final rng = Random(0x1753);
      final a = DilithiumPoly.zero(), b = DilithiumPoly.zero();
      for (int i = 0; i < 256; i++) {
        a.coeffs[i] = rng.nextInt(q);
        b.coeffs[i] = rng.nextInt(q);
      }

      // Schoolbook multiplication in Z_q[x]/(x^256 + 1).
      final ref = List<int>.filled(256, 0);
      for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
          final prod = (a.coeffs[i] * b.coeffs[j]) % q;
          final k = i + j;
          if (k < 256) {
            ref[k] = (ref[k] + prod) % q;
          } else {
            ref[k - 256] = (ref[k - 256] - prod) % q; // x^256 = -1
          }
        }
      }
      for (int i = 0; i < 256; i++) {
        ref[i] %= q;
        if (ref[i] < 0) ref[i] += q;
      }

      final na = DilithiumPoly.zero()..coeffs.setAll(0, a.coeffs);
      final nb = DilithiumPoly.zero()..coeffs.setAll(0, b.coeffs);
      DilithiumNTT.ntt(na);
      DilithiumNTT.ntt(nb);
      final prod = na.pointwiseMul(nb);
      DilithiumNTT.invNtt(prod);

      for (int i = 0; i < 256; i++) {
        expect(prod.coeffs[i] % q, ref[i], reason: 'coeff $i');
      }
    });
  });
}

import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/src/algos/dilithium/ntt.dart';
import 'package:pqcrypto/src/algos/dilithium/poly.dart';
import 'package:pqcrypto/src/algos/dilithium/reduce.dart';
import 'package:pqcrypto/src/algos/dilithium/rounding.dart';
import 'package:pqcrypto/src/algos/kyber/poly.dart';
import 'package:pqcrypto/src/common/mod_mask.dart';
import 'package:test/test.dart';

/// Full scans run on the VM. Web compilers run the same identities on a
/// dense net, including the values whose bitwise width differs from a
/// 32-bit shift.
const bool _vm = bool.fromEnvironment('dart.library.io');

int _posMod(int value, int modulus) {
  final r = value % modulus;
  return r < 0 ? r + modulus : r;
}

void _check(bool ok, String message) {
  if (!ok) fail(message);
}

void main() {
  group('Kyber Barrett', () {
    test('matches the non-negative residue on the proved envelope', () {
      const q = Poly.q;
      final lo = _vm ? -2000000 : -2 * q;
      final hi = _vm ? q * q : 5 * q;
      final step = _vm ? 1 : 3;
      for (var a = lo; a <= hi; a += step) {
        final got = Poly.barrettReduce(a);
        final expect = _posMod(a, q);
        _check(got == expect, 'barrett a=$a got=$got expect=$expect');
      }
    });

    test('matches a product of every pair of residues', () {
      const q = Poly.q;
      final step = _vm ? 1 : 17;
      for (var a = 0; a < q; a += step) {
        for (var b = 0; b < q; b += step) {
          final got = Poly.barrettReduce(a * b);
          final expect = (a * b) % q;
          _check(got == expect, 'product a=$a b=$b got=$got');
        }
      }
    });

    test('CBD noise is one conditional add', () {
      for (var a = 0; a <= 3; a++) {
        for (var b = 0; b <= 3; b++) {
          final got = caddq(a - b, 3329);
          final expect = _posMod(a - b, 3329);
          _check(got == expect, 'cbd a=$a b=$b');
        }
      }
    });
  });

  group('single ±q mask', () {
    test('Kyber and ML-DSA ranges', () {
      for (final q in [3329, 8380417]) {
        final subStep = q == 3329 || _vm ? 1 : 64;
        for (var r = 0; r < 2 * q; r += subStep) {
          final expect = r >= q ? r - q : r;
          _check(csubq(r, q) == expect, 'csub q=$q r=$r');
        }
        final addStep = q == 3329 || _vm ? 1 : 64;
        for (var r = 1 - q; r < q; r += addStep) {
          final expect = r < 0 ? r + q : r;
          _check(caddq(r, q) == expect, 'cadd q=$q r=$r');
        }
      }
    });
  });

  group('ML-DSA reduction', () {
    const q = 8380417;

    test('Montgomery constants', () {
      _check(4294967296 % q == mlDsaRMod, 'R mod q');
      _check((mlDsaRMod * mlDsaRMod) % q == mlDsaR2, 'R^2 mod q');
    });

    test('reduce32 matches the non-negative residue', () {
      for (var r = -2 * q; r <= 3 * q; r++) {
        _check(mlDsaReduce32(r) == _posMod(r, q), 'reduce32 $r');
      }
      const extremes = <int>[
        -2147483648,
        -2147483647,
        -1,
        0,
        1,
        2147483646,
        2147483647,
      ];
      for (final r in extremes) {
        _check(mlDsaReduce32(r) == _posMod(r, q), 'extreme $r');
      }
      final rng = Random(204);
      for (var i = 0; i < 20000; i++) {
        final r = rng.nextInt(1 << 30) * (rng.nextBool() ? 1 : -1);
        _check(mlDsaReduce32(r) == _posMod(r, q), 'random $r');
      }
    });

    test('plain product matches the residue', () {
      final specials = <int>[
        0,
        1,
        2,
        255,
        256,
        257,
        8192,
        mlDsaRMod,
        mlDsaR2,
        q - 1,
      ];
      final step = _vm ? 1 : 4096;
      for (final b in specials) {
        for (var a = 0; a < q; a += step) {
          final got = mlDsaMulMod(a, b);
          final expect = (a * b) % q;
          _check(got == expect, 'mul a=$a b=$b got=$got expect=$expect');
        }
      }
      for (final zeta in DilithiumNTT.zetas) {
        final zetaM = mlDsaMulMod(zeta, mlDsaRMod);
        _check(zetaM > 0 && zetaM < q, 'zetaM $zeta -> $zetaM');
        for (final a in [0, 1, 2, 1234567, q - 1]) {
          final expect = (a * zeta) % q;
          _check(mlDsaRedc(a, zetaM) == expect, 'twiddle a=$a zeta=$zeta');
        }
      }
      final limb = _vm ? 1536 : 256;
      for (var a = 0; a < limb; a++) {
        for (var b = 0; b < limb; b++) {
          _check(mlDsaMulMod(a, b) == (a * b) % q, 'limb a=$a b=$b');
        }
      }
    });

    test('power2Round matches division on the coefficient domain', () {
      (int, int) reference(int r) {
        r = _posMod(r, q);
        var r0 = r & 8191;
        if (r0 > 4096) r0 -= 8192;
        return ((r - r0) >> 13, r0);
      }

      final step = _vm ? 1 : 1024;
      for (var r = 0; r < q; r += step) {
        _check(power2Round(r) == reference(r), 'p2r $r');
        _check(power2Round(r - q) == reference(r), 'p2r low $r');
        _check(power2Round(r + q) == reference(r), 'p2r high $r');
      }
      _check(power2Round(-2147483648) == reference(-2147483648), 'p2r min');
      _check(power2Round(2147483647) == reference(2147483647), 'p2r max');
    });

    test('NTT round-trip and pointwise product', () {
      void roundTrip(List<int> coeffs) {
        final poly = DilithiumPoly(Int32List.fromList(coeffs));
        final original = Int32List.fromList(coeffs);
        DilithiumNTT.ntt(poly);
        DilithiumNTT.invNtt(poly);
        for (var i = 0; i < 256; i++) {
          _check(poly.coeffs[i] == original[i], 'roundtrip i=$i');
        }
      }

      roundTrip(List<int>.filled(256, 0));
      roundTrip(List<int>.filled(256, q - 1));
      final basis = List<int>.filled(256, 0);
      basis[3] = 1;
      basis[200] = q - 1;
      roundTrip(basis);
      final rng = Random(7);
      for (var trial = 0; trial < 8; trial++) {
        roundTrip([for (var i = 0; i < 256; i++) rng.nextInt(q)]);
      }

      final left = DilithiumPoly(
        Int32List.fromList([for (var i = 0; i < 256; i++) rng.nextInt(q)]),
      );
      final right = DilithiumPoly(
        Int32List.fromList([for (var i = 0; i < 256; i++) rng.nextInt(q)]),
      );
      final product = left.pointwiseMul(right);
      for (var i = 0; i < 256; i++) {
        final expect = (left.coeffs[i] * right.coeffs[i]) % q;
        _check(product.coeffs[i] == expect, 'pointwise $i');
      }
    });
  });
}

/// Division-free ML-DSA residue helpers.
///
/// Montgomery reduction uses `R = 2^32` and `n' = -q^{-1} mod R = 4236238847`.
/// Products are accumulated in 8-bit limbs so every intermediate fits in a
/// signed 32-bit bitwise operand. That is the dart2js integer width; it is not
/// a constant-time claim for the VM, dart2js, or dart2wasm.
///
/// [mlDsaRedc] returns `a·b·R^{-1} mod q`. [mlDsaMulMod] returns `a·b mod q`.
/// Both require `0 <= a, b < q` (every such factor is below `2^23`).
library;

import 'params.dart';

/// `2^32 mod q`. Public constant; not derived from a secret.
const int mlDsaRMod = 4193792;

/// `R^2 mod q` for `R = 2^32`.
const int mlDsaR2 = 2365951;

/// Canonical representative in `[0, q)` of a signed 32-bit [r].
///
/// Same fold as FIPS 204 `Decompose`: `q = 2^23 - 2^13 + 1`. Exact on
/// `[-2^31, 2^31)`.
int mlDsaReduce32(int r) {
  final high = ((r + 2147483648) >> 23) - 256;
  r = (r & 0x7fffff) + high * 8191;
  r += (r >> 31) & q;
  r -= q;
  r += (r >> 31) & q;
  return r;
}

/// `a·b·R^{-1} mod q` for `0 <= a, b < q`.
int mlDsaRedc(int a, int b) {
  final a0 = a & 0xff;
  final a1 = (a >> 8) & 0xff;
  final a2 = a >> 16;
  final b0 = b & 0xff;
  final b1 = (b >> 8) & 0xff;
  final b2 = b >> 16;

  var p0 = a0 * b0;
  var p1 = a0 * b1 + a1 * b0;
  var p2 = a0 * b2 + a1 * b1 + a2 * b0;
  var p3 = a1 * b2 + a2 * b1;
  var p4 = a2 * b2;
  var p5 = 0;
  var p6 = 0;

  p1 += p0 >> 8;
  p0 &= 0xff;
  p2 += p1 >> 8;
  p1 &= 0xff;
  p3 += p2 >> 8;
  p2 &= 0xff;
  p4 += p3 >> 8;
  p3 &= 0xff;
  p5 += p4 >> 8;
  p4 &= 0xff;
  p6 += p5 >> 8;
  p5 &= 0xff;

  // n' little-endian bytes of 0xFC7FDFFF.
  const n0 = 0xff;
  const n1 = 0xdf;
  const n2 = 0x7f;
  const n3 = 0xfc;
  var m0 = p0 * n0;
  var m1 = p0 * n1 + p1 * n0;
  var m2 = p0 * n2 + p1 * n1 + p2 * n0;
  var m3 = p0 * n3 + p1 * n2 + p2 * n1 + p3 * n0;
  m1 += m0 >> 8;
  m0 &= 0xff;
  m2 += m1 >> 8;
  m1 &= 0xff;
  m3 += m2 >> 8;
  m2 &= 0xff;
  m3 &= 0xff;

  // q = 0x7FE001.
  const q0 = 0x01;
  const q1 = 0xe0;
  const q2 = 0x7f;
  var x0 = p0 + m0 * q0;
  var x1 = p1 + m0 * q1 + m1 * q0;
  var x2 = p2 + m0 * q2 + m1 * q1 + m2 * q0;
  var x3 = p3 + m1 * q2 + m2 * q1 + m3 * q0;
  var x4 = p4 + m2 * q2 + m3 * q1;
  var x5 = p5 + m3 * q2;
  var x6 = p6;

  x1 += x0 >> 8;
  x2 += x1 >> 8;
  x3 += x2 >> 8;
  x4 += x3 >> 8;
  x5 += x4 >> 8;
  x6 += x5 >> 8;
  final x7 = x6 >> 8;
  final u = (x4 & 0xff) + ((x5 & 0xff) << 8) + ((x6 & 0xff) << 16) + (x7 << 24);
  final sn = u - q;
  return u - (q & ~(sn >> 31));
}

/// `a·b mod q` for `0 <= a, b < q`.
int mlDsaMulMod(int a, int b) => mlDsaRedc(mlDsaRedc(a, b), mlDsaR2);

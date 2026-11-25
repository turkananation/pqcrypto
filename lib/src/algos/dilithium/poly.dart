import 'dart:typed_data';

import 'package:pqcrypto/src/common/mod_mask.dart';

import 'params.dart';
import 'reduce.dart';

/// Polynomial in Rq = Zq[X]/(X^256 + 1)
/// where q = 8380417
class DilithiumPoly {
  final Int32List coeffs;

  DilithiumPoly(this.coeffs) {
    if (coeffs.length != n) {
      throw ArgumentError('Example Polynomial must have $n coefficients');
    }
  }

  factory DilithiumPoly.zero() => DilithiumPoly(Int32List(n));

  /// Reduce all coefficients modulo q
  /// Maps to [0, q-1]
  void reduce() {
    for (int i = 0; i < n; i++) {
      coeffs[i] = _reduce(coeffs[i]);
    }
  }

  /// Add two polynomials
  DilithiumPoly operator +(DilithiumPoly other) {
    final res = Int32List(n);
    for (int i = 0; i < n; i++) {
      res[i] = _add(coeffs[i], other.coeffs[i]);
    }
    return DilithiumPoly(res);
  }

  /// Subtract two polynomials
  DilithiumPoly operator -(DilithiumPoly other) {
    final res = Int32List(n);
    for (int i = 0; i < n; i++) {
      res[i] = _sub(coeffs[i], other.coeffs[i]);
    }
    return DilithiumPoly(res);
  }

  /// Pointwise multiplication (used in NTT domain)
  DilithiumPoly pointwiseMul(DilithiumPoly other) {
    // Note: This is simpler than Kyber because FIPS 204 NTT is complete,
    // not incomplete like Kyber's (which needs baseMul).
    // However, FIPS 204 Alg 2 (InvNTT) expects standard pointwise if fully transformed?
    // Actually FIPS 204 uses PointwiseMult (Alg 3) which is simple component-wise
    // multiplication in the NTT domain.
    final res = Int32List(n);
    for (int i = 0; i < n; i++) {
      res[i] = _mul(coeffs[i], other.coeffs[i]);
    }
    return DilithiumPoly(res);
  }

  // --- Modular Arithmetic Helpers ---

  static int _reduce(int a) => mlDsaReduce32(a);

  /// One correction. Exact when both inputs are in `[0, q)`, and also when
  /// one addend is a centered mask coefficient whose sum with a residue stays
  /// below `2q` (the `y + c·s1` range).
  static int _add(int a, int b) => csubq(a + b, q);

  /// One correction. Exact for a difference in `(-q, q)`.
  static int _sub(int a, int b) => caddq(a - b, q);

  /// Plain product. Both factors are NTT-domain residues in `[0, q)`.
  static int _mul(int a, int b) => mlDsaMulMod(a, b);
}

/// Vector of Polynomials (k x 1 or l x 1)
class DilithiumPolyVec {
  final List<DilithiumPoly> components;
  final int length;

  DilithiumPolyVec(this.components) : length = components.length;

  // Create zero vector of size L
  factory DilithiumPolyVec.zero(int size) {
    return DilithiumPolyVec(List.generate(size, (_) => DilithiumPoly.zero()));
  }

  DilithiumPoly operator [](int i) => components[i];
  void operator []=(int i, DilithiumPoly val) => components[i] = val;

  // Pointwise add
  DilithiumPolyVec operator +(DilithiumPolyVec other) {
    if (components.length != other.components.length) {
      throw ArgumentError("Dimension mismatch");
    }
    return DilithiumPolyVec(
      List.generate(length, (i) => components[i] + other.components[i]),
    );
  }
}

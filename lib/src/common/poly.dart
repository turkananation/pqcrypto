class Poly {
  static const int q = 3329; // Kyber modulus
  static const int n = 256;
  final List<int> coeffs; // Degree 256

  Poly(this.coeffs);

  /// Montgomery reduction: returns (a * R^-1) mod q
  static int montgomeryReduce(int a) {
    const int qinv = 62209; // -q^-1 mod 2^16
    int t = (a * qinv) & 0xFFFF; // "Unsigned" 16-bit
    // Dart ints are 64-bit, so standard montgomery needs care with sign extension if using 32-bit algo.
    // Spec: t = (a * qinv) mod 2^16.
    // int u = (a - t*q) >> 16.
    int u = (a - t * q) >> 16;
    return u;
  }

  /// Barrett reduction: returns a mod q
  static int barrettReduce(int a) {
    const int v = 20159; // 2^26 / q
    int shift = 26;
    int product = (a * v) >> shift;
    int res = a - product * q;
    return res;
  }

  // NTT using pure modular arithmetic (matching Go mlkem768 implementation)
  // Input: normal domain, output: NTT domain
  static Poly ntt(Poly poly) {
    final f = List<int>.from(poly.coeffs);
    int k = 1;

    for (int len = 128; len >= 2; len >>= 1) {
      for (int start = 0; start < 256; start += 2 * len) {
        final zeta = _zetas[k++];
        for (int j = start; j < start + len; j++) {
          // t = zeta * f[j + len] mod q
          final t = _fieldMul(zeta, f[j + len]);
          // f[j + len] = f[j] - t
          f[j + len] = _fieldSub(f[j], t);
          // f[j] = f[j] + t
          f[j] = _fieldAdd(f[j], t);
        }
      }
    }

    return Poly(f);
  }

  // InvNTT using pure modular arithmetic (matching Go mlkem768 implementation)
  // Input: NTT domain, output: normal domain
  static Poly invNtt(Poly poly) {
    final f = List<int>.from(poly.coeffs);
    int k = 127;

    for (int len = 2; len <= 128; len <<= 1) {
      for (int start = 0; start < 256; start += 2 * len) {
        final zeta = _zetas[k--];
        for (int j = start; j < start + len; j++) {
          final t = f[j];
          // f[j] = t + f[j + len]
          f[j] = _fieldAdd(t, f[j + len]);
          // f[j + len] = zeta * (f[j + len] - t)
          f[j + len] = _fieldMul(zeta, _fieldSub(f[j + len], t));
        }
      }
    }

    // Multiply by 128⁻¹ mod q = 3303
    const int inv128 = 3303;
    for (int i = 0; i < 256; i++) {
      f[i] = _fieldMul(f[i], inv128);
    }

    return Poly(f);
  }

  // Field element addition with single reduction
  static int _fieldAdd(int a, int b) {
    int x = a + b;
    // Reduce once if >= q
    if (x >= q) x -= q;
    return x;
  }

  // Field element subtraction with reduction
  static int _fieldSub(int a, int b) {
    int x = a - b + q;
    // Reduce once if >= q
    if (x >= q) x -= q;
    return x;
  }

  // Field element multiplication using Barrett reduction
  static int _fieldMul(int a, int b) {
    return barrettReduce(a * b);
  }

  // Zetas from FIPS 203 (matching Go implementation - unsigned values)
  static const List<int> _zetas = [
    1,
    1729,
    2580,
    3289,
    2642,
    630,
    1897,
    848,
    1062,
    1919,
    193,
    797,
    2786,
    3260,
    569,
    1746,
    296,
    2447,
    1339,
    1476,
    3046,
    56,
    2240,
    1333,
    1426,
    2094,
    535,
    2882,
    2393,
    2879,
    1974,
    821,
    289,
    331,
    3253,
    1756,
    1197,
    2304,
    2277,
    2055,
    650,
    1977,
    2513,
    632,
    2865,
    33,
    1320,
    1915,
    2319,
    1435,
    807,
    452,
    1438,
    2868,
    1534,
    2402,
    2647,
    2617,
    1481,
    648,
    2474,
    3110,
    1227,
    910,
    17,
    2761,
    583,
    2649,
    1637,
    723,
    2288,
    1100,
    1409,
    2662,
    3281,
    233,
    756,
    2156,
    3015,
    3050,
    1703,
    1651,
    2789,
    1789,
    1847,
    952,
    1461,
    2687,
    939,
    2308,
    2437,
    2388,
    733,
    2337,
    268,
    641,
    1584,
    2298,
    2037,
    3220,
    375,
    2549,
    2090,
    1645,
    1063,
    319,
    2773,
    757,
    2099,
    561,
    2466,
    2594,
    2804,
    1092,
    403,
    1026,
    1143,
    2150,
    2775,
    886,
    1722,
    1212,
    1874,
    1029,
    2110,
    2935,
    885,
    2154,
  ];

  /// Pointwise multiplication in NTT domain
  /// Implements MultiplyNTTs per FIPS 203, Algorithm 11 (matching Go mlkem768)
  static Poly baseMul(Poly a, Poly b) {
    final h = List<int>.filled(256, 0);

    // Process in pairs using gammas
    for (int i = 0; i < 256; i += 2) {
      final a0 = a.coeffs[i];
      final a1 = a.coeffs[i + 1];
      final b0 = b.coeffs[i];
      final b1 = b.coeffs[i + 1];
      final gamma = _gammas[i ~/ 2];

      // h[i] = a0*b0 + a1*b1*gamma
      h[i] = _fieldAdd(_fieldMul(a0, b0), _fieldMul(_fieldMul(a1, b1), gamma));
      // h[i+1] = a0*b1 + a1*b0
      h[i + 1] = _fieldAdd(_fieldMul(a0, b1), _fieldMul(a1, b0));
    }

    return Poly(h);
  }

  // Gammas are ζ^2BitRev7(i)+1 mod q (from FIPS 203, Appendix A)
  // Matching Go mlkem768 implementation
  static const List<int> _gammas = [
    17,
    3312,
    2761,
    568,
    583,
    2746,
    2649,
    680,
    1637,
    1692,
    723,
    2606,
    2288,
    1041,
    1100,
    2229,
    1409,
    1920,
    2662,
    667,
    3281,
    48,
    233,
    3096,
    756,
    2573,
    2156,
    1173,
    3015,
    314,
    3050,
    279,
    1703,
    1626,
    1651,
    1678,
    2789,
    540,
    1789,
    1540,
    1847,
    1482,
    952,
    2377,
    1461,
    1868,
    2687,
    642,
    939,
    2390,
    2308,
    1021,
    2437,
    892,
    2388,
    941,
    733,
    2596,
    2337,
    992,
    268,
    3061,
    641,
    2688,
    1584,
    1745,
    2298,
    1031,
    2037,
    1292,
    3220,
    109,
    375,
    2954,
    2549,
    780,
    2090,
    1239,
    1645,
    1684,
    1063,
    2266,
    319,
    3010,
    2773,
    556,
    757,
    2572,
    2099,
    1230,
    561,
    2768,
    2466,
    863,
    2594,
    735,
    2804,
    525,
    1092,
    2237,
    403,
    2926,
    1026,
    2303,
    1143,
    2186,
    2150,
    1179,
    2775,
    554,
    886,
    2443,
    1722,
    1607,
    1212,
    2117,
    1874,
    1455,
    1029,
    2300,
    2110,
    1219,
    2935,
    394,
    885,
    2444,
    2154,
    1175,
  ];

  Poly operator +(Poly other) {
    final res = List<int>.filled(256, 0);
    for (int i = 0; i < 256; i++) {
      int val = coeffs[i] + other.coeffs[i];
      if (val >= q) val -= q; // Conditional reduction
      res[i] = val;
    }
    return Poly(res);
  }

  Poly operator -(Poly other) {
    final res = List<int>.filled(256, 0);
    for (int i = 0; i < 256; i++) {
      int val = coeffs[i] - other.coeffs[i];
      if (val < 0) val += q;
      res[i] = val;
    }
    return Poly(res);
  }
}

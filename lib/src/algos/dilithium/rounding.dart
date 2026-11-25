import 'params.dart'; // for q

/// FIPS 204 Algorithm 3: Power2Round
/// Returns (r1, r0) such that r = r1 * 2^d + r0
/// r1 is "high bits", r0 is "low bits" in power-of-2 basis (sort of)
/// For ML-DSA: d = 13
(int r1, int r0) power2Round(int r) {
  // r = r mod q
  r = r % q;
  if (r < 0) r += q;

  // r0 = r mod 2^d (centered)
  // standard: r0 = r mod 2^d, then adjust to [-2^(d-1), 2^(d-1)]
  // But FIPS 204 Alg 3:
  // r^+ = r mod q
  // r0 = r^+ mod 2^d
  // if r0 > 2^(d-1) then r0 = r0 - 2^d
  // r1 = (r^+ - r0) / 2^d

  const dConst = d; // 13
  const twoPowD = 1 << dConst; // 8192
  const mask = twoPowD - 1;
  const half = 1 << (dConst - 1); // 4096

  int r0 = r & mask;
  if (r0 > half) {
    r0 = r0 - twoPowD;
  }

  // r1 = (r - r0) / 2^d
  int r1 = (r - r0) >> dConst;

  return (r1, r0);
}

/// Split a signed int32 coefficient using an ML-DSA alpha.
(int r1, int r0) decompose(int r, int alpha) {
  // Bias the shift for dart2js; fold using q = 2^23 - 8191.
  final high = ((r + 2147483648) >> 23) - 256;
  r = (r & 0x7fffff) + high * 8191;
  r += (r >> 31) & q;
  r -= q;
  r += (r >> 31) & q;

  // Reciprocals from pq-crystals/dilithium ref/rounding.c.
  int r1 = (r + 127) >> 7;
  if (alpha == 523776) {
    r1 = ((r1 * 1025 + (1 << 21)) >> 22) & 15;
  } else if (alpha == 190464) {
    r1 = (r1 * 11275 + (1 << 23)) >> 24;
    r1 ^= ((43 - r1) >> 31) & r1;
  } else {
    throw ArgumentError.value(alpha, 'alpha', 'unsupported ML-DSA parameter');
  }
  int r0 = r - r1 * alpha;
  r0 -= ((((q - 1) >> 1) - r0) >> 31) & q;
  return (r1, r0);
}

/// FIPS 204 Algorithm 5: HighBits(r, alpha)
int highBits(int r, int alpha) {
  final res = decompose(r, alpha);
  return res.$1;
}

/// FIPS 204 Algorithm 6: LowBits(r, alpha)
int lowBits(int r, int alpha) {
  final res = decompose(r, alpha);
  return res.$2;
}

/// FIPS 204 Algorithm 7: MakeHint(z, r, alpha)
/// Checks if adding z to r changes the HighBits of r.
/// Returns 1 if HighBits(r) != HighBits(r+z), else 0.
int makeHint(int z, int r, int alpha) {
  final r1 = highBits(r, alpha);
  final v1 = highBits(r + z, alpha);
  return r1 != v1 ? 1 : 0;
}

/// FIPS 204 Algorithm 8: UseHint(h, r, alpha)
/// Recovers the HighBits of r+z, given h and r (where h was MakeHint outcome)
/// Used in verification/signature recovery.
int useHint(int h, int r, int alpha) {
  final (r1, r0) = decompose(r, alpha);
  // Add 1 if r0 > 0; subtract 1 otherwise.
  final direction = 1 - 2 * (((r0 - 1) >> 31) & 1);
  int adjusted = r1 + direction;
  if (alpha == 523776) {
    adjusted &= 15;
  } else {
    // Wrap into [0, 44) without division.
    adjusted += (adjusted >> 31) & 44;
    adjusted -= 44;
    adjusted += (adjusted >> 31) & 44;
  }
  final mask = h == 1 ? -1 : 0;
  return r1 ^ ((r1 ^ adjusted) & mask);
}

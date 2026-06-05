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

/// FIPS 204 Algorithm 4: Decompose(r, alpha)
/// Returns (r1, r0) such that r = r1 * alpha + r0
/// Used for hinting.
/// r0 is in range roughly [-alpha/2, alpha/2]
(int r1, int r0) decompose(int r, int alpha) {
  r = r % q;
  if (r < 0) r += q;

  // Let r0 = r mod+- alpha
  // i.e., r0 is r reduced mod alpha to central representative
  // r1 = (r - r0) / alpha (if alpha divides exactly? No, it's integer division roughly)

  // Implementation logic from FIPS 204:
  // r0 = r mod(2*alpha)
  // if r0 > alpha then r0 = r0 - 2*alpha ???
  // Wait, standard defines mod+- alpha:
  // r0 ranges between -alpha/2 and alpha/2

  // FIPS describes:
  // r^+ = r mod q
  // r0 = r^+ mod alpha (wait, logic is simpler in ref code)

  // Ref code style:
  // r1 = (r + 127) >> 7? No alpha is usually (q-1)/88 or similar large values.

  // Let, alpha = 2*gamma2.
  // We want r = r1 * (2*gamma2) + r0 with r0 small.
  // Actually Decompose splits r into HighBits and LowBits logic essentially.

  // Official Alg 4:
  // r0 = r mod+ (2*gamma2)  (where alpha = 2*gamma2 usually, but here param alpha is 2*gamma2)
  // if r0 > alpha/2 ?

  // Let's implement straightforward integer arithmetic:
  // We want r1 such that r ≈ r1 * alpha
  // r0 = r - r1 * alpha

  // r1 = floor( (r + alpha/2) / alpha )?
  // No, let's use the property:
  // But we typically want specific range.

  // Correct logic for FIPS 204 Decompose:
  // r1 = floor( (r + alpha/2) / alpha )?
  // No, let's use the property:
  // r0 = r - r1 * alpha
  // We need r0 in [-alpha/2, alpha/2] (roughly).
  // AND we need specific handling near boundaries of q if applicable.

  // However, FIPS 204 says:
  // r0 = (r mod alpha)
  // if r0 > alpha/2, r0 -= alpha.
  // No, alpha is not power of 2 necessarily.

  // Let's follow Ref Implementation `decompose`:
  // Inputs: r, alpha
  // r1 = (r + 127) >> 7 ?? That is for HighBits.

  // Let's implement HighBits and LowBits directly as they appear to be the primary uses of Decompose.
  // Spec Section 2.3:
  // Decompose(r, alpha):
  //   r0 = r mod+- alpha
  //   if r - r0 == q - 1 then:
  //      r1 = 0, r0 = r0 - 1
  //   else:
  //      r1 = (r - r0) / alpha
  //   return (r1, r0)

  // mod+- alpha means central reduction in [-alpha/2, alpha/2] ?
  // Spec says: r' = r mod alpha. If r' > alpha/2, r' -= alpha.
  // Wait, standard uses 2*gamma2 as argument usually.

  int r0 = r % alpha;
  if (r0 > (alpha >> 1)) r0 -= alpha;

  int r1 = 0;
  if ((r - r0) == (q - 1)) {
    r1 = 0;
    r0 = r0 - 1;
  } else {
    r1 = (r - r0) ~/ alpha;
  }

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
  if (h == 1) {
    // Boundary crossed
    final m = (q - 1) ~/ alpha;
    if (r0 > 0) {
      return (r1 + 1) % m;
    } else {
      return (r1 - 1 + m) % m;
    }
  }
  return r1;
}

// Note: The modulus for r1 return in useHint depends on max value of r1 which is m = (q-1)/alpha.
// We might need to handle the modulo explicitly based on m.

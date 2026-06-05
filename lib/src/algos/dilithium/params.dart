/// FIPS 204 (ML-DSA) parameters and parameter-derived sizes.
///
/// Reference: NIST FIPS 204, Table 1 (parameter sets) and Table 2 (sizes).
library;

// Global constants (shared across all parameter sets).
const int q = 8380417; // Modulus 2^23 - 2^13 + 1
const int d = 13; // Dropped low bits of t
const int n = 256; // Polynomial degree
const int seedBytes = 32; // Length of the key-generation seed xi
const int trBytes = 64; // Length of tr = H(pk, 64)
const int muBytes = 64; // Length of mu
const int rndBytes = 32; // Length of the hedging value rnd

/// Security parameter sets defined by FIPS 204 Table 1.
enum DilithiumParameter { mlDsa44, mlDsa65, mlDsa87 }

/// An ML-DSA parameter set together with every parameter-derived size.
///
/// All byte sizes are *computed* from the primitive parameters so that tests,
/// packing, public input validation, and documentation share one source of
/// truth (FIPS 204 Table 2).
class DilithiumParams {
  final int k; // Rows of A / length of t, s2
  final int l; // Columns of A / length of s1
  final int eta; // Secret coefficient bound: coeffs in [-eta, eta]
  final int tau; // Number of +/-1 entries in the challenge c
  final int beta; // tau * eta
  final int omega; // Max Hamming weight of the hint h
  final int gamma1; // Coefficient range of the mask y
  final int gamma2; // Low-order rounding range
  final int cTildeSize; // Challenge hash length = lambda/4 bytes
  final int securityCategory; // NIST category: 2, 3, or 5
  final String name;

  const DilithiumParams._(
    this.k,
    this.l,
    this.eta,
    this.tau,
    this.beta,
    this.omega,
    this.gamma1,
    this.gamma2,
    this.cTildeSize,
    this.securityCategory,
    this.name,
  );

  static const mlDsa44 = DilithiumParams._(
    4,
    4,
    2,
    39,
    78,
    80,
    1 << 17,
    95232,
    32,
    2,
    'ML-DSA-44', //
  );
  static const mlDsa65 = DilithiumParams._(
    6,
    5,
    4,
    49,
    196,
    55,
    1 << 19,
    261888,
    48,
    3,
    'ML-DSA-65', //
  );
  static const mlDsa87 = DilithiumParams._(
    8,
    7,
    2,
    60,
    120,
    75,
    1 << 19,
    261888,
    64,
    5,
    'ML-DSA-87', //
  );

  /// Collision-strength parameter lambda (bits): cTildeSize = lambda / 4.
  int get lambda => cTildeSize * 4;

  /// Bits per s1/s2 coefficient: bitlen(2*eta) = 3 for eta=2, 4 for eta=4.
  int get etaBits => eta == 2 ? 3 : 4;

  /// Bits per z coefficient: bitlen(2*gamma1 - 1) = 18 for gamma1=2^17 else 20.
  int get zBits => gamma1 == (1 << 17) ? 18 : 20;

  /// Bits per w1 coefficient: 6 for gamma2=(q-1)/88 else 4.
  int get w1Bits => gamma2 == 95232 ? 6 : 4;

  /// Bytes of one packed s1/s2 polynomial.
  int get etaPolyBytes => 32 * etaBits;

  /// Bytes of one packed t0/t1 polynomial.
  int get t0PolyBytes => 32 * d; // 416
  int get t1PolyBytes => 32 * 10; // 320

  /// Bytes of one packed z polynomial.
  int get zPolyBytes => 32 * zBits;

  /// Bytes of one packed w1 polynomial.
  int get w1PolyBytes => 32 * w1Bits;

  /// FIPS 204 Table 2 public key length: 32 + 32*k*10/8.
  int get publicKeyBytes => 32 + k * t1PolyBytes;

  /// FIPS 204 Table 2 private key length.
  int get secretKeyBytes =>
      32 + 32 + trBytes + (l + k) * etaPolyBytes + k * t0PolyBytes;

  /// FIPS 204 Table 2 signature length.
  int get signatureBytes => cTildeSize + l * zPolyBytes + omega + k;

  static DilithiumParams get(DilithiumParameter param) {
    switch (param) {
      case DilithiumParameter.mlDsa44:
        return mlDsa44;
      case DilithiumParameter.mlDsa65:
        return mlDsa65;
      case DilithiumParameter.mlDsa87:
        return mlDsa87;
    }
  }
}

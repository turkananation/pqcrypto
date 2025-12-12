/// FIPS 204 (ML-DSA) Parameters
/// Reference: NIST FIPS 204 Algorithm 1 & Table 1
library;

// Global Constants
const int q = 8380417; // Modulus 2^23 - 2^13 + 1
const int d = 13; // Dropped bits from t
const int tau = 39; // Number of +/- 1's in hint
const int n = 256; // Polynomial degree
const int seedBytes = 32;
const int crhBytes = 48;

/// Security Parameter Sets
enum DilithiumParameter { mlDsa44, mlDsa65, mlDsa87 }

class DilithiumParams {
  final int k; // Matrix dimension (k x l)
  final int l;
  final int eta; // Secret key noise range
  final int beta; // Signature high-order bit range
  final int omega; // Max hamming weight of hint
  final int gamma1;
  final int gamma2;
  final int cTildeSize; // 2 * lambda bytes (32, 48, 64)
  final String name;

  const DilithiumParams._(
    this.k,
    this.l,
    this.eta,
    this.beta,
    this.omega,
    this.gamma1,
    this.gamma2,
    this.cTildeSize,
    this.name,
  );

  // Gamma2: 95232, 261888
  // CTilde: 32 (44), 48 (65), 64 (87)
  static const mlDsa44 = DilithiumParams._(
    4,
    4,
    2,
    78,
    80,
    1 << 17,
    95232,
    32,
    'ML-DSA-44',
  );
  static const mlDsa65 = DilithiumParams._(
    6,
    5,
    4,
    196,
    55,
    1 << 19,
    261888,
    48,
    'ML-DSA-65',
  );
  static const mlDsa87 = DilithiumParams._(
    8,
    7,
    2,
    120,
    75,
    1 << 19,
    261888,
    64,
    'ML-DSA-87',
  );

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

/// Pure Dart Post-Quantum Cryptography library.
///
/// Implements NIST-standardized algorithms:
/// - **ML-KEM** (FIPS 203): Module-Lattice Key Encapsulation Mechanism
/// - **ML-DSA** (FIPS 204): Module-Lattice Digital Signature Algorithm
///
/// See [PqcKem] for key encapsulation and [MlDsa] for digital signatures.
library;

// ML-KEM (FIPS 203)
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;

// ML-DSA (FIPS 204)
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;

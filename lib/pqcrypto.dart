/// Pure Dart Post-Quantum Cryptography library.
///
/// Implements NIST-standardized algorithms:
/// - **ML-KEM** (FIPS 203): Module-Lattice Key Encapsulation Mechanism
/// - **ML-DSA** (FIPS 204): Module-Lattice Digital Signature Algorithm
///
/// See [PqcKem] for key encapsulation and [MlDsa] for digital signatures.
///
/// ## Project ideas and recipes
///
/// The **Cookbook** (the "Cookbook" topic, sourced from `doc/cookbook/`)
/// catalogs concrete projects you can build across servers, mobile, desktop,
/// CLI, embedded Linux, web, and cross-language interop — each composed from a
/// small set of reusable, API-correct recipes. Start at `doc/cookbook/README.md`
/// (human) or `doc/cookbook/project-ideas.yaml` (machine-readable, for agents).
///
/// This package provides only the ML-KEM and ML-DSA primitives. Application
/// concerns such as HKDF, AEAD, classical key exchange, message hashing, and
/// secure key storage are intentionally out of scope and must come from your own
/// stack. ML-KEM yields a 32-byte shared secret, not encryption by itself, and
/// is not authenticated transport on its own.
///
/// {@category Cookbook}
library;

// ML-KEM (FIPS 203)
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;

// ML-DSA (FIPS 204)
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;

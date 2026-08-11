/// Pure Dart Post-Quantum Cryptography library.
///
/// Implements NIST-standardized algorithms:
/// - **ML-KEM** (FIPS 203): Module-Lattice Key Encapsulation Mechanism
/// - **ML-DSA** (FIPS 204): Module-Lattice Digital Signature Algorithm
/// - **SLH-DSA** (FIPS 205): Stateless Hash-Based Signatures
///
/// See [PqcKem] for key encapsulation and [MlDsa] or [SlhDsa] for digital
/// signatures.
///
/// ## Project ideas and recipes
///
/// The **Cookbook** (the "Cookbook" topic, sourced from `doc/cookbook/`)
/// catalogs concrete projects you can build across servers, mobile, desktop,
/// CLI, embedded Linux, web, and cross-language interop — each composed from a
/// small set of reusable, API-correct recipes. Start at `doc/cookbook/README.md`
/// (human) or `doc/cookbook/project-ideas.yaml` (machine-readable, for agents).
///
/// This package provides ML-KEM, ML-DSA, and all 12 standardized SLH-DSA
/// parameter sets as cryptographic primitives. Application concerns such as
/// HKDF, AEAD, classical key exchange, message hashing, and secure key storage
/// are intentionally out of scope and must come from your own stack. ML-KEM
/// yields a 32-byte shared secret, not encryption by itself, and is not
/// authenticated transport on its own.
///
/// {@category Cookbook}
library;

export 'src/common/hmac.dart';
export 'src/common/keccak.dart';
export 'src/common/keccak_parameters.dart';
export 'src/common/mgf1.dart';
export 'src/common/sha2.dart';
export 'src/common/shake.dart';
export 'src/common/zeroize.dart';

// ML-KEM (FIPS 203)
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;

// ML-DSA (FIPS 204)
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;

// SLH-DSA (FIPS 205)
export 'src/algos/slhdsa/params.dart'
    show SlhDsaHashFamily, SlhDsaParameter, SlhDsaParams;
export 'src/algos/slhdsa/slhdsa.dart' show SlhDsa, SlhDsaPreHash;

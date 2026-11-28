/// Pure Dart Post-Quantum Cryptography library.
///
/// Implements NIST-standardized algorithms:
/// - **ML-KEM** (FIPS 203): Module-Lattice Key Encapsulation Mechanism
/// - **ML-DSA** (FIPS 204): Module-Lattice Digital Signature Algorithm
/// - **SLH-DSA** (FIPS 205): Stateless Hash-Based Signatures
/// - **cSHAKE** (SP 800-185): cSHAKE128 and cSHAKE256
/// - **KMAC** (SP 800-185): KMAC128, KMAC256, KMACXOF128, and KMACXOF256
/// - **TupleHash** (SP 800-185): TupleHash128, TupleHash256, and the XOF forms
/// - **ParallelHash** (SP 800-185): ParallelHash128, ParallelHash256, and the XOF forms
///
/// See [PqcKem] for key encapsulation, [MlDsa] or [SlhDsa] for digital
/// signatures, [CShake128] or [CShake256] for cSHAKE, [Kmac128] or [Kmac256]
/// for KMAC, [TupleHash128] or [TupleHash256] for TupleHash, and
/// [ParallelHash128] or [ParallelHash256] for ParallelHash.
///
/// ## Project ideas and recipes
///
/// The **Cookbook** (the "Cookbook" topic, sourced from `doc/cookbook/`)
/// catalogs concrete projects you can build across servers, mobile, desktop,
/// CLI, embedded Linux, web, and cross-language interop — each composed from a
/// small set of reusable, API-correct recipes. Start at `doc/cookbook/README.md`
/// (human) or `doc/cookbook/project-ideas.yaml` (machine-readable, for agents).
///
/// This package provides ML-KEM, ML-DSA, all 12 standardized SLH-DSA
/// parameter sets, cSHAKE128/cSHAKE256, KMAC128/KMAC256,
/// TupleHash128/TupleHash256, and ParallelHash128/ParallelHash256 and their
/// XOF forms as cryptographic primitives.
/// Application concerns such as HKDF, AEAD, classical key exchange, message
/// hashing, and secure key storage are intentionally out of scope and must
/// come from your own stack. ML-KEM yields a 32-byte shared secret, not
/// encryption by itself, and is not authenticated transport on its own.
///
/// {@category Cookbook}
library;

export 'src/common/hmac.dart';
export 'src/common/keccak.dart' hide fips202AbsorbBits, keccakAbsorbBytes;
export 'src/common/sp800_185.dart'
    show leftEncode, rightEncode, encodeString, bytepad, CShake128, CShake256;
export 'src/common/kmac.dart' show Kmac128, Kmac256, KmacXof128, KmacXof256;
export 'src/common/tuplehash.dart'
    show TupleHash128, TupleHash256, TupleHashXof128, TupleHashXof256;
export 'src/common/parallelhash.dart'
    show
        ParallelHash128,
        ParallelHash256,
        ParallelHashXof128,
        ParallelHashXof256;
export 'src/common/keccak_parameters.dart';
export 'src/common/mgf1.dart';
export 'src/common/sha2.dart';
export 'src/common/shake.dart';

// ML-KEM (FIPS 203)
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem, KyberLevel;
// ML-KEM derived sizes (publicKeyBytes / secretKeyBytes / ciphertextBytes).
// Exported so callers can size buffers from the primitive's own tables rather
// than hardcoding literals; matches the FIPS 204/205 params already exported
// below.
export 'src/algos/kyber/params.dart' show KyberParams;

// ML-DSA (FIPS 204)
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;

// SLH-DSA (FIPS 205)
export 'src/algos/slhdsa/params.dart'
    show SlhDsaHashFamily, SlhDsaParameter, SlhDsaParams;
export 'src/algos/slhdsa/slhdsa.dart' show SlhDsa, SlhDsaPreHash;

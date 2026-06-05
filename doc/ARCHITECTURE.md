# pqcrypto Architecture

Last updated: 2026-06-05

`pqcrypto` is a pure Dart post-quantum cryptography package. The current
production center is ML-KEM (FIPS 203). ML-DSA (FIPS 204) is present and
exported, but remains experimental until the ML-DSA test and KAT blockers are
resolved.

## Package Shape

```text
pqcrypto/
  lib/
    pqcrypto.dart                  # public API exports
    src/
      common/
        keccak.dart                # vendored FIPS 202 SHA3/SHAKE core
        shake.dart                 # SHAKE wrappers used by algorithms
        poly.dart                  # ML-KEM polynomial arithmetic
      algos/
        kyber/                     # ML-KEM implementation
          kem.dart                 # KyberKem and PqcKem public API
          indcpa.dart              # K-PKE core
          pack.dart                # FIPS 203 encoders, decoders, compression
          params.dart              # ML-KEM parameter sizes
        dilithium/                 # ML-DSA experimental implementation
          dsa.dart                 # MlDsa static API
          params.dart              # ML-DSA-44/65/87 parameters
          poly.dart                # Dilithium polynomial/vector types
          ntt.dart                 # Dilithium NTT
          packing.dart             # ML-DSA key/signature packing
          rounding.dart            # Power2Round, Decompose, hint helpers
          symmetric.dart           # ExpandA, ExpandS, ExpandMask, sampling
  test/
    data/                          # checked-in ML-KEM KAT corpus
    kat_evaluator_test.dart        # VM-only ML-KEM KAT runner
    keccak_test.dart               # FIPS 202 known-answer tests
    kem_validation_test.dart       # ML-KEM input validation tests
    roundtrip_test.dart            # portable ML-KEM VM/web round-trips
    dsa_*.dart                     # experimental ML-DSA tests
  tool/
    openssl_interop/               # separate unpublished OpenSSL FFI harness
```

## Public API Boundary

`lib/pqcrypto.dart` exports:

```dart
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;
```

The export does not make ML-DSA production-ready. Treat ML-DSA APIs as
experimental until [BUGS.md](BUGS.md), [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md),
and [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md) show green KAT-backed evidence.

## Dependency Boundary

The published package has no third-party runtime dependencies. FIPS 202
SHA3/SHAKE support is vendored in `lib/src/common/keccak.dart`; `shake.dart`
wraps that implementation. The OpenSSL interop code lives in a separate
unpublished path package under `tool/openssl_interop/` and is not part of the
runtime package.

## ML-KEM Data Flow

```text
KeyGen:
  d, z
    -> G(d || k) = rho || sigma
    -> K-PKE key generation
    -> pk = ByteEncode12(t_hat) || rho
    -> sk = ByteEncode12(s_hat) || pk || H(pk) || z

Encapsulate(pk):
  m
    -> G(m || H(pk)) = K || r
    -> c = K-PKE.Encrypt(pk, m, r)
    -> return c, K

Decapsulate(sk, c):
  -> m' = K-PKE.Decrypt(sk, c)
  -> G(m' || H(pk)) = K' || r'
  -> c' = K-PKE.Encrypt(pk, m', r')
  -> if c == c' return K', else return J(z || c)
```

Current ML-KEM evidence is documented in [MLKEM_TESTING.md](MLKEM_TESTING.md) and
[OPENSSL_INTEROP.md](OPENSSL_INTEROP.md).

## ML-DSA Data Flow

The ML-DSA code follows the FIPS 204 shape: KeyGen expands seeds into
`rho`, `rhoPrime`, and `K`; derives `A`, `s1`, `s2`, and `t`; signs by sampling
`y`, building a challenge, and rejection-sampling `z` and hints; verifies by
recomputing the challenge from the public key, message, and signature.

Current blockers are not architectural absence; they are correctness,
validation, and side-channel hardening gaps. The full suite currently fails in
ML-DSA packing/symmetric/debug tests, so architecture docs must not present
ML-DSA as production validated.

## Design Choices

### Separate Polynomial Types

ML-KEM and ML-DSA use different rings and different NTT shapes:

| Algorithm | Modulus | Polynomial type | NTT style                  |
| --------- | ------- | --------------- | -------------------------- |
| ML-KEM    | 3329    | `Poly`          | Incomplete, base-mul pairs |
| ML-DSA    | 8380417 | `DilithiumPoly` | Complete, coefficient-wise |

Keeping these types separate makes the arithmetic easier to audit and avoids
pretending the two schemes share a single polynomial abstraction.

### Pure Dart Arithmetic

The library uses Dart integer arithmetic, typed byte/int arrays where practical,
and no Montgomery domain conversions. This keeps the implementation auditable
and web-compatible. Performance opportunities are tracked in
[PERFORMANCE.md](PERFORMANCE.md).

### Evidence-Scoped Assurance

Do not describe this package as FIPS 140 validated or fully certified. The
repository provides implementation evidence: checked-in ML-KEM KAT vectors,
unit tests, web tests, and OpenSSL interop checks. Formal module validation is a
separate process.

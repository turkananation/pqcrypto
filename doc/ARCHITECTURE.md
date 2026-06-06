# pqcrypto Architecture

Last updated: 2026-06-05

`pqcrypto` is a pure Dart post-quantum cryptography package with two supported
algorithm surfaces: ML-KEM (FIPS 203) and ML-DSA (FIPS 204). Both are byte-exact
against their checked-in NIST KAT corpora; ML-KEM additionally has OpenSSL
interop evidence. This is algorithm/KAT conformance evidence, not a CMVP/FIPS 140
module validation — see [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md). SLH-DSA
(FIPS 205) is planned and tracked in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md); it is not yet
implemented.

## Package Shape

```text
pqcrypto/
  lib/
    pqcrypto.dart                  # public API exports
    src/
      common/
        keccak.dart                # vendored FIPS 202 SHA3/SHAKE + KeccakXof
        shake.dart                 # SHAKE wrappers + incremental XOF
        sha2.dart                  # vendored FIPS 180-4 SHA-256/384/512
        zeroize.dart               # best-effort secret zeroization helpers
        poly.dart                  # ML-KEM polynomial arithmetic
      algos/
        kyber/                     # ML-KEM implementation
          kem.dart                 # KyberKem and PqcKem public API
          indcpa.dart              # K-PKE core
          pack.dart                # FIPS 203 encoders, decoders, compression
          params.dart              # ML-KEM parameter sizes
        dilithium/                 # ML-DSA (FIPS 204) implementation
          dsa.dart                 # MlDsa: external + internal + HashML-DSA API
          params.dart              # ML-DSA-44/65/87 params + Table 2 sizes
          poly.dart                # Dilithium polynomial/vector types
          ntt.dart                 # Dilithium NTT + Appendix B zetas
          packing.dart             # ML-DSA key/signature packing (signed domains)
          rounding.dart            # Power2Round, Decompose, hint helpers
          symmetric.dart           # ExpandA/S, ExpandMask, SampleInBall, pre-hash
  test/
    data/
      MLKEM/                       # checked-in ML-KEM KAT corpus + README
      MLDSA/                       # checked-in ML-DSA KAT corpus (18 files) + README
    kat_evaluator_test.dart        # VM-only ML-KEM KAT runner (3000 vectors)
    mldsa_kat_test.dart            # VM-only discovered ML-DSA KAT runner (18 files)
    keccak_test.dart               # FIPS 202 known-answer tests
    sha2_test.dart                 # FIPS 180-4 SHA-2 known-answer tests
    kem_validation_test.dart       # ML-KEM input validation tests
    roundtrip_test.dart            # portable ML-KEM VM/web round-trips
    dsa_zetas_test.dart            # Appendix B zetas + negacyclic NTT property
    dsa_rounding_test.dart         # Power2Round/Decompose/MakeHint/UseHint bounds
    dsa_negative_test.dart         # malformed pk/sig/hint/context (verify = false)
    dsa_api_test.dart              # context binding, hedged/deterministic, domains
    dsa_*.dart                     # further focused ML-DSA tests
  tool/
    openssl_interop/               # separate unpublished OpenSSL FFI harness
```

## Planned: SLH-DSA (FIPS 205)

SLH-DSA is the next signature scheme and is **not yet implemented**. It is
hash-only and will add, under `lib/src/algos/slhdsa/`, the components `params`,
`util` (toInt/toByte/base_2b/Trunc_n), `address` (`ADRS` 32-byte and `ADRS^c`
22-byte), `hashing` (the six tweakable hashes for the SHAKE and SHA-2 families),
`wots`, `xmss`, `hypertree`, `fors`, and the top-level `slhdsa` (internal +
external APIs). The SHAKE family reuses `keccak.dart` with no new primitive; the
SHA-2 family additionally needs vendored `lib/src/common/hmac.dart` and
`lib/src/common/mgf1.dart`. WOTS+, XMSS, hypertree, and FORS are internal
components and will **not** be exported as standalone public APIs. The full
layout, public API, hardening, and milestone plan are in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md).

## Public API Boundary

`lib/pqcrypto.dart` exports:

```dart
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;
```

The ML-DSA surface is KAT-validated: `MlDsa` exposes the FIPS 204 external
functions (`generateKeyPair`, `sign`, `verify`, `hashSign`, `hashVerify`) and
the internal/CAVP helpers (`generateKeyPairSeeded`, `signInternal`,
`verifyInternal`). See [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md) and
[MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md) for the
evidence, and [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md) for the claim limit.

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
  -> always compute K_bar = J(z || c)
  -> constant-time select: (c == c') ? K' : K_bar  (branchless mask)
```

ML-KEM decapsulation computes both candidate secrets and selects with a
branchless mask, and zeroizes `m'`, `K' || r'`, `K_bar`, `c'`, and `z` in a
`finally` block.

Current ML-KEM evidence is documented in [MLKEM_TESTING.md](MLKEM_TESTING.md) and
[OPENSSL_INTEROP.md](OPENSSL_INTEROP.md).

## ML-DSA Data Flow

The ML-DSA code follows the FIPS 204 shape: KeyGen expands seeds into
`rho`, `rhoPrime`, and `K`; derives `A`, `s1`, `s2`, and `t`; signs by sampling
`y`, building a challenge, and rejection-sampling `z` and hints; verifies by
recomputing the challenge from the public key, message, and signature.

External vs. internal layering mirrors FIPS 204: the public `sign`/`verify`
format `M'` (domain byte, context, and — for HashML-DSA — the pre-hash OID and
digest) and delegate to deterministic `*_internal` cores. Signing is hedged by
default (`rnd` from `Random.secure()`); rejection samplers squeeze an incremental
SHAKE XOF so they cannot exhaust a fixed buffer; the infinity-norm check
evaluates all 256 coefficients with no early exit. The whole surface is
byte-exact against the checked-in KAT corpus (`test/data/MLDSA`); residual
hardening (per-iteration branch directions, broader pre-hash support) is tracked
in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

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
repository provides implementation evidence: checked-in ML-KEM and ML-DSA KAT
vectors, unit tests, web tests, and OpenSSL interop checks. Formal module
validation is a separate process — see
[FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md) for exactly what is and is not
claimed and why.

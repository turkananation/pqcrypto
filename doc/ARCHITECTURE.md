# pqcrypto Architecture

Last updated: 2026-06-15

`pqcrypto` is a pure Dart post-quantum cryptography package with two supported
algorithm surfaces: ML-KEM (FIPS 203) and ML-DSA (FIPS 204). Both are byte-exact
against their checked-in NIST KAT corpora; ML-KEM additionally has OpenSSL
interop evidence. This is algorithm/KAT conformance evidence, not a CMVP/FIPS 140
module validation — see [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md). Full
FIPS 202 and SP 800-185 coverage targets 0.6.0, with 0.7.0 spillover if the
evidence gate cannot close, and is planned in
[FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md). SLH-DSA
(FIPS 205) is in development and tracked in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md). Its SHAKE
implementation is byte-exact on the ACVP subset and the external API is
exported in the development tree, but v0.4.0 is not shipped.

## Package Shape

```text
pqcrypto/
  lib/
    pqcrypto.dart                  # public API exports
    src/
      common/
        keccak.dart                # vendored FIPS 202 SHA3/SHAKE + KeccakXof
        keccak_parameters.dart     # tested Keccak-f[1600] and function profiles
        shake.dart                 # SHAKE wrappers + incremental XOF
        sp800_185.dart             # planned cSHAKE/KMAC/TupleHash/ParallelHash
        sha2.dart                  # vendored FIPS 180-4 SHA-2 functions
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
        slhdsa/                     # FIPS 205 implementation in progress
          params.dart              # 12 Table 2 sets + all derived sizes
          util.dart                # Algorithms 1-4 and Trunc_n helper
          address.dart             # 32-byte ADRS + Table 1 member functions
          hashing.dart             # SHAKE instantiation of six hash functions
          wots.dart                # Algorithms 5-8
          xmss.dart                # Algorithms 9-11
          hypertree.dart           # Algorithms 12-13
          fors.dart                # Algorithms 14-17
          slhdsa.dart              # Algorithms 18-25
  test/
    data/
      MLKEM/                       # checked-in ML-KEM KAT corpus + README
      MLDSA/                       # checked-in ML-DSA KAT corpus (18 files) + README
      FIPS202/                     # selected official byte examples + provenance
      SLHDSA/                      # official ACVP sample corpus + provenance
    kat_evaluator_test.dart        # VM-only ML-KEM KAT runner (3000 vectors)
    mldsa_kat_test.dart            # VM-only discovered ML-DSA KAT runner (18 files)
    keccak_test.dart               # current FIPS 202 known-answer tests
    fips202_examples_test.dart     # normalized official byte-example runner
    slhdsa_acvp_corpus_test.dart   # ACVP integrity/schema gate (1,248 cases)
    slhdsa_kat_test.dart           # VM-only ACVP runner (1,248 cases, all 12)
    slhdsa_*_test.dart             # Algorithms 1-25 regressions
    sp800_185_*_test.dart          # planned SP 800-185 examples and regressions
    sha2_test.dart                 # FIPS 180-4 SHA-2 known-answer tests
    kem_validation_test.dart       # ML-KEM input validation tests
    roundtrip_test.dart            # portable ML-KEM VM/web round-trips
    dsa_zetas_test.dart            # Appendix B zetas + negacyclic NTT property
    dsa_rounding_test.dart         # Power2Round/Decompose/MakeHint/UseHint bounds
    dsa_negative_test.dart         # malformed pk/sig/hint/context (verify = false)
    dsa_api_test.dart              # context binding, hedged/deterministic, domains
    dsa_*.dart                     # further focused ML-DSA tests
  tool/
    bench/                         # portable SLH-DSA VM/JS/Wasm benchmarks
    openssl_interop/               # separate unpublished OpenSSL FFI harness
```

## In Development: SLH-DSA (FIPS 205)

SLH-DSA is the next signature scheme. The implementation provides all 12
parameter sets, Algorithms 1-25 for both hash families, the 32-byte `ADRS` and
22-byte `ADRS^c`, internal/external composition, and a VM-only runner that is
byte-exact on all 1,248 cases in the pinned official NIST ACVP sample corpus.

The external SHAKE surface is exported from `lib/pqcrypto.dart` in the
development tree. Algorithms 18-20 remain behind the source-only
`SlhDsaInternal` facade for ACVP execution. Verify-after-sign,
BUFF/performance documentation, and per-target benchmark baselines are
complete. The decomposed VM matrix, both web compilers, and publication
preflight are green; only the release metadata, tag, and publish steps remain
before v0.4.0. The SHA-2 family also needs HMAC, MGF1, and the
22-byte `ADRS^c`. Component internals are not standalone public APIs. The full
plan is in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md).

## Planned: FIPS 202 Completion and SP 800-185

The current Keccak implementation is a shared primitive for ML-KEM, ML-DSA, and
future SLH-DSA. It is **partial FIPS 202 support**, not a complete standalone
SHA-3 release surface: SHA3-224/256/384/512, SHAKE128/256, and incremental
SHAKE XOFs exist. Selected official NIST byte examples and direct constants,
suffix, rate, and capacity tests are present. Non-byte example handling, the
complete official corpus, and SP 800-185 remain planned for 0.6.0 or controlled
0.7.0 spillover.

The target architecture keeps Keccak ownership in `lib/src/common/keccak.dart`
and adds `lib/src/common/sp800_185.dart` for the derived functions:

- SP 800-185 encodings: `left_encode`, `right_encode`, `encode_string`,
  `bytepad`, and test-only bit substring helpers;
- cSHAKE128/256;
- KMAC128/256 and KMACXOF128/256;
- TupleHash128/256 and TupleHashXOF128/256; and
- ParallelHash128/256 and ParallelHashXOF128/256.

The full architecture, API, corpus strategy, and issue map are in
[FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md).

## Public API Boundary

`lib/pqcrypto.dart` exports:

```dart
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart'
    show DilithiumParams, DilithiumParameter;
export 'src/algos/slhdsa/params.dart'
    show SlhDsaHashFamily, SlhDsaParameter, SlhDsaParams;
export 'src/algos/slhdsa/slhdsa.dart' show SlhDsa, SlhDsaPreHash;
```

The ML-DSA surface is KAT-validated: `MlDsa` exposes the FIPS 204 external
functions (`generateKeyPair`, `sign`, `verify`, `hashSign`, `hashVerify`) and
the internal/CAVP helpers (`generateKeyPairSeeded`, `signInternal`,
`verifyInternal`). See [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md) and
[MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md) for the
evidence, and [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md) for the claim limit.

The SLH-DSA package-root surface contains only Algorithms 21-25 and the
parameter/pre-hash types. `SlhDsaParams.supportedValues` lists all 12 parameter
sets — both the SHAKE and SHA-2 hash families — each byte-exact against the
checked-in NIST ACVP corpus.

## Dependency Boundary

The published package has no third-party runtime dependencies. Current FIPS 202
SHA3/SHAKE support is vendored in `lib/src/common/keccak.dart`; `shake.dart`
wraps that implementation. Full FIPS 202 and SP 800-185 remain planned 0.6.0
work, with 0.7.0 spillover only if the evidence gate requires it.
The OpenSSL interop code lives in a separate
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

| Algorithm   | Modulus   | Polynomial type   | NTT style                    |
| ----------- | --------- | ----------------- | ---------------------------- |
| ML-KEM      | 3329      | `Poly`            | Incomplete, base-mul pairs   |
| ML-DSA      | 8380417   | `DilithiumPoly`   | Complete, coefficient-wise   |

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

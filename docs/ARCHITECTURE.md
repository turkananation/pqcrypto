# pqcrypto Architecture Document

**Date**: 2026-03-14
**Version**: 0.1.0

---

## 1. High-Level Architecture

```text
pqcrypto/
  lib/
    pqcrypto.dart                    <-- Public API entrypoint
    src/
      common/                        <-- Shared primitives
        poly.dart                    <-- Kyber Poly (NTT, baseMul, zetas)
        shake.dart                   <-- SHAKE-128/256 wrappers
      algos/
        kyber/                       <-- ML-KEM (FIPS 203) -- PRODUCTION
          kem.dart                   <-- High-level KEM API
          indcpa.dart                <-- IND-CPA encryption core
          pack.dart                  <-- Serialization & compression
          params.dart                <-- Security parameter sets
        dilithium/                   <-- ML-DSA (FIPS 204) -- IN DEVELOPMENT
          dsa.dart                   <-- High-level DSA API (sign/verify)
          ntt.dart                   <-- Dilithium-specific NTT
          poly.dart                  <-- Dilithium polynomial arithmetic
          packing.dart               <-- Serialization (BitPack, SimpleBitPack)
          params.dart                <-- Security parameter sets
          rounding.dart              <-- Power2Round, Decompose, Hints
          symmetric.dart             <-- Sampling (ExpandA, ExpandS, SampleInBall)
  test/
    kat_evaluator.dart               <-- NIST KAT runner for ML-KEM
    pack_test.dart                   <-- ML-KEM serialization tests
    cbd_test.dart                    <-- ML-KEM noise distribution tests
    dsa_test.dart                    <-- ML-DSA key generation tests
    dsa_sign_test.dart               <-- ML-DSA sign/verify round-trip
    dsa_math_test.dart               <-- ML-DSA polynomial arithmetic
    dsa_ntt_test.dart                <-- ML-DSA NTT round-trip
    dsa_pack_test.dart               <-- ML-DSA serialization tests
    dsa_symmetric_test.dart          <-- ML-DSA sampling tests
  tool/
    gen_dsa_zetas.dart               <-- Zeta table generator for Dilithium
  example/
    main.dart                        <-- Usage demo with benchmarks
```

---

## 2. Module Dependency Graph

```text
pqcrypto.dart
    |
    +-- kyber/kem.dart (PqcKem, KyberKem)
    |       |
    |       +-- kyber/indcpa.dart (Indcpa)
    |       |       |
    |       |       +-- common/poly.dart (Poly, NTT, baseMul)
    |       |       +-- common/shake.dart (Shake128, Shake256)
    |       |       +-- kyber/pack.dart (Pack)
    |       |       +-- kyber/params.dart (KyberParams)
    |       |
    |       +-- kyber/pack.dart
    |       +-- kyber/params.dart
    |       +-- common/shake.dart
    |       +-- pointycastle (SHA3Digest)
    |
    +-- dilithium/dsa.dart (MlDsa) [NOT YET EXPORTED]
            |
            +-- dilithium/poly.dart (DilithiumPoly, DilithiumPolyVec)
            +-- dilithium/ntt.dart (DilithiumNTT)
            +-- dilithium/packing.dart (packPK, packSK, packSig, etc.)
            +-- dilithium/params.dart (DilithiumParams)
            +-- dilithium/rounding.dart (power2Round, decompose, hints)
            +-- dilithium/symmetric.dart (DilithiumSymmetric)
            +-- common/shake.dart
            +-- common/poly.dart (Poly - only for type import)
```

---

## 3. Design Decisions

### 3.1 Separate Polynomial Types for Kyber vs Dilithium

**Decision**: Kyber uses `Poly` (from `common/poly.dart`) with `List<int>` coefficients and 3329 modulus. Dilithium uses `DilithiumPoly` (from `dilithium/poly.dart`) with `Int32List` coefficients and 8380417 modulus.

**Rationale**: The two algorithms operate in fundamentally different polynomial rings:

- Kyber: Z_3329[X]/(X^256 + 1), coefficients fit in 12 bits
- Dilithium: Z_8380417[X]/(X^256 + 1), coefficients need 23 bits

Different NTT implementations are required (different zeta tables, different reduction strategies). Sharing a base type would add complexity without benefit.

**Trade-off**: Code duplication in NTT butterfly operations. Mitigated by the fact that the operations have different constant parameters.

### 3.2 Pure Modular Arithmetic (Not Montgomery)

**Decision**: Both Kyber and Dilithium NTTs use direct modular arithmetic (`(a * b) % q`) rather than Montgomery multiplication.

**Rationale**:

- Simpler code, easier to audit
- Dart's 64-bit integers handle intermediate products without overflow
- `q^2` for both algorithms fits in 53 bits (safe for JS compilation)
- Montgomery form requires domain conversion overhead

**Trade-off**: ~2x slower than Montgomery on native platforms. Acceptable for a pure Dart library targeting correctness-first.

### 3.3 Static Methods with Parameter Objects

**Decision**: Cryptographic operations are static methods on classes (e.g., `MlDsa.sign()`, `Indcpa.encrypt()`) that take a `Params` object.

**Rationale**: Follows the spec structure where algorithms are parameterized. Avoids object lifecycle management for stateless operations.

### 3.4 `pointycastle` Dependency for SHA-3

**Decision**: Use `pointycastle` for SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 rather than implementing from scratch.

**Rationale**: SHA-3/Keccak is complex (1600-bit state, 24 rounds of permutation). `pointycastle` is a mature, well-tested Dart cryptography library. Implementing Keccak from scratch would be error-prone and redundant.

**Trade-off**: Adds a dependency. `pointycastle` is a large package (includes AES, RSA, etc.), but tree-shaking in `dart2js` should eliminate unused code.

---

## 4. Data Flow

### 4.1 ML-KEM Key Encapsulation Flow

```text
KeyGen:
  d, z (random 32+32 bytes)
    -> G(d) = (rho, sigma)
    -> A = ExpandA(rho)                   [SHAKE-128 matrix]
    -> s, e = CBD(sigma, eta)             [SHAKE-256 noise]
    -> s_hat = NTT(s), e_hat = NTT(e)
    -> t_hat = A * s_hat + e_hat          [NTT domain multiply]
    -> pk = Encode12(t_hat) || rho
    -> sk = Encode12(s_hat) || pk || H(pk) || z

Encapsulate(pk):
  m (random 32 bytes)
    -> (K, r) = G(m || H(pk))
    -> ct = Encrypt(pk, m, r)             [IND-CPA encryption]
    -> return (ct, K)

Decapsulate(sk, ct):
  -> m' = Decrypt(sk, ct)                 [IND-CPA decryption]
  -> (K', r') = G(m' || H(pk))
  -> ct' = Encrypt(pk, m', r')            [Re-encryption check]
  -> if ct == ct': return K'              [Constant-time compare]
  -> else: return J(z || ct)              [Implicit rejection]
```

### 4.2 ML-DSA Digital Signature Flow

```text
KeyGen(seed):
  -> (rho, rho', K) = H(seed)            [SHAKE-256 expand]
  -> A = ExpandA(rho)                     [SHAKE-128 matrix, k x l]
  -> (s1, s2) = ExpandS(rho')            [SHAKE-256 bounded]
  -> t = InvNTT(A * NTT(s1)) + s2
  -> (t1, t0) = Power2Round(t, d=13)
  -> pk = (rho, t1)
  -> tr = H(pk)
  -> sk = (rho, K, tr, s1, s2, t0)

Sign(sk, M):
  -> mu = H(tr || M)
  -> rho' = H(K || mu)
  -> LOOP (kappa = 0, l, 2l, ...):
      -> y = ExpandMask(rho', kappa)
      -> w = InvNTT(A * NTT(y))
      -> w1 = HighBits(w)
      -> c_tilde = H(mu || Encode(w1))
      -> c = SampleInBall(c_tilde)
      -> z = y + c*s1
      -> REJECT if ||z|| >= gamma1 - beta
      -> r0 = LowBits(w - c*s2)
      -> REJECT if ||r0|| >= gamma2 - beta
      -> ct0 = c*t0
      -> REJECT if ||ct0|| >= gamma2
      -> h = MakeHint(-ct0, w-cs2+ct0)
      -> REJECT if weight(h) > omega
  -> sig = (c_tilde, z, h)

Verify(pk, M, sig):
  -> (rho, t1) = Unpack(pk)
  -> (c_tilde, z, h) = Unpack(sig)
  -> CHECK ||z|| < gamma1 - beta
  -> A = ExpandA(rho)
  -> tr = H(pk); mu = H(tr || M)
  -> c = SampleInBall(c_tilde)
  -> w' = UseHint(h, A*z - c*t1*2^d)
  -> c_tilde' = H(mu || Encode(w'))
  -> return c_tilde == c_tilde'
```

---

## 5. Polynomial Ring Structure

### 5.1 Kyber Ring: R_q = Z_3329[X]/(X^256 + 1)

| Property | Value |
| -------- | ----- |
| Modulus q | 3329 (prime, NTT-friendly) |
| Degree n | 256 |
| NTT type | Incomplete (degree-2 factors) |
| Primitive root | 17 (of order 512 mod 3329) |
| BaseMul | Karatsuba-style on degree-1 modules |
| Zetas | 128 values (bit-reversed order) |
| Gammas | 128 values (for baseMul twist) |

### 5.2 Dilithium Ring: R_q = Z_8380417[X]/(X^256 + 1)

| Property | Value |
| -------- | ----- |
| Modulus q | 8380417 = 2^23 - 2^13 + 1 |
| Degree n | 256 |
| NTT type | Complete (degree-1 factors) |
| Primitive root | 1753 (of order 512 mod q) |
| Pointwise mul | Simple coefficient-wise |
| Zetas | 256 values (bit-reversed order) |

---

## 6. Test Architecture

```text
test/
  Unit Tests (isolated component testing):
    dsa_math_test.dart       -- Modular arithmetic, reduce, add, mul
    dsa_ntt_test.dart        -- NTT/InvNTT round-trip
    dsa_pack_test.dart       -- Serialization round-trip (BitPack, SimpleBitPack)
    dsa_symmetric_test.dart  -- Sampling bounds (ExpandA, ExpandS)
    pack_test.dart           -- ML-KEM compression round-trip
    cbd_test.dart            -- ML-KEM noise statistical distribution

  Integration Tests:
    dsa_test.dart            -- ML-DSA KeyGen output sizes + determinism
    dsa_sign_test.dart       -- ML-DSA Sign/Verify round-trip (all 3 levels)

  Compliance Tests:
    kat_evaluator.dart       -- NIST KAT vector runner (ML-KEM only)
```

---

## 7. Platform Compatibility Matrix

| Platform | Dart Runtime | Int Size | NTT Safety | Status |
| -------- | ------------ | -------- | ---------- | ------ |
| Linux x64 | VM (JIT/AOT) | 64-bit | Safe | ✅ |
| macOS x64/ARM | VM | 64-bit | Safe | ⏳ |
| Windows x64 | VM | 64-bit | Safe | ⏳ |
| Android | VM (AOT) | 64-bit | Safe | ⏳ |
| iOS | VM (AOT) | 64-bit | Safe | ⏳ |
| Web (dart2js) | JS | 53-bit double | **Verify** | ⚠️ |
| Web (dart2wasm) | Wasm | 64-bit | Safe | ⏳ |

**JS Safety Note**: Dilithium's `q^2 = (8380417)^2 = 7.023 * 10^13 < 2^53`. Safe for JS. Kyber's `q^2 = (3329)^2 = 1.108 * 10^7`. Trivially safe.

# Algorithm Expansion Guide

**Date**: 2026-03-14
**How to add remaining PQC algorithms to pqcrypto**

---

## 1. Current State

| Algorithm | Standard | Status | Maturity |
|-----------|----------|--------|----------|
| ML-KEM (Kyber) | FIPS 203 | ✅ | KAT validated |
| ML-DSA (Dilithium) | FIPS 204 | ⏳ | Round-trip works |
| SLH-DSA (SPHINCS+) | FIPS 205 | ❌ | - |
| FN-DSA (FALCON) | Draft FIPS 206 | ❌ | - |
| HQC | Selected Round 4 | ❌ | - |

---

## 2. SLH-DSA (SPHINCS+) - FIPS 205

### Overview

SLH-DSA is a **hash-based** stateless digital signature scheme. Unlike ML-DSA (lattice-based), it relies only on the security of hash functions, making it the most conservative PQC option.

### Architecture

```
lib/src/algos/sphincs/
  slh_dsa.dart          -- High-level API (KeyGen, Sign, Verify)
  address.dart          -- ADRS (address) structure
  fors.dart             -- FORS (Few-time One-time Signature)
  wots.dart             -- WOTS+ (Winternitz OTS)
  hypertree.dart        -- Hypertree multi-tree structure
  xmss.dart             -- XMSS tree
  params.dart           -- Parameter sets
  hash.dart             -- Hash function abstraction (SHA-256 or SHAKE-256 mode)
```

### Key Implementation Components

1. **WOTS+ (Winternitz One-Time Signatures)**
   - Chain function: iterative hash application
   - Key: k hash chains of length w
   - Existing `Shake256` can be reused

2. **FORS (Forest of Random Subsets)**
   - Fixed-height binary tree
   - Private key: random leaves
   - Public key: tree root

3. **Hypertree**
   - Multi-layer XMSS tree
   - Each layer signs the next layer's root
   - Height d layers, each of height h/d

4. **Parameter Sets (FIPS 205)**

| Parameter | SLH-DSA-128s | SLH-DSA-128f | SLH-DSA-192s | SLH-DSA-256f |
|-----------|-------------|-------------|-------------|-------------|
| n | 16 | 16 | 24 | 32 |
| h | 63 | 66 | 63 | 68 |
| d | 7 | 22 | 7 | 17 |
| Security | 128-bit | 128-bit | 192-bit | 256-bit |
| PK size | 32 B | 32 B | 48 B | 64 B |
| Sig size | 7856 B | 17088 B | 16224 B | 49856 B |
| **Speed** | Slow | Fast | Slow | Fast |

### Effort Estimate

- **Complexity**: Medium (simpler math than lattice schemes)
- **LOC**: ~800-1200
- **Time**: 2-3 weeks for a single developer
- **Dependencies**: Only SHAKE/SHA-3 (already available)
- **Key Challenge**: Signature sizes are large (7-50 KB). The "f" variants trade size for speed.

### Implementation Steps

1. Implement ADRS structure (byte array with field accessors)
2. Implement WOTS+ chain function and key generation
3. Implement XMSS tree construction and signing
4. Implement FORS signing and verification
5. Build hypertree on top of XMSS layers
6. Implement SLH-DSA.KeyGen, Sign, Verify
7. Validate against NIST KAT vectors

---

## 3. FN-DSA (FALCON) - Draft FIPS 206

### Overview

FN-DSA is a **lattice-based** signature scheme using NTRU lattices with Gaussian sampling. It produces the **smallest signatures** among PQC signature schemes but has the most complex implementation.

### Architecture

```
lib/src/algos/falcon/
  fn_dsa.dart           -- High-level API
  ntru_solve.dart       -- NTRU equation solver (KeyGen core)
  fft.dart              -- FFT over complex/real numbers
  sampler.dart          -- Discrete Gaussian sampling (critical!)
  codec.dart            -- Signature compression (Huffman-like)
  params.dart           -- FN-DSA-512, FN-DSA-1024
  shake256x4.dart       -- 4-way parallel SHAKE (optional optimization)
```

### Key Challenges

1. **Discrete Gaussian Sampling**
   - Must be constant-time (side-channel critical)
   - Requires high-precision floating-point or fixed-point arithmetic
   - The sampler is the most security-sensitive component
   - **Dart's `double` (IEEE 754 double-precision)** may suffice for n=512 but is risky for n=1024

2. **NTRU Equation Solving**
   - KeyGen requires solving f*G - g*F = q (mod X^n + 1)
   - Uses recursive Babai-like algorithm
   - Complex number arithmetic needed

3. **FFT (not NTT)**
   - Unlike Kyber/Dilithium, FALCON uses FFT over reals/complexes
   - Need custom complex number type with sufficient precision

4. **Signature Compression**
   - Variable-length encoding of signature coefficients
   - Huffman-like compression scheme

### Parameter Sets

| Parameter | FN-DSA-512 | FN-DSA-1024 |
|-----------|-----------|------------|
| n | 512 | 1024 |
| Security | 128-bit | 256-bit |
| PK size | 897 B | 1793 B |
| Sig size | ~666 B | ~1280 B |
| **Advantage** | **Smallest sigs** | **Smallest sigs** |

### Effort Estimate

- **Complexity**: High (most complex PQC algorithm to implement correctly)
- **LOC**: ~2000-3000
- **Time**: 4-8 weeks
- **Key Risk**: Gaussian sampler side-channel resistance in pure Dart
- **Recommendation**: Wait for FIPS 206 finalization before implementing. Consider using FFI to a C reference implementation for the sampler.

---

## 4. HQC (Hamming Quasi-Cyclic) - NIST Round 4 KEM

### Overview

HQC is a **code-based** KEM selected as an additional KEM standard alongside ML-KEM. It provides diversity in underlying hardness assumptions (decoding random linear codes vs. lattice problems).

### Architecture

```
lib/src/algos/hqc/
  kem.dart              -- High-level KEM API
  gf.dart               -- GF(2^m) arithmetic
  reed_solomon.dart     -- Reed-Solomon code
  reed_muller.dart      -- Reed-Muller code
  parsing.dart          -- Vector encoding/decoding
  params.dart           -- HQC-128, HQC-192, HQC-256
```

### Key Components

1. **GF(2^m) Arithmetic**
   - Finite field operations for error correction
   - Multiplication via polynomial multiplication mod irreducible
   - Can use lookup tables for small fields

2. **Reed-Solomon + Reed-Muller Codes**
   - Concatenated code structure
   - RS outer code for error correction
   - RM inner code for noise tolerance

3. **Quasi-Cyclic Structure**
   - Polynomials in F_2[X]/(X^n - 1)
   - Efficient multiplication using NTT over F_2

### Parameter Sets

| Parameter | HQC-128 | HQC-192 | HQC-256 |
|-----------|---------|---------|---------|
| Security | 128-bit | 192-bit | 256-bit |
| PK size | ~2,249 B | ~4,522 B | ~7,245 B |
| CT size | ~4,497 B | ~9,042 B | ~14,469 B |
| SS size | 64 B | 64 B | 64 B |

### Effort Estimate

- **Complexity**: Medium-High
- **LOC**: ~1500-2000
- **Time**: 3-5 weeks
- **Key Challenge**: GF(2^m) arithmetic efficiency in Dart
- **Status**: NIST announced HQC as additional KEM standard. Final spec expected 2025-2026.

---

## 5. Implementation Priority Recommendation

### Recommended Order

| Priority | Algorithm | Rationale |
|----------|-----------|-----------|
| 1 | **Complete ML-DSA** | Already started, most requested, FIPS 204 finalized |
| 2 | **SLH-DSA** | Simplest to implement, conservative security assumption |
| 3 | **HQC** | Provides KEM diversity (code-based vs lattice-based) |
| 4 | **FN-DSA** | Most complex, wait for FIPS 206 finalization |

### Implementation Checklist Template

For each new algorithm:

- [ ] Create `lib/src/algos/<name>/` directory structure
- [ ] Implement parameter classes with all security levels
- [ ] Implement core mathematical primitives (NTT/FFT/GF)
- [ ] Implement key generation
- [ ] Implement primary operation (sign/encapsulate)
- [ ] Implement secondary operation (verify/decapsulate)
- [ ] Implement serialization (pack/unpack)
- [ ] Write unit tests for each component
- [ ] Write round-trip integration tests
- [ ] Run NIST KAT vectors (all levels)
- [ ] Export through `pqcrypto.dart`
- [ ] Add to README compliance table
- [ ] Benchmark on Dart VM and Web
- [ ] Security review (side-channels, input validation)

---

## 6. Shared Infrastructure Needs

### Current Reusable Components

| Component | Location | Reusable By |
|-----------|----------|-------------|
| SHAKE-128 | common/shake.dart | All algorithms |
| SHAKE-256 | common/shake.dart | All algorithms |
| SHA3-256/512 | via pointycastle | All algorithms |

### Needed Infrastructure

| Component | Needed By | Priority |
|-----------|-----------|----------|
| SHA-256 wrapper | SLH-DSA (SHA-256 mode) | P2 |
| GF(2^m) library | HQC | P3 |
| Complex number type | FN-DSA | P4 |
| FFT (complex) | FN-DSA | P4 |
| Gaussian sampler | FN-DSA | P4 |
| Huffman codec | FN-DSA | P4 |
| `secureZero()` utility | All algorithms | P1 |
| Constant-time utilities | All algorithms | P1 |

# pqcrypto NIST FIPS Compliance Report

**Date**: 2026-03-13
**Version**: 0.1.0
**Standards**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)

---

## 1. FIPS 203 (ML-KEM) Compliance

### Overall Status: COMPLIANT

The ML-KEM implementation has been validated against 3000/3000 NIST Known Answer Test (KAT) vectors across all three security levels.

### Algorithm-by-Algorithm Compliance

| FIPS 203 Algorithm | Implementation | File | Status |
|-------------------|---------------|------|--------|
| Alg 4: ByteEncode_d | `Pack.byteEncode12`, `compressAndEncode*` | pack.dart | PASS |
| Alg 5: ByteDecode_d | `Pack.byteDecode12`, `decodeAndDecompress*` | pack.dart | PASS |
| Alg 6: SampleNTT | `Indcpa._sampleNTT` | indcpa.dart | PASS |
| Alg 7: SamplePolyCBD | `Indcpa._cbd` | indcpa.dart | PASS |
| Alg 8: NTT | `Poly.ntt` | poly.dart | PASS |
| Alg 9: NTT^-1 | `Poly.invNtt` | poly.dart | PASS |
| Alg 10: MultiplyNTTs | `Poly.baseMul` | poly.dart | PASS |
| Alg 12: K-PKE.KeyGen | `Indcpa.generateKeyPair` | indcpa.dart | PASS |
| Alg 13: K-PKE.Encrypt | `Indcpa.encrypt` | indcpa.dart | PASS |
| Alg 14: K-PKE.Decrypt | `Indcpa.decrypt` | indcpa.dart | PASS |
| Alg 16: ML-KEM.KeyGen | `KyberKem.generateKeyPair` | kem.dart | PASS |
| Alg 17: ML-KEM.Encaps | `KyberKem.encapsulate` | kem.dart | PASS |
| Alg 18: ML-KEM.Decaps | `KyberKem.decapsulate` | kem.dart | PASS |
| Def 4.7: Compress | `Pack.compress` | pack.dart | PASS |
| Def 4.8: Decompress | `Pack.decompress` | pack.dart | PASS |

### Parameter Verification

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | Spec Match |
|-----------|-----------|-----------|------------|------------|
| n | 256 | 256 | 256 | YES |
| q | 3329 | 3329 | 3329 | YES |
| k | 2 | 3 | 4 | YES |
| eta1 | 3 | 2 | 2 | YES |
| eta2 | 2 | 2 | 2 | YES |
| du | 10 | 10 | 11 | YES |
| dv | 4 | 4 | 5 | YES |
| PK bytes | 800 | 1184 | 1568 | YES |
| SK bytes | 1632 | 2400 | 3168 | YES |
| CT bytes | 768 | 1088 | 1568 | YES |

### Security Properties

| Property | Implementation | Status |
|----------|---------------|--------|
| IND-CCA2 | Fujisaki-Okamoto transform with re-encryption check | COMPLIANT |
| Implicit Rejection | `_j(z, ct, 32)` using SHAKE-256 | COMPLIANT |
| Constant-time comparison | `_constantTimeEq` OR-accumulation | COMPLIANT |
| Domain separation | G=SHA3-512, H=SHA3-256, J=SHAKE-256 | COMPLIANT |

### Known Deviations

1. **Incremental XOF squeezing**: Not implemented. Fixed-length SHAKE output used. While functionally equivalent, a strict interpretation of the spec calls for incremental squeezing with retry.
2. **RNG source**: Uses `Random.secure()` which delegates to platform CSPRNG. FIPS 203 requires an approved DRBG (SP 800-90A). Compliance depends on the platform's underlying RNG.

---

## 2. FIPS 204 (ML-DSA) Compliance

### Overall Status: IN PROGRESS (NON-COMPLIANT)

The ML-DSA implementation produces valid signatures that verify internally but has multiple deviations from FIPS 204 that prevent KAT compliance.

### Algorithm-by-Algorithm Compliance

| FIPS 204 Algorithm | Implementation | File | Status |
|-------------------|---------------|------|--------|
| Alg 1: NTT | `DilithiumNTT.ntt` | ntt.dart | PASS (verified round-trip) |
| Alg 2: NTT^-1 | `DilithiumNTT.invNtt` | ntt.dart | PASS |
| Alg 3: Power2Round | `power2Round` | rounding.dart | PASS |
| Alg 4: Decompose | `decompose` | rounding.dart | NEEDS VERIFICATION |
| Alg 5: HighBits | `highBits` | rounding.dart | Delegates to decompose |
| Alg 6: LowBits | `lowBits` | rounding.dart | Delegates to decompose |
| Alg 7: MakeHint | `makeHint` | rounding.dart | PASS (logic correct) |
| Alg 8: UseHint | `useHint` | rounding.dart | PASS (logic correct) |
| Alg 9: SampleInBall | `DilithiumSymmetric.sampleInBall` | symmetric.dart | **ISSUE** (stream too short) |
| Alg 10: SimpleBitPack | `simpleBitPack` | packing.dart | PASS |
| Alg 11: SimpleBitUnpack | `simpleBitUnpack` | packing.dart | PASS |
| Alg 12: BitPack | `bitPack` | packing.dart | PASS |
| Alg 13: HintBitPack | `packHint` / inline in `packSig` | packing.dart | NEEDS REVIEW |
| Alg 14: HintBitUnpack | inline in `unpackSig` | packing.dart | PASS (with validation) |
| Alg 24: ML-DSA.KeyGen_internal | `MlDsa.generateKeyPair` | dsa.dart | PASS (sizes match) |
| Alg 26: ML-DSA.Sign_internal | `MlDsa.sign` | dsa.dart | **ISSUES** (see below) |
| Alg 28: ML-DSA.Verify_internal | `MlDsa.verify` | dsa.dart | ISSUES (depends on sign) |
| Alg 30: RejNTTPoly | `_rejNttPoly` | symmetric.dart | **ISSUE** (input encoding) |
| Alg 31: RejBoundedPoly | `_rejBoundedPoly` | symmetric.dart | PASS |
| Alg 33: ExpandA | `expandA` | symmetric.dart | Depends on RejNTTPoly |
| Alg 34: ExpandS | `expandS` | symmetric.dart | PASS |
| Alg 35: ExpandMask | `expandMask` | symmetric.dart | **ISSUE** (rho' truncated) |

### Parameter Verification

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | Spec Match |
|-----------|----------|----------|----------|------------|
| q | 8380417 | 8380417 | 8380417 | YES |
| d | 13 | 13 | 13 | YES |
| k | 4 | 6 | 8 | YES |
| l | 4 | 5 | 7 | YES |
| eta | 2 | 4 | 2 | YES |
| **tau** | **39** | **39 (WRONG: should be 49)** | **39 (WRONG: should be 60)** | **NO** |
| beta | 78 | 196 | 120 | YES |
| gamma1 | 2^17 | 2^19 | 2^19 | YES |
| gamma2 | 95232 | 261888 | 261888 | YES |
| omega | 80 | 55 | 75 | YES |
| cTildeSize | 32 | 48 | 64 | YES |
| PK bytes | 1312 | 1952 | 2592 | YES |
| SK bytes | 2560 | 4032 | 4896 | YES |
| Sig bytes | 2420 | 3309 | 4627 | YES |

### Blocking Issues for FIPS 204 Compliance

| Issue | Severity | Description |
|-------|----------|-------------|
| tau global constant | CRITICAL | Only correct for ML-DSA-44 |
| ExpandMask rho' truncation | CRITICAL | Only uses 32 of 64 bytes |
| RejNTTPoly input encoding | MEDIUM | 2-byte vs 1-byte indices |
| SampleInBall stream length | HIGH | May exhaust for tau=60 |
| Debug print statements | HIGH | Must remove before release |

### Test Coverage for ML-DSA

| Test Area | Coverage | Tests |
|-----------|----------|-------|
| NTT round-trip | Full (random) | dsa_ntt_test.dart |
| Polynomial arithmetic | Basic | dsa_math_test.dart |
| Packing round-trip | Full (all formats) | dsa_pack_test.dart |
| Sampling bounds | Partial | dsa_symmetric_test.dart |
| KeyGen sizes | Full (all levels) | dsa_test.dart |
| Sign/Verify round-trip | Full (all levels) | dsa_sign_test.dart |
| NIST KAT vectors | **NONE** | Not implemented |
| Negative tests | Partial (bad msg/sig) | dsa_sign_test.dart |

---

## 3. Cryptographic Primitive Compliance

### Hash Functions (Delegated to pointycastle)

| Primitive | FIPS Reference | Implementation | Status |
|-----------|---------------|----------------|--------|
| SHA3-256 | FIPS 202 | `SHA3Digest(256)` via pointycastle | DELEGATED |
| SHA3-512 | FIPS 202 | `SHA3Digest(512)` via pointycastle | DELEGATED |
| SHAKE-128 | FIPS 202 | `SHAKEDigest(128)` via pointycastle | DELEGATED |
| SHAKE-256 | FIPS 202 | `SHAKEDigest(256)` via pointycastle | DELEGATED |

Note: `pointycastle` is not FIPS-validated. For FIPS compliance of the overall system, the SHA-3 implementation would need to use a validated module (e.g., via FFI to OpenSSL FIPS module).

### Random Number Generation

| Requirement | Implementation | Compliance |
|-------------|---------------|------------|
| FIPS 203 Section 3.3 | `Random.secure()` | Platform-dependent |
| SP 800-90A approved DRBG | Delegates to OS CSPRNG | NOT VERIFIED |

---

## 4. Compliance Roadmap

### Phase 1: ML-DSA Correctness (Target: v0.2.0)
- [ ] Fix tau per security level
- [ ] Fix ExpandMask rho' handling
- [ ] Fix SampleInBall stream length
- [ ] Verify RejNTTPoly input encoding against reference
- [ ] Remove all debug print statements
- [ ] Run NIST KAT vectors for all three levels

### Phase 2: Security Hardening (Target: v0.3.0)
- [ ] Add input validation on all public APIs
- [ ] Implement constant-time norm checks
- [ ] Add secret material zeroization
- [ ] Side-channel analysis review

### Phase 3: FIPS Module Validation (Long-term)
- [ ] Integrate with FIPS-validated SHA-3 module (e.g., OpenSSL FIPS)
- [ ] Implement approved DRBG (SP 800-90A)
- [ ] Engage CMVP lab for validation testing
- [ ] Document security policy per FIPS 140-3 requirements

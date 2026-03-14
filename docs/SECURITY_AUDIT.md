# pqcrypto Security Audit Report

**Auditor**: Automated Deep Code Audit
**Date**: 2026-03-13
**Scope**: Full codebase (`lib/`, `test/`, `tool/`)
**Version**: 0.1.0 (commit `176e2b4`)

---

## Executive Summary

This audit covers the `pqcrypto` Dart library implementing ML-KEM (FIPS 203) and ML-DSA (FIPS 204). The ML-KEM implementation is **production-quality** with 3000/3000 NIST KAT vectors passing. The ML-DSA implementation is **in active development** and contains several critical issues that must be resolved before any production use.

| Component | Severity Summary |
|-----------|-----------------|
| ML-KEM (Kyber) | 2 Medium, 3 Low |
| ML-DSA (Dilithium) | 4 Critical, 3 High, 2 Medium |
| Common (Poly/SHAKE) | 1 Medium |

---

## CRITICAL Findings

### CRIT-01: ML-DSA `tau` Hardcoded as Global Constant [RESOLVED]

**File**: `lib/src/algos/dilithium/params.dart`
**Severity**: CRITICAL
**CVSS**: N/A (correctness issue preventing FIPS 204 compliance)
**Resolution**: QW-01. `tau` added to `DilithiumParams` with values 39/49/60. Regression test: `quick_wins_test.dart`.

The `tau` parameter (number of +/-1 coefficients in the challenge polynomial) is defined as a single global constant `const int tau = 39`. Per FIPS 204, `tau` varies by security level:

| Parameter Set | Correct tau | Current Code |
|--------------|-------------|-------------|
| ML-DSA-44 | 39 | 39 (correct by accident) |
| ML-DSA-65 | 49 | **39 (WRONG)** |
| ML-DSA-87 | 60 | **39 (WRONG)** |

**Impact**: ML-DSA-65 and ML-DSA-87 signatures will have reduced security weight in the challenge polynomial. Signatures may still "work" (sign/verify internally) but are **non-compliant** and have weaker security guarantees. NIST KAT vectors will fail for ML-DSA-65 and ML-DSA-87.

**Recommendation**: Add `tau` as a field in `DilithiumParams` class with correct per-level values.

---

### CRIT-02: Debug `print()` Statements Leak Cryptographic Intermediates [RESOLVED]

**File**: `lib/src/algos/dilithium/dsa.dart`, `lib/src/algos/dilithium/packing.dart`
**Severity**: CRITICAL
**CWE**: CWE-532 (Insertion of Sensitive Information into Log File)
**Resolution**: QW-02. All `print()` removed from `lib/`. QW-09: `avoid_print` lint rule enforced as error to prevent regression.

The ML-DSA `sign()` and `verify()` functions contain extensive `print()` calls that output:
- Hashes of secret key components (`s1Hat`, `s2Hat`, `t0Hat`)
- Hashes of intermediate values (`mu`, `w1`, `cTilde`, `z`, `h`)
- NTT-domain values of the challenge polynomial `c`
- The `cTilde` challenge seed in full

These values, if captured in logs or console output, constitute a **partial key recovery oracle**. An attacker observing signing logs could reconstruct the challenge polynomial and perform lattice reduction attacks on the signature scheme.

**Impact**: Complete loss of signature security if logs are captured.

**Recommendation**: Remove ALL `print()` statements from cryptographic code. Use a debug flag or conditional compilation (`assert()`) for development only.

---

### CRIT-03: ML-DSA `SampleInBall` Insufficient Stream Length [RESOLVED]

**File**: `lib/src/algos/dilithium/symmetric.dart`
**Severity**: CRITICAL
**Resolution**: QW-03. Stream increased from 256 to 840 bytes (6 SHAKE-256 blocks). Stress test: 100 seeds with tau=60 in `quick_wins_test.dart`.

```dart
final stream = Shake256.shake(rho, 256); // Safe amount?
```

The stream is fixed at 256 bytes. For ML-DSA-87 with `tau=60`, the rejection sampling loop needs up to 60 samples where each sample from a byte must satisfy `byte <= i` for `i` in `[196, 255]`. The worst-case rejection rate occurs when `i` is small (e.g., `i=196` rejects ~23.4% of bytes).

With 256 - 8 = 248 usable bytes and needing up to 60 accepted values with rejection, the probability of stream exhaustion is **non-negligible** for ML-DSA-87. Even the comment in the code acknowledges this with "Safe amount?".

**Impact**: `SampleInBall` may throw an exception during signing for ML-DSA-87, causing denial of service or forcing retry loops.

**Recommendation**: Increase stream to at least 840 bytes (`SHAKE256` rate * 6 blocks) or implement incremental squeezing.

---

### CRIT-04: ML-DSA `ExpandMask` Truncates 64-byte `rho'` to 32 bytes [RESOLVED]

**File**: `lib/src/algos/dilithium/symmetric.dart`
**Severity**: CRITICAL
**Resolution**: QW-04. Input buffer changed to `Uint8List(64 + 2)`, copies all 64 bytes. Regression test: `quick_wins_test.dart` verifies upper 32 bytes influence output.

```dart
static DilithiumPoly _rejGamma1(Uint8List rho, int nonce, int gamma1) {
    final input = Uint8List(32 + 2);  // Only takes 32 bytes from rho'
    input.setRange(0, 32, rho);
```

FIPS 204 specifies that `rho'` (used for mask generation) is 64 bytes. The `_rejGamma1` function constructs a 34-byte input buffer but the caller passes a 64-byte `rhoPrime`. Only the first 32 bytes are used.

**Impact**: The masking vector `y` only depends on half the entropy of `rho'`. While this does not immediately break security (32 bytes of entropy is still 256 bits), it violates FIPS 204 and will fail NIST KAT validation.

**Recommendation**: Change input buffer to `Uint8List(64 + 2)` and copy all 64 bytes of `rho'`.

---

## HIGH Severity Findings

### HIGH-01: No Zeroization of Secret Key Material

**Files**: All cryptographic modules
**Severity**: HIGH
**CWE**: CWE-244 (Improper Clearing of Heap Memory)

Neither ML-KEM nor ML-DSA implementations zeroize sensitive data after use:
- Secret key polynomial coefficients remain in memory
- Intermediate values (`rhoSigma`, `sigma`, `kKey`, `rhoPrime`) are never cleared
- SHAKE digest internal states are `reset()` but not zeroized

In Dart, there is no `memset_s` equivalent, and the GC may delay collection. However, `Uint8List.fillRange(0, length, 0)` should be called on all sensitive buffers in `finally` blocks.

**Impact**: Secret keys persist in process memory after use, vulnerable to memory dump attacks, cold boot attacks, or process memory inspection.

**Recommendation**: Implement a `secureZero()` helper and apply it to all secret material in `finally` blocks. Consider using `dart:ffi` for guaranteed zeroization on native platforms.

---

### HIGH-02: No Input Validation on Public Key / Ciphertext Sizes [RESOLVED]

**File**: `lib/src/algos/kyber/kem.dart`
**Severity**: HIGH
**CWE**: CWE-20 (Improper Input Validation)
**Resolution**: QW-10. `ArgumentError` guards added to `encapsulate()` (pk size) and `decapsulate()` (sk size, ct size). Regression test: `quick_wins_test.dart`.

The `encapsulate()` and `decapsulate()` methods accept `Uint8List` inputs without validating sizes:

```dart
(Uint8List ct, Uint8List ss) encapsulate(Uint8List pk, [Uint8List? nonce]) {
    // No check: pk.length == params.publicKeyBytes
```

```dart
Uint8List decapsulate(Uint8List sk, Uint8List ct) {
    // No check: sk.length == params.secretKeyBytes
    // No check: ct.length == params.ciphertextBytes
```

**Impact**: Malformed inputs cause array index out-of-bounds exceptions that leak timing information. An attacker could probe the implementation with various sizes to gain side-channel information.

**Recommendation**: Add size validation at the top of all public API methods:
```dart
if (pk.length != params.publicKeyBytes) throw ArgumentError('Invalid PK size');
```

---

### HIGH-03: ML-DSA `_checkNorm` Uses Non-Constant-Time Comparison

**File**: `lib/src/algos/dilithium/dsa.dart:463-480`
**Severity**: HIGH
**CWE**: CWE-208 (Observable Timing Discrepancy)

```dart
static bool _checkNorm(DilithiumPoly p, int bound) {
    for (int i = 0; i < 256; i++) {
      int t = p.coeffs[i];
      if (t > (q >> 1)) t -= q;
      if (t.abs() >= bound) return true;  // Early return leaks position
    }
    return false;
}
```

The function returns `true` immediately when a coefficient exceeds the bound. The timing difference reveals which coefficient (if any) exceeded the norm, which leaks information about the secret key in the signing rejection loop.

**Impact**: Timing side-channel allows partial secret key recovery through repeated signature observations.

**Recommendation**: Accumulate result in a flag and return after processing all coefficients.

---

## MEDIUM Severity Findings

### MED-01: `Random.secure()` Instantiated on Every Call

**File**: `lib/src/algos/kyber/kem.dart:148`
**Severity**: MEDIUM

```dart
Uint8List _randomBytes(int len) {
    final rng = Random.secure();  // New instance every call
    return Uint8List.fromList(List.generate(len, (_) => rng.nextInt(256)));
}
```

Creating a new `Random.secure()` on every call is unnecessary overhead and may cause entropy pool contention on some platforms.

**Recommendation**: Use a single static or instance-level `Random.secure()` or pass an RNG parameter.

---

### MED-02: Kyber `_genMatrixPoly` Uses Fixed Stream Length Without Fallback

**File**: `lib/src/algos/kyber/indcpa.dart:203`
**Severity**: MEDIUM

```dart
final stream = Shake128.shake(input, 672); // 4 blocks = 672 bytes.
```

The comment in `_sampleNTT` (line 233) acknowledges "Fallback? If we run out of stream, technically we should squeeze more." With 672 bytes and rejection rate ~3329/4096 (~81% acceptance), the expected accepted samples from 672/3*2 = 448 candidates is ~363, well above 256. However, the theoretical failure probability, while very small, is non-zero.

**Recommendation**: Implement incremental squeezing or increase buffer to 840 bytes (5 blocks).

---

### MED-03: `KyberLevel` Enum Defined in Two Files [RESOLVED]

**File**: `lib/src/algos/kyber/params.dart` and `lib/src/algos/kyber/kem.dart`
**Severity**: MEDIUM (Code Quality)
**Resolution**: QW-07. Duplicate removed from `params.dart`. Canonical definition in `kem.dart`.

---

### MED-04: ML-DSA `_rejNttPoly` Constructs Both 34-byte and 36-byte Inputs [PARTIALLY RESOLVED]

**File**: `lib/src/algos/dilithium/symmetric.dart`
**Severity**: MEDIUM
**Resolution**: QW-06. Dead 34-byte `input` buffer removed. Encoding question (1-byte vs 2-byte index) remains OPEN pending FIPS 204 final spec verification.

FIPS 204 specifies: `rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)` = 34 bytes total (since s,r < 256 for all parameter sets). However, the function uses `IntegerToBytes(x, 2)` encoding (2 bytes each), producing 36 bytes.

**Impact**: If the reference implementation uses 1-byte encoding, all A-matrix entries will be wrong, causing complete failure. The round-trip tests pass, suggesting internal consistency, but NIST KAT validation may fail.

**Recommendation**: Verify against FIPS 204 final spec and reference implementation. Remove dead code.

---

## LOW Severity Findings

### LOW-01: Barrett Reduction in `Poly` May Produce Values >= q

**File**: `lib/src/common/poly.dart:20-26`

```dart
static int barrettReduce(int a) {
    const int v = 20159;
    int shift = 26;
    int product = (a * v) >> shift;
    int res = a - product * q;
    return res;  // May be in [0, 2q-1]
}
```

Barrett reduction can produce values in `[0, 2q-1]`. A final conditional subtraction is needed for strict `[0, q-1]` output. The NTT butterfly operations call `_fieldAdd` and `_fieldSub` which perform single conditional reductions, compensating for this. However, using `barrettReduce` output directly in comparisons could be incorrect.

---

### LOW-02: `_listEquals` in KAT Evaluator Not Constant-Time

**File**: `test/kat_evaluator.dart:181-186`
**Severity**: LOW (test-only code, not security-relevant)

---

### LOW-03: Kyber `Indcpa._polySub` Single Reduction May Be Insufficient

**File**: `lib/src/algos/kyber/indcpa.dart:342-350`

If `a.coeffs[i]` has not been reduced and is greater than `2q`, then `a - b + q` may still be negative (if `b` is large). However, in practice the calling code always reduces before subtraction, so this is not exploitable.

---

## Side-Channel Resistance Summary

| Operation | Constant-Time? | Notes |
|-----------|---------------|-------|
| ML-KEM `_constantTimeEq` | Yes | Correct OR-accumulation pattern |
| ML-KEM Decapsulation branch | Yes | Uses `_constantTimeEq` result |
| ML-KEM NTT multiplication | Partial | Barrett reduction is data-independent, but Dart `%` operator may not be |
| ML-DSA `_checkNorm` | **No** | Early return on first violation |
| ML-DSA NTT `(a * b) % q` | **No** | Dart `%` operator timing may vary with operand size |
| ML-DSA `decompose` | **No** | Branch on `r - r0 == q - 1` |
| ML-DSA hint generation | **No** | Multiple data-dependent branches |
| SHAKE-128/256 | Delegated | Depends on `pointycastle` implementation |

---

## Recommendations Priority Matrix

| Priority | Action | Effort |
|----------|--------|--------|
| P0 | Fix `tau` per security level | 30 min |
| P0 | Remove all `print()` from crypto code | 30 min |
| P0 | Fix `SampleInBall` stream length | 15 min |
| P0 | Fix `ExpandMask` rho' truncation | 15 min |
| P1 | Add input size validation | 1 hour |
| P1 | Implement secret material zeroization | 2 hours |
| P1 | Make `_checkNorm` constant-time | 30 min |
| P2 | Verify `_rejNttPoly` input encoding against FIPS 204 | 2 hours |
| P2 | Implement incremental SHAKE squeezing | 4 hours |
| P3 | Cache `Random.secure()` instance | 15 min |
| P3 | Remove duplicate `KyberLevel` enum | 10 min |

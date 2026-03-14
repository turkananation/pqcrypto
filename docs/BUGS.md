# pqcrypto Known Bugs & Issues

**Date**: 2026-03-13
**Version**: 0.1.0

---

## Status Key

| Status | Meaning |
|--------|---------|
| OPEN | Confirmed, not yet fixed |
| WIP | Fix in progress |
| FIXED | Fix applied and regression-tested |
| VERIFIED | Tested and confirmed with KAT |

---

## Critical Bugs

### BUG-001: `tau` Global Constant Breaks ML-DSA-65 and ML-DSA-87

**Status**: FIXED (QW-01, test: quick_wins_test.dart)
**Component**: ML-DSA
**File**: `lib/src/algos/dilithium/params.dart:8`
**Affects**: ML-DSA-65, ML-DSA-87 correctness and security

**Description**: `tau` is defined as `const int tau = 39` at module scope. Per FIPS 204 Table 1:
- ML-DSA-44: tau = 39
- ML-DSA-65: tau = 49
- ML-DSA-87: tau = 60

The `SampleInBall` function and all callers use this global `tau`, meaning ML-DSA-65/87 generate challenge polynomials with only 39 non-zero coefficients instead of the required 49/60.

**Fix**: Add `tau` field to `DilithiumParams`:
```dart
class DilithiumParams {
  final int tau; // Add this
  // ...
  static const mlDsa44 = DilithiumParams._(..., 39, ...);
  static const mlDsa65 = DilithiumParams._(..., 49, ...);
  static const mlDsa87 = DilithiumParams._(..., 60, ...);
}
```

Then update all call sites: `dsa.dart:278`, `dsa.dart:571`.

---

### BUG-002: `ExpandMask`/`_rejGamma1` Input Buffer Truncates `rho'`

**Status**: FIXED (QW-04, test: quick_wins_test.dart)
**Component**: ML-DSA
**File**: `lib/src/algos/dilithium/symmetric.dart:220`

**Description**: `rho'` is 64 bytes (output of `CRH`), but `_rejGamma1` creates a `Uint8List(32 + 2)` input, only copying the first 32 bytes.

```dart
final input = Uint8List(32 + 2);        // Should be 64 + 2
input.setRange(0, 32, rho);             // Should copy 64 bytes
```

**Impact**: All masking vectors `y` are derived from only half the entropy. NIST KAT vectors will not match.

**Fix**:
```dart
final input = Uint8List(64 + 2);
input.setRange(0, 64, rho);
input[64] = nonce & 0xFF;
input[65] = (nonce >> 8) & 0xFF;
```

---

### BUG-003: ML-DSA `SampleInBall` Stream Too Short for ML-DSA-87

**Status**: FIXED (QW-03, test: quick_wins_test.dart)
**Component**: ML-DSA
**File**: `lib/src/algos/dilithium/symmetric.dart:357`

**Description**: `Shake256.shake(rho, 256)` produces only 248 usable bytes (256 - 8 sign bytes). For `tau=60` (ML-DSA-87), the rejection sampling needs to place 60 coefficients. When `i` is in range `[196, 217]`, many random bytes are rejected (`byte > i`), consuming bytes quickly.

Expected bytes consumed with worst-case rejection: ~73 bytes for ML-DSA-87, but variance can push this to ~90+ bytes. 248 bytes is likely sufficient for most cases but the tail probability of exhaustion is concerning.

**Fix**: Increase to `Shake256.shake(rho, 840)` (6 SHAKE-256 blocks).

---

### BUG-004: `_rejNttPoly` Dead Code and Possible Wrong Input Encoding

**Status**: FIXED (dead code removed via QW-06; encoding question remains OPEN)
**Component**: ML-DSA
**File**: `lib/src/algos/dilithium/symmetric.dart:59-86`

**Description**: Two input buffers are constructed:
1. `input` (34 bytes) - unused dead code
2. `inputStrict` (36 bytes) - used with 2-byte index encoding

FIPS 204 Algorithm 30 (RejNTTPoly) specifies `rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)` for the XOF seed when indices fit in a single byte. However, some reference implementations use 2-byte encoding. This needs verification against the final FIPS 204 spec.

**Impact**: If encoding is wrong, the A matrix is completely different from the specification, causing total failure against NIST KAT vectors (even if internal round-trip tests pass).

---

## High Bugs

### BUG-005: ML-DSA `t0` Packing May Lose Sign Information

**Status**: OPEN
**Component**: ML-DSA Packing
**File**: `lib/src/algos/dilithium/packing.dart:219-223`

**Description**: `t0` coefficients are in the centered range `[-2^(d-1), 2^(d-1)]` = `[-4096, 4096]`. The `packSK` function uses:
```dart
final packed = simpleBitPack(t0[i], 13);
```

`simpleBitPack` expects non-negative values in `[0, 2^b - 1]`. If `t0` coefficients are stored as negative integers or as values > `2^13`, this will produce incorrect packing. The `unpackSK` function compensates with sign correction logic (lines 278-289), but this only works if the pack-side mapping is consistent.

**Verification needed**: Trace the `t0` coefficient range through `power2Round` -> `packSK` -> `unpackSK` to confirm round-trip correctness.

---

### BUG-006: Debug `print()` Statements in Production Code

**Status**: FIXED (QW-02, verified: `grep print lib/` returns 0 matches; QW-09 lint prevents regression)
**Component**: ML-DSA
**File**: `lib/src/algos/dilithium/dsa.dart` (20+ locations)

**Description**: The `sign()` function alone contains 15+ `print()` calls that output cryptographic intermediate values every signing operation. The `verify()` function contains 10+ similar calls. The `packing.dart` file also contains debug prints in `bitPackZ` and `bitUnpackZ`.

These are not behind any debug flag or `assert()` guard.

---

### BUG-007: `KyberLevel` Enum Defined Twice

**Status**: FIXED (QW-07, removed duplicate from params.dart)
**Component**: ML-KEM
**Files**: `lib/src/algos/kyber/params.dart:27`, `lib/src/algos/kyber/kem.dart:10`

**Description**: The `KyberLevel` enum exists in both files. The one in `kem.dart` is used for the factory constructor. The one in `params.dart` is unused but could cause confusion or import conflicts.

---

## Medium Bugs

### BUG-008: ML-KEM `encapsulate` Shared Secret Comparison Uses `toString()`

**File**: `example/main.dart:31` and `README.md:150`

**Description**: Example and documentation compare shared secrets using:
```dart
assert(ssAlice.toString() == ssBob.toString());
```

`Uint8List.toString()` produces `[a, b, c, ...]` which is correct for comparison but inefficient. If the list is very long, the string comparison may be slow and the output format is implementation-dependent.

**Recommendation**: Use `listEquals` from `package:collection` or a byte-by-byte comparison.

---

### BUG-009: ML-DSA `sign()` Uses `hashVec` with `params.k` Hardcoded for All Vectors

**File**: `lib/src/algos/dilithium/dsa.dart:413-424`

**Description**: The debug `hashVec` function inside `sign()` uses `params.k` for the flat buffer size, but it's called on vectors of both length `k` and length `l`. This is only used for debug printing and doesn't affect correctness of the signature.

---

### BUG-010: ML-DSA `verify()` Unused Variables

**File**: `lib/src/algos/dilithium/dsa.dart:494-500, 523-543`

**Description**: The verify function allocates `t1Flat`, `t1View` for debug hashing, and the inner `hashVec` function creates `flat` and `view` variables that shadow outer variables. This is wasteful but functionally harmless.

---

## Low / Cosmetic Issues

### BUG-011: Library Docstring is Placeholder

**Status**: FIXED (QW-08)

**File**: `lib/pqcrypto.dart:1-4`

### BUG-012: ML-DSA Not Exported

**Status**: FIXED (QW-05, test: quick_wins_test.dart)

**File**: `lib/pqcrypto.dart`

### BUG-013: `ignore: unused_import` in `indcpa.dart`

**File**: `lib/src/algos/kyber/indcpa.dart:7`
```dart
// ignore: unused_import
import 'package:pqcrypto/src/algos/kyber/pack.dart';
```

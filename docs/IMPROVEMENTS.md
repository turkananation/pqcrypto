# pqcrypto Improvements & Recommendations

**Date**: 2026-03-14
**Version**: 0.1.0

---

## 1. Correctness Improvements (Must-Fix)

### IMP-01: Make ML-DSA Parameters Complete

The `DilithiumParams` class is missing the `tau` parameter. Current global `const int tau = 39` is correct only for ML-DSA-44.

```
Required additions to DilithiumParams:
  - tau (int): 39, 49, 60 for ML-DSA-44, -65, -87
  - lambdaBytes (int): derived from cTildeSize / 2
  - signatureBytes (int): computed from gamma1, omega, k, l, cTildeSize
  - publicKeyBytes (int): 32 + k * 320
  - secretKeyBytes (int): computed from k, l, eta, d
```

### IMP-02: Remove All Debug Output from Cryptographic Code

Every `print()` in `dsa.dart` and `packing.dart` must be removed or guarded behind `assert()`:

```dart
// WRONG - runs in production
print("Sign Loop: mu: ${_toHex(mu)}...");

// ACCEPTABLE - only runs in debug/checked mode
assert(() { print("Sign Loop: mu: ${_toHex(mu)}..."); return true; }());

// BEST - remove entirely
// (no output)
```

### IMP-03: Validate Public API Inputs

Add guards at all public entry points:

```dart
(Uint8List ct, Uint8List ss) encapsulate(Uint8List pk, [Uint8List? nonce]) {
  if (pk.length != params.publicKeyBytes) {
    throw ArgumentError('Invalid public key length: ${pk.length}, expected ${params.publicKeyBytes}');
  }
  // ...
}
```

Apply to: `KyberKem.encapsulate`, `KyberKem.decapsulate`, `KyberKem.generateKeyPair`, `MlDsa.sign`, `MlDsa.verify`, `MlDsa.generateKeyPair`.

---

## 2. API Design Improvements

### IMP-04: Unified Public API

Currently only ML-KEM is exported. Create a cohesive public API:

```dart
// lib/pqcrypto.dart
library pqcrypto;

// ML-KEM (FIPS 203)
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;

// ML-DSA (FIPS 204)
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart' show DilithiumParams, DilithiumParameter;
```

### IMP-05: Consistent Naming Convention

Current naming inconsistency:

| Kyber | Dilithium | Suggested |
|-------|-----------|-----------|
| `KyberKem` | `MlDsa` | Both should use FIPS names |
| `PqcKem.kyber768` | No equivalent | `PqcDsa.mlDsa44` |
| `generateKeyPair()` | `generateKeyPair()` | Consistent |
| `encapsulate()` | `sign()` | Correct per function |

Suggested high-level API:

```dart
// Key Encapsulation
final kem = PqcKem.mlKem768;  // Rename from kyber768
final (pk, sk) = kem.generateKeyPair();
final (ct, ss) = kem.encapsulate(pk);
final ss2 = kem.decapsulate(sk, ct);

// Digital Signatures
final dsa = PqcDsa.mlDsa44;
final (pk, sk) = dsa.generateKeyPair();
final sig = dsa.sign(sk, message);
final valid = dsa.verify(pk, message, sig);
```

### IMP-06: Instance-Based DSA API

The current `MlDsa` uses static methods requiring params to be passed everywhere. Refactor to match `KyberKem`'s instance pattern:

```dart
class MlDsa {
  final DilithiumParams params;
  const MlDsa._(this.params);

  factory MlDsa(DilithiumParameter level) { ... }

  (Uint8List pk, Uint8List sk) generateKeyPair([Uint8List? seed]) { ... }
  Uint8List sign(Uint8List sk, Uint8List message) { ... }
  bool verify(Uint8List pk, Uint8List message, Uint8List sig) { ... }
}

class PqcDsa {
  static final mlDsa44 = MlDsa(DilithiumParameter.mlDsa44);
  static final mlDsa65 = MlDsa(DilithiumParameter.mlDsa65);
  static final mlDsa87 = MlDsa(DilithiumParameter.mlDsa87);
}
```

---

## 3. Security Improvements

### IMP-07: Secret Material Zeroization

```dart
/// Secure zeroization helper
void secureZero(Uint8List data) {
  data.fillRange(0, data.length, 0);
}

void secureZeroInt32(Int32List data) {
  data.fillRange(0, data.length, 0);
}
```

Apply to:

- `rhoSigma`, `sigma`, `kKey` after use in KeyGen
- `rhoPrime` after signing
- `mPrime`, `kPrime`, `rPrime` after decapsulation
- All secret polynomial coefficient lists

### IMP-08: Constant-Time Operations for ML-DSA

```dart
// Replace early-return norm check
static bool _checkNorm(DilithiumPoly p, int bound) {
  int fail = 0;
  for (int i = 0; i < 256; i++) {
    int t = p.coeffs[i];
    if (t > (q >> 1)) t -= q;
    // Constant-time: fail |= ((bound - 1 - t.abs()) >> 31)
    int absT = t ^ (t >> 31);  // abs without branch
    absT -= (t >> 31);
    fail |= ((bound - 1 - absT) >>> 31);
  }
  return fail != 0;
}
```

### IMP-09: Constant-Time Conditional Select for ML-KEM

While `_constantTimeEq` is correct, add a constant-time select:

```dart
Uint8List _constantTimeSelect(int condition, Uint8List a, Uint8List b) {
  // condition is 0 or 1
  final result = Uint8List(a.length);
  final mask = -condition;  // 0x00000000 or 0xFFFFFFFF
  for (int i = 0; i < a.length; i++) {
    result[i] = (a[i] & mask) | (b[i] & ~mask);
  }
  return result;
}
```

---

## 4. Code Quality Improvements

### IMP-10: Eliminate Dead Code

Files with dead/unreachable code:

- `indcpa.dart:7`: Unused `pack.dart` import with `// ignore: unused_import`
- `symmetric.dart:59-63`: Unused 34-byte `input` buffer (superseded by `inputStrict`)
- `dsa.dart:111-123`: `hashVec` debug function defined inside `generateKeyPair`
- `params.dart:27`: Duplicate `KyberLevel` enum

### IMP-11: Comprehensive Dartdoc

Add `///` documentation to all public classes and methods:

```dart
/// ML-KEM Key Encapsulation Mechanism (FIPS 203).
///
/// Provides IND-CCA2 secure key encapsulation using
/// Module-Learning With Errors (M-LWE).
///
/// Usage:
/// ```dart
/// final kem = PqcKem.kyber768;
/// final (pk, sk) = kem.generateKeyPair();
/// ```
class KyberKem {
```

### IMP-12: Add `@visibleForTesting` Annotations

Internal methods used by tests should be annotated:

```dart
import 'package:meta/meta.dart';

@visibleForTesting
static Poly sampleInBall(Uint8List seed, KyberParams params, {int nonce = 0}) {
```

### IMP-13: Stricter Analysis Options

Update `analysis_options.yaml`:

```yaml
include: package:lints/recommended.yaml

linter:
  rules:
    - prefer_final_locals
    - avoid_print        # Catch stray print() in lib/
    - unawaited_futures
    - prefer_const_constructors
    - prefer_const_declarations

analyzer:
  errors:
    avoid_print: error   # Prevent print() in lib/
```

---

## 5. Testing Improvements

### IMP-14: NIST KAT Vectors for ML-DSA

Implement a KAT evaluator for ML-DSA similar to `kat_evaluator.dart`:

```dart
// test/dsa_kat_evaluator.dart
void main() {
  test('NIST ML-DSA-44 KAT', () async {
    // Parse NIST response files
    // Compare: KeyGen(seed) -> (pk, sk) match
    // Compare: Sign(sk, msg) -> sig match
    // Compare: Verify(pk, msg, sig) -> true
  });
}
```

NIST KAT vectors are available at:
<https://github.com/post-quantum-cryptography/KAT>

### IMP-15: Cross-Platform Testing

Add CI jobs for:

- Dart VM (Linux, macOS, Windows)
- `dart2js` (browser)
- `dart2wasm` (browser)
- Flutter (Android, iOS emulators)

### IMP-16: Negative/Adversarial Tests

```dart
test('Decapsulate rejects truncated ciphertext', () {
  final kem = PqcKem.kyber768;
  final (pk, sk) = kem.generateKeyPair();
  final (ct, _) = kem.encapsulate(pk);
  expect(() => kem.decapsulate(sk, ct.sublist(0, 100)), throwsA(anything));
});

test('Decapsulate produces implicit rejection for modified CT', () {
  final kem = PqcKem.kyber768;
  final (pk, sk) = kem.generateKeyPair();
  final (ct, ss) = kem.encapsulate(pk);
  final badCt = Uint8List.fromList(ct);
  badCt[0] ^= 0xFF;
  final badSs = kem.decapsulate(sk, badCt);
  expect(badSs, isNot(equals(ss)));  // Should produce different key
  expect(badSs.length, 32);          // Should still be valid length
});

test('Verify rejects modified signature', () {
  // Already exists in dsa_sign_test.dart
});

test('Verify rejects wrong public key', () {
  final dsa = DilithiumParams.mlDsa44;
  final seed1 = Uint8List(32)..fillRange(0, 32, 1);
  final seed2 = Uint8List(32)..fillRange(0, 32, 2);
  final (pk1, sk1) = MlDsa.generateKeyPair(dsa, seed1);
  final (pk2, _) = MlDsa.generateKeyPair(dsa, seed2);
  final msg = Uint8List.fromList('test'.codeUnits);
  final sig = MlDsa.sign(sk1, msg, dsa);
  expect(MlDsa.verify(pk2, msg, sig, dsa), isFalse);
});
```

### IMP-17: Benchmark Tests

Add automated performance regression tests:

```dart
test('ML-KEM-768 encapsulation under 5ms', () {
  final kem = PqcKem.kyber768;
  final (pk, _) = kem.generateKeyPair();

  // Warmup
  for (var i = 0; i < 100; i++) kem.encapsulate(pk);

  final sw = Stopwatch()..start();
  for (var i = 0; i < 100; i++) kem.encapsulate(pk);
  sw.stop();

  expect(sw.elapsedMilliseconds / 100, lessThan(5.0));
});
```

---

## 6. Documentation Improvements

### IMP-18: Fix Library Docstring

Replace placeholder in `lib/pqcrypto.dart`:

```dart
/// Pure Dart Post-Quantum Cryptography library.
///
/// Implements NIST-standardized algorithms:
/// - **ML-KEM** (FIPS 203): Module-Lattice Key Encapsulation Mechanism
/// - **ML-DSA** (FIPS 204): Module-Lattice Digital Signature Algorithm
///
/// See [PqcKem] for key encapsulation and [PqcDsa] for digital signatures.
library pqcrypto;
```

### IMP-19: Update README for ML-DSA

Add ML-DSA usage examples and compliance status table:

```markdown
## ML-DSA FIPS 204 Compliance Status

| Algorithm | Status | NIST KAT | Security Level |
|-----------|--------|----------|----------------|
| ML-DSA-44 | In Progress | Pending | NIST Level 2 |
| ML-DSA-65 | In Progress | Pending | NIST Level 3 |
| ML-DSA-87 | In Progress | Pending | NIST Level 5 |
```

### IMP-20: Add CONTRIBUTING.md

Document:

- How to run tests
- Code style requirements
- PR review process
- Security vulnerability reporting

---

## 7. Quick Wins (High Impact, Low Effort)

These are changes that can be made in **under 30 minutes each** and deliver immediate correctness, security, or quality gains. Sorted by impact-to-effort ratio.

### QW-01: Fix `tau` Per Security Level (~5 min)

**Impact**: CRITICAL (fixes ML-DSA-65/87 correctness)
**Files**: `params.dart`, `dsa.dart`

Add `tau` to `DilithiumParams`, remove the global constant, update callers:

```dart
// params.dart: Add to class
final int tau;

// params.dart: In each constructor
static const mlDsa44 = DilithiumParams._( ... tau: 39 ... );
static const mlDsa65 = DilithiumParams._( ... tau: 49 ... );
static const mlDsa87 = DilithiumParams._( ... tau: 60 ... );

// dsa.dart: Change call sites (2 locations)
// line 278:  DilithiumSymmetric.sampleInBall(cSeed, tau)
//        ->  DilithiumSymmetric.sampleInBall(cSeed, params.tau)
// line 571:  DilithiumSymmetric.sampleInBall(cTilde, tau)
//        ->  DilithiumSymmetric.sampleInBall(cTilde, params.tau)
```

---

### QW-02: Delete All `print()` From Crypto Code (~10 min)

**Impact**: CRITICAL (stops leaking secret intermediates)
**Files**: `dsa.dart` (~20 calls), `packing.dart` (~3 calls)

Bulk delete. Every `print(` in these files is debug output. None is user-facing.

Lines to remove in `dsa.dart`: 125, 255-259, 269, 285-293, 411, 426-428, 435-437, 451-452, 501-503, 546-547, 549, 607-609, 663-666, 672-674, 702-707, 713.

Lines to remove in `packing.dart`: 348-352, 370.

---

### QW-03: Fix `SampleInBall` Stream Length (~2 min)

**Impact**: HIGH (prevents runtime crash on ML-DSA-87)
**File**: `symmetric.dart:357`

One-line change:

```dart
// Before:
final stream = Shake256.shake(rho, 256);
// After:
final stream = Shake256.shake(rho, 840);
```

---

### QW-04: Fix `ExpandMask` rho' Input Size (~3 min)

**Impact**: CRITICAL (fixes FIPS 204 compliance for all levels)
**File**: `symmetric.dart:220-223`

```dart
// Before:
final input = Uint8List(32 + 2);
input.setRange(0, 32, rho);
input[32] = nonce & 0xFF;
input[33] = (nonce >> 8) & 0xFF;

// After:
final input = Uint8List(64 + 2);
input.setRange(0, 64, rho);
input[64] = nonce & 0xFF;
input[65] = (nonce >> 8) & 0xFF;
```

---

### QW-05: Export ML-DSA in `pqcrypto.dart` (~1 min)

**Impact**: MEDIUM (makes ML-DSA accessible to users)
**File**: `lib/pqcrypto.dart`

```dart
export 'src/algos/kyber/kem.dart' show KyberKem, PqcKem;
export 'src/algos/dilithium/dsa.dart' show MlDsa;
export 'src/algos/dilithium/params.dart' show DilithiumParams, DilithiumParameter;
```

---

### QW-06: Remove Dead `_rejNttPoly` Input Buffer (~2 min)

**Impact**: LOW (code clarity, removes confusion)
**File**: `symmetric.dart:59-63`

Delete the unused 34-byte `input` variable that was superseded by `inputStrict`.

---

### QW-07: Remove Duplicate `KyberLevel` Enum (~1 min)

**Impact**: LOW (prevents import conflicts)
**File**: `params.dart:27`

Delete `enum KyberLevel { kem512, kem768, kem1024 }` from `params.dart`. Keep the one in `kem.dart`.

---

### QW-08: Fix Library Docstring (~1 min)

**Impact**: LOW (first impression for pub.dev users)
**File**: `lib/pqcrypto.dart:1-4`

Replace `"Support for doing something awesome"` with real description.

---

### QW-09: Add `avoid_print` Lint Rule (~2 min)

**Impact**: MEDIUM (prevents future print() regressions)
**File**: `analysis_options.yaml`

```yaml
linter:
  rules:
    - avoid_print
```

This will flag any new `print()` added to `lib/` during development.

---

### QW-10: Add Input Size Validation to ML-KEM Public API (~10 min)

**Impact**: HIGH (prevents crashes and timing leaks from malformed input)
**Files**: `kem.dart`

Add three guards:

```dart
// In encapsulate():
if (pk.length != params.publicKeyBytes) throw ArgumentError(...);

// In decapsulate():
if (sk.length != params.secretKeyBytes) throw ArgumentError(...);
if (ct.length != params.ciphertextBytes) throw ArgumentError(...);
```

---

### Quick Win Summary

| ID | Task | Time | Impact | Component |
|----|------|------|--------|-----------|
| QW-01 | Fix `tau` per level | 5 min | CRITICAL | ML-DSA |
| QW-02 | Remove all `print()` | 10 min | CRITICAL | ML-DSA |
| QW-03 | Fix `SampleInBall` stream | 2 min | HIGH | ML-DSA |
| QW-04 | Fix `ExpandMask` rho' size | 3 min | CRITICAL | ML-DSA |
| QW-05 | Export ML-DSA | 1 min | MEDIUM | API |
| QW-06 | Remove dead input buffer | 2 min | LOW | ML-DSA |
| QW-07 | Remove duplicate enum | 1 min | LOW | ML-KEM |
| QW-08 | Fix library docstring | 1 min | LOW | Docs |
| QW-09 | Add `avoid_print` lint | 2 min | MEDIUM | Quality |
| QW-10 | Add input size validation | 10 min | HIGH | ML-KEM |
| | **TOTAL** | **~37 min** | | |

Executing QW-01 through QW-04 alone (20 minutes of work) eliminates all 4 Critical findings from the security audit.

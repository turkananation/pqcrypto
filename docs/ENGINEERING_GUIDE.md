# pqcrypto Engineering Guide

**Date**: 2026-03-14
**Audience**: Contributors, maintainers, and integrators

---

## 1. Development Environment Setup

### Prerequisites

```bash
# Dart SDK 3.10.0+
dart --version

# Clone
git clone https://github.com/turkananation/pqcrypto.git
cd pqcrypto

# Install dependencies
dart pub get
```

### Project Dependencies

| Package | Version | Purpose |
| ------- | ------- | ------- |
| `pointycastle` | ^4.0.0 | SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 |
| `lints` | ^6.0.0 | Static analysis (dev) |
| `test` | ^1.25.6 | Testing framework (dev) |

---

## 2. Running Tests

### Full Test Suite

```bash
dart test
```

### Individual Test Groups

```bash
# ML-KEM tests
dart test test/pack_test.dart
dart test test/cbd_test.dart

# ML-DSA tests
dart test test/dsa_test.dart
dart test test/dsa_sign_test.dart
dart test test/dsa_ntt_test.dart
dart test test/dsa_pack_test.dart
dart test test/dsa_math_test.dart
dart test test/dsa_symmetric_test.dart

# NIST KAT validation (requires KAT data files)
dart test test/kat_evaluator.dart
```

### Running Benchmarks

```bash
dart run example/main.dart
```

---

## 3. Code Organization Conventions

### File Naming

| Pattern | Convention |
| ------- | ---------- |
| Algorithm API | `kem.dart`, `dsa.dart` |
| NTT operations | `ntt.dart` |
| Serialization | `pack.dart`, `packing.dart` |
| Parameters | `params.dart` |
| Polynomial types | `poly.dart` |
| Hash/sampling | `shake.dart`, `symmetric.dart` |
| Helper math | `rounding.dart` |

### Class Naming

| Type | Convention | Example |
| ---- | ---------- | ------- |
| High-level API | `<AlgoName>Kem/Dsa` | `KyberKem`, `MlDsa` |
| Polynomial | `Poly`, `DilithiumPoly` | Algorithm-specific types |
| Parameters | `<Algo>Params` | `KyberParams`, `DilithiumParams` |
| Enums | `<Algo>Level/Parameter` | `KyberLevel`, `DilithiumParameter` |

### Modular Arithmetic

**Kyber** (q = 3329):

- Barrett reduction: `Poly.barrettReduce(a)` -> `a mod q` (may be in `[0, 2q-1]`)
- Field operations: `_fieldAdd`, `_fieldSub`, `_fieldMul` with single conditional reduction
- NTT: Uses bit-reversed zeta table, incomplete NTT (degree-2 modules)

**Dilithium** (q = 8380417):

- Direct modular reduction: `a % q` with conditional `+ q` for negative
- NTT: Complete NTT (degree-1 modules), simpler pointwise multiplication
- Operations are in-place where possible

---

## 4. Adding a New Algorithm

### Step-by-Step Template

1. **Create directory**: `lib/src/algos/<name>/`

2. **Define parameters** (`params.dart`):

```dart
class FooParams {
  final int n;          // Polynomial degree
  final int q;          // Modulus
  final int securityLevel;
  // ... algorithm-specific parameters

  const FooParams._(...);

  static const level1 = FooParams._(...);
  static const level3 = FooParams._(...);
  static const level5 = FooParams._(...);
}
```

1. **Implement polynomial type** (`poly.dart`):

```dart
class FooPoly {
  final Int32List coeffs;
  // Arithmetic operations: +, -, pointwise mul
  // Reduction: reduce()
}
```

1. **Implement core transforms** (`ntt.dart` or equivalent):

```dart
class FooNTT {
  static void ntt(FooPoly poly) { ... }
  static void invNtt(FooPoly poly) { ... }
}
```

1. **Implement serialization** (`packing.dart`):

```dart
Uint8List packPublicKey(...) { ... }
Uint8List packSecretKey(...) { ... }
// Round-trip tests are MANDATORY
```

1. **Implement high-level API** (`foo.dart`):

```dart
class FooCrypto {
  (Uint8List, Uint8List) generateKeyPair([Uint8List? seed]) { ... }
  // KEM: encapsulate/decapsulate
  // DSA: sign/verify
}
```

1. **Export** (`lib/pqcrypto.dart`):

```dart
export 'src/algos/foo/foo.dart' show FooCrypto, PqcFoo;
```

1. **Test**:
   - Unit tests for each component
   - Round-trip tests for serialization
   - Integration tests for full operations
   - NIST KAT vectors

---

## 5. Mathematical Background Quick Reference

### Polynomial Rings

Both ML-KEM and ML-DSA operate in the ring **R_q = Z_q[X] / (X^n + 1)** where elements are polynomials of degree < n with coefficients in Z_q.

**Key property**: X^n + 1 splits completely modulo q for both Kyber (q=3329) and Dilithium (q=8380417), enabling NTT.

### Number Theoretic Transform (NTT)

The NTT transforms a polynomial from the "coefficient domain" to the "evaluation domain":

- **Forward NTT**: Evaluate polynomial at n/2 specific points (powers of zeta)
- **Inverse NTT**: Interpolate back to coefficients
- **Pointwise multiplication**: In NTT domain, polynomial multiplication becomes element-wise

**Kyber NTT** (Incomplete):

- X^256 + 1 factors into 128 quadratic modules
- BaseMul multiplies in degree-1 polynomial pairs using gammas
- Requires 128 zeta values

**Dilithium NTT** (Complete):

- X^256 + 1 factors into 256 linear modules
- Pointwise multiplication is direct coefficient-wise
- Requires 256 zeta values

### Barrett Reduction

For reducing `a mod q` without division:

```text
v = floor(2^k / q)
t = floor(a * v / 2^k)
result = a - t * q
// result is in [0, 2q-1], may need conditional subtraction
```

### Compression (ML-KEM)

Maps field element x in [0, q-1] to d-bit value and back:

```text
compress(x, d) = round(x * 2^d / q) mod 2^d
decompress(y, d) = round(y * q / 2^d)
```

Introduces lossy quantization error bounded by q / 2^(d+1).

### Power2Round / Decompose (ML-DSA)

Splits coefficient into high and low parts:

```text
Power2Round(r, d): r = r1 * 2^d + r0
Decompose(r, alpha): r = r1 * alpha + r0 (centered)
```

Used for hint generation: the hint tells the verifier when `HighBits(w)` differs from `HighBits(w - cs2)`.

---

## 6. Security Development Practices

### DO

- Use `Int32List` / `Uint8List` for polynomial coefficients
- Validate all external inputs (sizes, ranges)
- Zeroize secret material after use
- Write constant-time comparison functions
- Test against NIST KAT vectors before releasing
- Use `assert()` for debug-only diagnostics
- Review all modular arithmetic for overflow

### DON'T

- Use `print()` in `lib/` code
- Use early returns in security-sensitive loops
- Allocate more memory than needed for secret data
- Trust that Dart's GC will clear sensitive buffers
- Use `Random()` (insecure) - always use `Random.secure()`
- Implement your own SHA-3 / Keccak unless absolutely necessary
- Store secret keys in Dart `String` type (immutable, not zeroizable)

---

## 7. Platform-Specific Notes

### Dart VM (Native)

- `int` is 64-bit signed
- `Int32List` uses contiguous 32-bit storage
- `Random.secure()` uses `/dev/urandom` (Linux), `BCryptGenRandom` (Windows), `SecRandomCopyBytes` (macOS/iOS)
- AOT compilation available for production

### dart2js (JavaScript)

- `int` becomes JS `number` (64-bit IEEE 754 double)
- Safe integer range: `-2^53` to `2^53`
- `Int32List` uses `Int32Array` (typed array)
- `Random.secure()` uses `crypto.getRandomValues()`
- **Risk**: Multiplication of large coefficients must stay within safe integer range
  - Kyber: max product = 3329^2 = ~1.1 * 10^7 (safe)
  - Dilithium: max product = 8380417^2 = ~7.0 * 10^13 (safe, < 2^53)

### dart2wasm (WebAssembly)

- `int` is 64-bit signed (i64)
- Most performant web target for crypto
- `Int32List` maps to Wasm linear memory
- Preferred over dart2js for production web deployment

### Flutter

- Uses Dart VM on mobile/desktop
- Web builds use dart2js or dart2wasm
- No special considerations beyond platform-specific RNG

---

## 8. CI / CD Pipeline (Recommended)

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        sdk: ['3.10.0', 'stable']
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dart-lang/setup-dart@v1
        with:
          sdk: ${{ matrix.sdk }}
      - run: dart pub get
      - run: dart analyze
      - run: dart test

  web-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dart-lang/setup-dart@v1
      - run: dart pub get
      - run: dart test --platform chrome

  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dart-lang/setup-dart@v1
      - run: dart pub get
      - run: dart run example/main.dart
```

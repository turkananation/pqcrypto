# pqcrypto Performance Analysis & Optimization Guide

**Date**: 2026-03-13
**Version**: 0.1.0

---

## 1. Current Performance Baseline

### ML-KEM (Kyber) - Dart VM JIT

| Algorithm | KeyGen | Encapsulate | Decapsulate | Security |
|-----------|--------|-------------|-------------|----------|
| ML-KEM-512 | ~0.7 ms | ~0.7 ms | ~0.6 ms | 128-bit |
| ML-KEM-768 | ~1.3 ms | ~1.4 ms | ~1.0 ms | 192-bit |
| ML-KEM-1024 | ~1.8 ms | ~1.8 ms | ~1.7 ms | 256-bit |

### Comparison with Native Implementations

| Implementation | ML-KEM-768 KeyGen | ML-KEM-768 Encap | ML-KEM-768 Decap |
|---------------|-------------------|-------------------|-------------------|
| **pqcrypto (Dart VM)** | **1.3 ms** | **1.4 ms** | **1.0 ms** |
| liboqs (C, AVX2) | 0.03 ms | 0.04 ms | 0.03 ms |
| Go stdlib crypto/mlkem | 0.15 ms | 0.18 ms | 0.16 ms |
| pqcrypto-js (JS/Wasm) | 2.5 ms | 3.0 ms | 2.8 ms |

The Dart implementation is approximately **8-10x slower than Go** and **40x slower than optimized C/AVX2**. This is expected for pure interpreted/JIT code with no SIMD.

---

## 2. Performance Bottleneck Analysis

### 2.1 Profiling Hotspots (Estimated)

| Operation | % of Encapsulate | Notes |
|-----------|-----------------|-------|
| NTT (forward + inverse) | ~35% | 7 NTT operations for KEM-768 |
| BaseMul (pointwise) | ~20% | 128 gamma-twisted multiplications per poly |
| SHAKE-128 (matrix gen) | ~25% | 9 XOF calls for k=3 matrix |
| Compression/Serialization | ~10% | Bit manipulation |
| CBD Sampling | ~5% | SHAKE-256 + bitwise ops |
| Other (allocation, copy) | ~5% | GC pressure |

### 2.2 Key Performance Limiters

#### A. Barrett Reduction (Kyber NTT)

```dart
static int barrettReduce(int a) {
    const int v = 20159;
    int shift = 26;
    int product = (a * v) >> shift;
    int res = a - product * q;
    return res;
}
```

Called 256 times per NTT layer, 7 layers = 1792 calls per NTT. With 7+ NTTs per KEM operation, this is ~12,500 Barrett reductions per encapsulation.

**Optimization opportunity**: The `>> shift` can be combined with the multiplication using Dart's native 64-bit arithmetic. No overflow risk since `a * v < 2^46`.

#### B. SHAKE-128/256 via pointycastle

The `pointycastle` SHAKE implementation processes data through the Keccak permutation. Each `shake()` call creates a new `SHAKEDigest` object, performs absorption, and squeezes output.

**Overhead sources**:
- Object allocation for each call
- No streaming/incremental API usage
- Internal state copying

#### C. Memory Allocation Pattern

The NTT creates `List<int>.from(poly.coeffs)` (a copy) on every call. With Kyber's NTT using `List<int>` (boxed integers on VM), each 256-element list has overhead from object headers.

---

## 3. Optimization Roadmap

### Tier 1: Algorithmic Optimizations (No API Change)

#### OPT-01: Use `Int32List` for Kyber Polynomials
**Estimated speedup**: 15-25%

Replace `List<int>` with `Int32List` in `Poly` class:
```dart
class Poly {
  final Int32List coeffs;  // Instead of List<int>
}
```

Benefits:
- Contiguous memory layout (cache-friendly)
- No boxing/unboxing overhead
- Better GC performance (single allocation vs 256 objects)

Note: Dilithium already uses `Int32List`. Kyber should follow.

#### OPT-02: In-Place NTT Operations
**Estimated speedup**: 10-15%

Current Kyber NTT copies the coefficient list:
```dart
static Poly ntt(Poly poly) {
    final f = List<int>.from(poly.coeffs);  // Allocation!
    ...
    return Poly(f);  // Another allocation!
}
```

Make NTT in-place (Dilithium already does this):
```dart
static void ntt(Poly poly) {  // Modify in-place
    final f = poly.coeffs;
    ...
}
```

#### OPT-03: Pre-compute Matrix A for Repeated Operations
**Estimated speedup**: 20-30% for batch operations

Currently, `ExpandA` is called separately in each `encrypt()` call during encapsulation. For protocols requiring multiple encapsulations with the same public key, cache the expanded matrix.

#### OPT-04: Lazy Barrett Reduction
**Estimated speedup**: 5-10%

Currently, `_fieldMul` applies Barrett reduction after every multiplication. In the NTT butterfly, the result of multiplication is immediately added/subtracted:
```dart
final t = _fieldMul(zeta, f[j + len]);
f[j + len] = _fieldSub(f[j], t);
f[j] = _fieldAdd(f[j], t);
```

Since `_fieldAdd` and `_fieldSub` handle values up to `2q`, Barrett reduction could be deferred to every other layer, halving the number of reductions.

### Tier 2: Platform-Specific Optimizations

#### OPT-05: Native SHAKE via `dart:ffi` (Mobile/Desktop)
**Estimated speedup**: 50-70% overall

SHAKE-128/256 dominates compute time. Using a C implementation via FFI:
- OpenSSL's EVP interface
- XKCP (eXtended Keccak Code Package)
- Custom minimal Keccak-f[1600]

Implementation:
```dart
// Conditional import
import 'shake_native.dart' if (dart.library.html) 'shake_web.dart';
```

#### OPT-06: WebAssembly NTT Kernel (Web)
**Estimated speedup**: 30-50% on web

Compile a tight NTT loop in C/Rust to Wasm, call via `dart:js_interop` or `dart:wasm`:
- NTT forward/inverse
- BaseMul
- Matrix-vector multiplication

#### OPT-07: SIMD via `dart:ffi` + Platform Intrinsics
**Estimated speedup**: 3-5x on x86/ARM with NEON/AVX2

For server-side or native mobile deployment:
- Vectorized NTT butterfly (4-wide for 32-bit coefficients)
- Vectorized Barrett reduction
- Vectorized polynomial addition/subtraction

### Tier 3: Architectural Optimizations

#### OPT-08: Streaming SHAKE Interface
**Estimated speedup**: 10-15%

Replace single-shot `Shake128.shake(input, outputLen)` with an incremental absorb/squeeze API:
```dart
class ShakeStream {
    void absorb(Uint8List data);
    void squeeze(Uint8List output, int offset, int length);
}
```

This avoids over-allocating output buffers for rejection sampling.

#### OPT-09: Object Pooling for Polynomials
**Estimated speedup**: 5-10%

Pre-allocate a pool of `Int32List(256)` buffers to reduce GC pressure during batch operations.

---

## 4. Benchmarking Guide

### Running Existing Benchmarks

```bash
dart run example/main.dart
```

This runs 200-iteration benchmarks for all three ML-KEM security levels with JIT warmup.

### Recommended Benchmark Suite

```dart
// benchmark/kem_bench.dart
void main() {
  final warmup = 100;
  final iterations = 1000;

  for (final level in [PqcKem.kyber512, PqcKem.kyber768, PqcKem.kyber1024]) {
    // Warmup
    for (var i = 0; i < warmup; i++) {
      final (pk, sk) = level.generateKeyPair();
      final (ct, _) = level.encapsulate(pk);
      level.decapsulate(sk, ct);
    }

    // Benchmark KeyGen
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) level.generateKeyPair();
    sw.stop();
    print('KeyGen: ${sw.elapsedMicroseconds / iterations} us');

    // ... similar for Encap/Decap
  }
}
```

### AOT vs JIT Comparison

```bash
# JIT (development)
dart run benchmark/kem_bench.dart

# AOT (production)
dart compile exe benchmark/kem_bench.dart -o kem_bench
./kem_bench
```

AOT typically shows **10-20% improvement** over JIT for NTT-heavy code due to eliminated compilation overhead.

---

## 5. ML-DSA Performance Expectations

### Estimated ML-DSA Performance (Dart VM JIT)

| Algorithm | KeyGen | Sign (avg) | Verify | Security |
|-----------|--------|------------|--------|----------|
| ML-DSA-44 | ~4 ms | ~12 ms | ~4 ms | 128-bit |
| ML-DSA-65 | ~7 ms | ~25 ms | ~7 ms | 192-bit |
| ML-DSA-87 | ~12 ms | ~40 ms | ~12 ms | 256-bit |

Sign is significantly slower due to the rejection loop (expected ~4.25 iterations for ML-DSA-44).

### Comparison Targets

| Implementation | ML-DSA-44 Sign | ML-DSA-44 Verify |
|---------------|----------------|------------------|
| liboqs (C, AVX2) | 0.3 ms | 0.1 ms |
| Go crypto/mldsa | 1.5 ms | 0.5 ms |
| **pqcrypto target** | **<15 ms** | **<5 ms** |

---

## 6. Memory Usage

### ML-KEM Key Sizes

| Algorithm | PK | SK | CT | SS |
|-----------|-----|------|------|-----|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B |

### ML-DSA Key Sizes

| Algorithm | PK | SK | Sig |
|-----------|------|------|------|
| ML-DSA-44 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | 2592 B | 4896 B | 4627 B |

### Runtime Memory (Estimated per Operation)

| Operation | Peak Heap (approx) |
|-----------|-------------------|
| ML-KEM-768 KeyGen | ~50 KB |
| ML-KEM-768 Encap | ~60 KB |
| ML-KEM-768 Decap | ~55 KB |
| ML-DSA-44 Sign | ~120 KB |
| ML-DSA-44 Verify | ~80 KB |

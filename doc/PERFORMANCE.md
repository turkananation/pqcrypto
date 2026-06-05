# Performance Notes

Last updated: 2026-06-05

This document records performance direction, not a certified benchmark report.
Run fresh benchmarks before publishing timing claims.

## Current Measurement Boundary

The package is pure Dart and has no runtime dependencies. ML-KEM uses the
vendored FIPS 202 implementation in `lib/src/common/keccak.dart`; OpenSSL FFI is
confined to `tool/openssl_interop/` and is not part of runtime performance.

`example/main.dart` provides a simple warmup and timing demo for ML-KEM-512,
ML-KEM-768, and ML-KEM-1024. It is useful for local sanity checks, but it is not
an automated benchmark suite.

## Known Hotspots

| Area                      | Why it matters                                     | Improvement direction                              |
| ------------------------- | -------------------------------------------------- | -------------------------------------------------- |
| ML-KEM NTT                | Many modular reductions and polynomial operations. | Measure `Int32List`, in-place NTT, lazy reduction. |
| Matrix generation         | Repeated SHAKE calls during K-PKE operations.      | Streaming XOF or precomputed matrix options.       |
| Serialization/compression | Bit packing is on every key/ciphertext path.       | Keep regression tests before micro-optimizing.     |
| Keccak/FIPS 202           | Pure Dart Keccak is portable but compute-heavy.    | Optimize vendored implementation cautiously.       |
| Allocations               | Temporary `Uint8List`/poly objects create GC load. | Pooling only after measurement.                    |

## Benchmark Commands

```bash
dart run example/main.dart
dart compile exe example/main.dart -o /tmp/pqcrypto_example
/tmp/pqcrypto_example
```

Recommended future benchmark suite:

```text
benchmark/
  kem_bench.dart          # KeyGen/Encaps/Decaps per level
  keccak_bench.dart       # SHA3/SHAKE throughput
  pack_bench.dart         # encode/decode/compress paths
```

The suite should report:

- Dart SDK version;
- runtime target: VM JIT, AOT, dart2js, dart2wasm;
- CPU/OS;
- warmup count and iteration count;
- p50/p95 timings if possible.

## Optimization Rules

1. Keep KAT and OpenSSL interop green before and after every optimization.
2. Do not trade constant-time or validation behavior for speed.
3. Avoid runtime dependencies unless the package boundary changes deliberately.
4. Keep web behavior explicit; `dart2js` uses a different integer backend from
   the VM.
5. Prefer measured hot spots over speculative rewrites.

## Candidate Work

| ID      | Candidate                             | Risk | Notes                                       |
| ------- | ------------------------------------- | ---- | ------------------------------------------- |
| PERF-01 | `Int32List` for ML-KEM `Poly.coeffs`. | Med  | May reduce boxing/GC; requires broad tests. |
| PERF-02 | In-place ML-KEM NTT.                  | High | Touches core arithmetic; KAT gate required. |
| PERF-03 | Streaming SHAKE/XOF API.              | Med  | Could reduce over-squeeze allocation.       |
| PERF-04 | Precomputed matrix API.               | Med  | Useful for batch encapsulation contexts.    |
| PERF-05 | Optional native helper package.       | High | Keep outside core runtime package.          |

## Claim Boundary

The README may include timings only when produced by a recent benchmark run with
environment details. Otherwise prefer qualitative wording: "pure Dart",
"web-compatible", and "zero runtime dependencies".

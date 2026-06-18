# Performance Notes

Last updated: 2026-06-16

This document records performance direction, not a certified benchmark report.
Run fresh benchmarks before publishing timing claims.

## Current Measurement Boundary

The package is pure Dart and has no runtime dependencies. ML-KEM, ML-DSA, and
SLH-DSA use vendored primitives under `lib/src/common/`; OpenSSL and liboqs FFI
are confined to `tool/openssl_interop/` and `tool/liboqs_interop/` and are not
part of runtime performance.

`example/main.dart` is a functional demo for ML-KEM, ML-DSA, SLH-DSA, and a
signed ML-KEM-768 + ML-DSA-65 handshake transcript. It is useful for local
sanity checks, but it is not an automated benchmark suite.

SLH-DSA has a portable benchmark entrypoint at
`tool/bench/slhdsa_bench.dart`. It measures one key generation, deterministic
signature, and verification operation through the public API and verifies the
generated signature before reporting a result. The tool supports all 12 FIPS
205 parameter sets; the table below publishes a SHAKE-only single-sample
baseline.

## SLH-DSA SHAKE Baseline

These are **single-sample engineering baselines**, not a statistical benchmark
or service-level guarantee. Each target ran sequentially on 2026-06-15:

- 11th Gen Intel Core i5-1135G7, 4 cores / 8 threads;
- Linux 7.0.11 x86-64;
- Dart SDK 3.12.0 stable;
- Node.js 24.14.1 for the compiled JavaScript and Wasm artifacts.

The web-compiler measurements use Node as the execution engine. Browser,
mobile, thermal, and power-constrained performance can differ materially.
Times are milliseconds; signing is deterministic to make the operation
repeatable. No warmup or repeated sampling was performed.

| Parameter          | Target           | KeyGen ms |   Sign ms | Verify ms | Signature bytes |
| ------------------ | ---------------- | --------: | --------: | --------: | --------------: |
| SLH-DSA-SHAKE-128s | VM JIT           |  3,921.23 | 30,410.87 |     37.84 |           7,856 |
| SLH-DSA-SHAKE-128f | VM JIT           |     58.97 |  1,396.35 |     81.99 |          17,088 |
| SLH-DSA-SHAKE-192s | VM JIT           |  5,542.54 | 52,033.58 |     45.79 |          16,224 |
| SLH-DSA-SHAKE-192f | VM JIT           |     97.74 |  2,526.04 |    128.28 |          35,664 |
| SLH-DSA-SHAKE-256s | VM JIT           |  3,969.54 | 46,788.48 |     67.29 |          29,792 |
| SLH-DSA-SHAKE-256f | VM JIT           |    305.97 |  4,829.33 |    126.83 |          49,856 |
| SLH-DSA-SHAKE-128s | dart2js / Node   |  4,364.00 | 31,776.00 |     33.00 |           7,856 |
| SLH-DSA-SHAKE-128f | dart2js / Node   |     70.00 |  1,689.00 |    101.00 |          17,088 |
| SLH-DSA-SHAKE-192s | dart2js / Node   |  6,636.00 | 55,741.00 |     48.00 |          16,224 |
| SLH-DSA-SHAKE-192f | dart2js / Node   |    109.00 |  3,579.00 |    516.00 |          35,664 |
| SLH-DSA-SHAKE-256s | dart2js / Node   | 11,295.00 | 51,477.00 |     90.00 |          29,792 |
| SLH-DSA-SHAKE-256f | dart2js / Node   |    296.00 |  5,077.00 |    136.00 |          49,856 |
| SLH-DSA-SHAKE-128s | dart2wasm / Node |  3,743.86 | 28,726.75 |     31.83 |           7,856 |
| SLH-DSA-SHAKE-128f | dart2wasm / Node |     68.87 |  1,597.91 |     93.01 |          17,088 |
| SLH-DSA-SHAKE-192s | dart2wasm / Node |  5,857.62 | 52,302.48 |     40.06 |          16,224 |
| SLH-DSA-SHAKE-192f | dart2wasm / Node |     99.96 |  2,274.58 |    122.13 |          35,664 |
| SLH-DSA-SHAKE-256s | dart2wasm / Node |  3,923.03 | 47,928.88 |     61.60 |          29,792 |
| SLH-DSA-SHAKE-256f | dart2wasm / Node |    269.40 |  4,771.06 |    127.31 |          49,856 |

The `s` sets require `allowSlowSigning: true` because measured signing latency
is roughly 29-56 seconds on this machine. `SLH-DSA-SHAKE-128f` is the
recommended interactive default, but its 17,088-byte signature and roughly
1.4-1.7 second signing baseline still require explicit product-level latency
and payload-size planning.

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
dart run tool/bench/slhdsa_bench.dart --target=vm-jit

dart compile js -O2 \
  -DSLHDSA_BENCH_TARGET=dart2js-node \
  tool/bench/slhdsa_bench.dart -o /tmp/slhdsa_bench.js
node tool/bench/run_dart2js.mjs /tmp/slhdsa_bench.js

dart compile wasm \
  -DSLHDSA_BENCH_TARGET=dart2wasm-node \
  tool/bench/slhdsa_bench.dart -o /tmp/slhdsa_bench.wasm
node tool/bench/run_dart2wasm.mjs /tmp/slhdsa_bench.wasm
```

Use `--parameter=shake128f` on the VM, or compile with
`-DSLHDSA_BENCH_PARAMETER=shake128f`, to select one set.

Future statistical benchmark work should report:

- Dart SDK version;
- runtime target: VM JIT, AOT, dart2js, dart2wasm;
- CPU/OS;
- warmup count and iteration count;
- p50/p95 timings if possible.

## Optimization Rules

1. Keep KAT and native-provider interop green before and after every optimization.
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

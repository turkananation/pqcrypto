# Performance

`pqcrypto` is pure Dart, so performance depends on the target (Dart VM AOT is
fastest; web is slowest) and on which operation you run. This page gives
practical guidance; the canonical baseline and optimization tracker is
[PERFORMANCE.md](https://github.com/turkananation/pqcrypto/blob/main/doc/PERFORMANCE.md).

## Cost asymmetry to design around

- **Cheaper:** ML-KEM `encapsulate`/`decapsulate`, ML-DSA `verify`.
- **More expensive:** key generation, and ML-DSA `sign` (rejection sampling can
  loop several times before it accepts a signature).

Design so the expensive operations are rare or off the critical path. On
constrained devices, prefer pushing *verification* to the device and *signing*
to a server.

## Keep UIs responsive (mobile & desktop)

Run heavy operations off the UI thread with an isolate:

```dart
import 'dart:isolate';
import 'package:pqcrypto/pqcrypto.dart';

final (pk, sk) = await Isolate.run(
  () => MlDsa.generateKeyPair(DilithiumParams.mlDsa65),
);
// Flutter equivalent: compute(fn, input);
```

Passing a secret key into an isolate copies sensitive bytes; for hardened apps,
prefer a dedicated long-lived crypto isolate over copying keys per call.

## Web (dart2js / dart2wasm)

Flutter web does **not** run isolates on a separate thread — `compute()` keeps
the same API but does not move CPU work off the main thread. Recommendations:

- Prefer **`dart2wasm`** for CPU-heavy crypto.
- Generate long-term keys server-side or rarely; keep per-interaction work small.
- Show loading states around any key generation.

## Choosing parameters for performance

Lower parameter sets are faster and smaller:

- **Fastest / smallest:** ML-KEM-512, ML-DSA-44.
- **Balanced default:** ML-KEM-768, ML-DSA-65.
- **Maximum margin:** ML-KEM-1024, ML-DSA-87.

Signature and key sizes also grow with the level (see [ML-KEM](ML-KEM) and
[ML-DSA](ML-DSA) size tables) — relevant when bandwidth or storage is the binding
constraint.

## Measuring

Benchmark on your actual target hardware and compiler; numbers from a desktop VM
do not predict a mobile or web build. A formal automated benchmark suite across
AOT/`dart2js`/`dart2wasm` is on the [Roadmap](Roadmap) (0.6.0).

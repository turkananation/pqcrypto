# Installation

`pqcrypto` is a pure Dart package with **zero runtime dependencies**. It works in
any Dart or Flutter project and on every Dart target.

## Add the package

```bash
dart pub add pqcrypto
```

or for a Flutter project:

```bash
flutter pub add pqcrypto
```

This adds the latest version to your `pubspec.yaml`:

```yaml
dependencies:
  pqcrypto: ^0.4.0
```

Then import the single public library:

```dart
import 'package:pqcrypto/pqcrypto.dart';
```

That import exposes the entire public API: `PqcKem` / `KyberKem` (ML-KEM),
`MlDsa` / `DilithiumParams` (ML-DSA), and `SlhDsa` / `SlhDsaParams` (SLH-DSA).

## Requirements

- **Dart SDK:** `^3.10.0` (records and pattern destructuring are used in the
  public API).
- **No native toolchain, no FFI, no C libraries.** The FIPS 202 (SHA-3/SHAKE)
  and FIPS 180-4 (SHA-2) primitives are vendored in pure Dart.

## Supported platforms

| Target                           | Supported | Notes                                                |
| -------------------------------- | --------- | ---------------------------------------------------- |
| Dart VM (JIT/AOT)                | Yes       | Fastest path; ideal for servers and CLIs.            |
| Flutter — iOS / Android          | Yes       | Offload heavy work to an isolate (see below).        |
| Flutter / Dart — macOS/Win/Linux | Yes       | Desktop and embedded Linux / SBC.                    |
| Web — `dart2js`                  | Yes       | Works; no isolate offload (see below).               |
| Web — `dart2wasm`                | Yes       | Works; preferred web compiler for CPU-heavy crypto.  |
| Bare-metal microcontrollers      | No        | No supported Dart toolchain for Cortex-M-class MCUs. |

## Keep the UI responsive

Key generation and signing are CPU-intensive. On Flutter mobile and desktop,
run them off the UI thread:

```dart
import 'dart:isolate';
import 'package:pqcrypto/pqcrypto.dart';

final (pk, sk) = await Isolate.run(
  () => MlDsa.generateKeyPair(DilithiumParams.mlDsa65),
);
```

On **Flutter web**, isolates do not run on a separate thread, so `compute()`
does not move CPU work off the main thread — prefer `dart2wasm`, do heavy key
generation rarely, or generate long-term keys server-side.

## Verify your setup

Run the bundled example to confirm everything works end to end:

```bash
dart run example/main.dart
```

Next: [Quickstart](Quickstart) · [Cookbook](Cookbook) ·
[Cryptographic Algorithms](Cryptographic-Algorithms)

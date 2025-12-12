# pqcrypto: Pure Dart Post-Quantum Cryptography

**pqcrypto** is a pure Dart library implementing Post-Quantum Cryptography (PQC) algorithms, targeting compatibility with Flutter and the Dart web ecosystem.

The current release provides a **production-hardened implementation of ML-KEM (Kyber)**, adhering to the **FIPS 203** (Module-Lattice-Based Key-Encapsulation Mechanism) standard.

## Features

-   **Full FIPS 203 Compliance**:
    -   **Algorithm Support**: Kyber-512, Kyber-768, Kyber-1024.
    -   **Secure Primitives**: 
        -   **SHAKE-128/256** based matrix generation (`GenMatrix`).
        -   **Centered Binomial Distribution (CBD)** for secure noise sampling.
    -   **Key Encapsulation**: Correct `(rho, sigma) := G(d)` derivation and implicit rejection mechanism in decapsulation.
    -   **Fujisaki-Okamoto Transform**: Robust re-encryption check to prevent chosen-ciphertext attacks (IND-CCA2 security).
-   **Platform Agnostic**:
    -   100% Pure Dart. Works on Android, iOS, Windows, Linux, macOS, and Web (dart2js/dart2wasm).
    -   Zero native dependencies (uses `pointycastle` for SHA3 primitives).

## Installation

Add the dependency to your `pubspec.yaml`:

```yaml
dependencies:
  pqcrypto:
    path: ./  # Or git url / pub version
  pointycastle: ^3.7.4
```

## Usage

The library exposes a high-level `PqcKem` API for easy integration.

### Quick Start: Key Encapsulation

```dart
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  // 1. Select the algorithm variant
  // Options: PqcKem.kyber512, PqcKem.kyber768, PqcKem.kyber1024
  final kem = PqcKem.kyber768;

  // 2. Generate Keypair (Server Side)
  // Returns Public Key (pk) and Secret Key (sk)
  final (pk, sk) = kem.generateKeyPair();
  print('Public Key size: ${pk.length} bytes');
  print('Secret Key size: ${sk.length} bytes');

  // 3. Encapsulate (Client Side)
  // Uses the Public Key to generate a Shared Secret and Ciphertext
  final (ct, ss_sender) = kem.encapsulate(pk);
  print('Ciphertext size: ${ct.length} bytes');

  // 4. Decapsulate (Server Side)
  // Server uses Secret Key and Ciphertext to recover the same Shared Secret
  final ss_receiver = kem.decapsulate(sk, ct);

  // Check that secrets match
  assert(ss_sender.toString() == ss_receiver.toString());
  print('Shared Secret derived successfully!');
}
```

## Performance

Current benchmarks (running on modest hardware under JIT):

| Algorithm | Key Generation | Encapsulation | Decapsulation |
| :--- | :--- | :--- | :--- |
| **Kyber-512** | ~3.0 ms | < 1 ms | < 1 ms |
| **Kyber-768** | ~6.1 ms | < 1 ms | < 1 ms |
| **Kyber-1024** | ~8.6 ms | < 1 ms | < 1 ms |

*Note: Current implementation uses schoolbook polynomial multiplication ($O(N^2)$). Future updates will check NTT implementation ($O(N \log N)$) for significant speedups.*

## Project Structure

```
lib/
├── pqcrypto.dart                 # Main export file
├── src/
│   ├── algos/
│   │   └── kyber/
│   │       ├── kem.dart          # High-level API (generate, encap, decap)
│   │       ├── indcpa.dart       # Core IND-CPA Encryption/Decryption logic
│   │       ├── pack.dart         # Byte encoding/decoding (serialization)
│   │       └── params.dart       # Algorithm constants (k, eta, sizes)
│   └── common/
│       ├── poly.dart             # Polynomial arithmetic
│       └── shake.dart            # SHAKE128/256 wrapper
```

## Roadmap

-   [x] **Phase 1: Foundation**
    -   Establish project structure.
    -   Implement core math (`Poly`).
    -   Implement Kyber-768 logic flow.
-   [x] **Phase 2: Correctness & Compliance**
    -   Implement full `GenMatrix` using SHAKE-128.
    -   Secure Noise Sampling (CBD).
    -   Full FIPS 203 FO Transform (implicit rejection).
    -   Verify against KAT vectors.
-   [ ] **Phase 3: Optimization**
    -   Implement Number Theoretic Transform (NTT) for faster polynomial multiplication.
    -   Explore SIMD/WASM optimizations.
-   [ ] **Phase 4: Algo Expansion**
    -   Add **ML-DSA (Dilithium)** for digital signatures.

## Development

Run tests:

```bash
dart test
```

Run static analysis:

```bash
dart analyze
```

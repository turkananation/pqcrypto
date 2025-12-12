# pqcrypto: Pure Dart Post-Quantum Cryptography

**pqcrypto** is a pure Dart library implementing Post-Quantum Cryptography (PQC) algorithms, targeting compatibility with Flutter and the Dart web ecosystem. The initial release focuses on **ML-KEM (Kyber)**, the primary Key Encapsulation Mechanism (KEM) selected by NIST for standardization (FIPS 203).

> [!WARNING]
> **Experimental / Research Quality**: This library is currently in active development. While it implements the cryptographic logic of Kyber-768, certain components (such as full matrix generation via XOF) are simplified for architectural validation. **Do not use in production systems requiring FIPS compliance or high security assurance at this stage.**

## Features

-   **ML-KEM-768 (Kyber-768)** implementation:
    -   Level 3 security (roughly equivalent to AES-192).
    -   Pure Dart implementation of Number Theoretic Transform (NTT) for polynomial arithmetic.
    -   Correct packet formats for Public Keys, Secret Keys, and Ciphertexts.
-   **SHAKE128** support:
    -   Integrated via `pointycastle` for robust XOF (Extendable Output Function) operations.
-   **Platform Agnostic**:
    -   Works on mobile (Flutter iOS/Android), Desktop, and Web (dart2js/dart2wasm).

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

### Quick Start: Key Encapsulation (Kyber)

```dart
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  // 1. Select the algorithm (Kyber-768)
  final kem = PqcKem.kyber768;

  // 2. Generate Keypair (Server Side)
  // Returns Public Key (1184 bytes) and Secret Key (2400 bytes)
  final (pk, sk) = kem.generateKeyPair();

  // 3. Encapsulate (Client Side)
  // Uses the Server's Public Key to generate a Shared Secret and Ciphertext
  final (ct, ss_sender) = kem.encapsulate(pk);

  // 4. Decapsulate (Server Side)
  // Server uses Secret Key and Ciphertext to recover the same Shared Secret
  final ss_receiver = kem.decapsulate(sk, ct);

  // Check that secrets match
  assert(ss_sender.toString() == ss_receiver.toString());
  print('Shared Secret derived successfully!');
}
```

## Project Structure

The project is organized to separate algorithms, common math primitives, and packing logic.

```
lib/
├── pqcrypto.dart                 # Main export file
├── src/
│   ├── algos/
│   │   └── kyber/
│   │       ├── kem.dart          # High-level API (generate, encap, decap)
│   │       ├── indcpa.dart       # Core IND-CPA Encryption/Decryption logic
│   │       └── pack.dart         # Byte encoding/decoding (serialization)
│   └── common/
│       ├── poly.dart             # Polynomial arithmetic (NTT, reduction)
│       └── shake.dart            # SHAKE128 XOF wrapper (PointyCastle)
test/
├── kyber_test.dart               # Round-trip correctness tests
├── kat_kyber_test.dart           # NIST Known Answer Tests (KAT) harness
└── data/                         # Test vectors
```

### Key Components

*   **`Poly` (`src/common/poly.dart`)**: Handles degree-256 polynomials over ring $R_q$. Implements efficient multiplication using NTT.
*   **`Indcpa` (`lib/src/algos/kyber/indcpa.dart`)**: Implements the underlying Public-Key Encryption (PKE) scheme. Handles sampling noise, matrix vector multiplication (simplified), and message encoding.
*   **`Pack` (`lib/src/algos/kyber/pack.dart`)**: Manages the complex bit-packing required by the Kyber specification (e.g., compressing 12-bit coefficients into byte arrays).

## Roadmap & Future Expansion

We aim to build a comprehensive PQC suite for the Dart ecosystem.

-   [x] **Phase 1: Foundation (Current)**
    -   Establish project structure.
    -   Implement core math (`Poly`, `NTT`).
    -   Implement Kyber-768 logic flow.
-   [ ] **Phase 2: Correctness & Compliance**
    -   Implement full `GenMatrix` using SHAKE-128 expansion for strictly adhering to FIPS 203 test vectors.
    -   Integrate full NIST KAT suite.
    -   Add constant-time protections (where possible in Dart).
-   [ ] **Phase 3: Algo Expansion**
    -   Add **ML-DSA (Dilithium)** for digital signatures.
    -   Add **Sphincs+** as fallback signature scheme.
-   [ ] **Phase 4: Optimization**
    -   Explore FFI (Foreign Function Interface) bindings to C/Rust for performance-critical paths on native platforms.
    -   WASM optimization for web targets.

## Development

Run tests:

```bash
dart test
```

Run static analysis:

```bash
dart analyze
```

# pqcrypto: Pure Dart Post-Quantum Cryptography

**pqcrypto** is a pure Dart library implementing Post-Quantum Cryptography (PQC) algorithms, targeting compatibility with Flutter and the Dart web ecosystem.

The supported release surface provides a **FIPS 203-aligned implementation of ML-KEM (Kyber)** with checked-in known-answer tests, OpenSSL interoperability evidence, and focused unit coverage for serialization, modular reduction, and input validation. ML-DSA APIs are exported for ongoing development, but they are not production validated yet.

---

## 🚀 Features

- **FIPS 203-aligned ML-KEM support**:
  - **Algorithm Support**: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - **Secure Primitives**:
    - **SHAKE-128/256** based matrix generation and hashing.
    - **Centered Binomial Distribution (CBD)** for secure noise sampling.
  - **Key Encapsulation**: `(rho, sigma) := G(d || k)` derivation for K-PKE key generation.
  - **Fujisaki-Okamoto Transform**: Robust re-encryption check to prevent chosen-ciphertext attacks (IND-CCA2 security).
  - **Input Checks**: Public-key length/modulus checks, decapsulation-key length/hash checks, and ciphertext length checks.
- **Platform Agnostic**:
  - 100% Pure Dart. Works on Android, iOS, Windows, Linux, macOS, and Web (dart2js/dart2wasm) — verified on all three backends in CI.
  - **Zero dependencies.** No third-party packages at all: FIPS 202 (SHA3-256/512, SHAKE128/256) is vendored in-tree, so `lib/` depends only on `dart:typed_data`.

---

## 🛡️ ML-KEM Validation Status

This implementation tracks [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), but this repository does not claim CMVP/FIPS 140 module validation. The current evidence is the checked-in KAT corpus plus unit tests for the algorithm surfaces listed below.

| Algorithm       | Status       | Checked-in KAT Vectors | Security Level         |
| :-------------- | :----------: | :--------------------: | :--------------------: |
| **ML-KEM-512**  | **KAT pass** | **1000/1000 PASS**     | NIST Level 1 (AES-128) |
| **ML-KEM-768**  | **KAT pass** | **1000/1000 PASS**     | NIST Level 3 (AES-192) |
| **ML-KEM-1024** | **KAT pass** | **1000/1000 PASS**     | NIST Level 5 (AES-256) |

**Total checked-in vectors:** 3000/3000 pass locally as of June 3, 2026.

See [doc/MLKEM_TESTING.md](doc/MLKEM_TESTING.md) for the KAT file hashes, coverage boundaries, and release-gate commands.

---

## ML-DSA Experimental Status

The package currently exports `MlDsa`, `DilithiumParams`, and
`DilithiumParameter`, but ML-DSA remains experimental. The current full test
suite fails in ML-DSA packing/symmetric/debug tests, and no repo-local ML-DSA
KAT corpus is checked in. Do not use ML-DSA for production signatures until the
blockers in [doc/BUGS.md](doc/BUGS.md) and
[doc/PROGRESS_TRACKER.md](doc/PROGRESS_TRACKER.md) are closed and verified.

---

## 🔗 OpenSSL Interoperability

`pqcrypto`'s ML-KEM is **wire-compatible with OpenSSL's** native ML-KEM at **all
three parameter sets** — ML-KEM-512, ML-KEM-768, and ML-KEM-1024. OpenSSL
exposes those native ML-KEM algorithms in the 3.5 line and newer; the local
interop harness ([`tool/openssl_interop/`](tool/openssl_interop/)) drives both
implementations over `dart:ffi` and proves byte-level agreement on each:

| Test      | What it proves                                                         |
| :-------- | :--------------------------------------------------------------------- |
| **A / B** | each implementation is internally self-consistent (sanity)             |
| **C**     | OpenSSL decapsulates a **pqcrypto** ciphertext → same secret (fuzzed)  |
| **D**     | pqcrypto decapsulates an **OpenSSL** ciphertext → same secret (fuzzed) |
| **E**     | same seed `(d‖z)` ⇒ **byte-identical public keys**                     |
| **F**     | public-key wire round-trip (pqcrypto → OpenSSL → bytes) is identical   |
| **G**     | implicit-rejection secret `J(z‖c)` agrees on an invalid ciphertext     |

Shared secrets — including the FIPS 203 implicit-rejection branch — are
**byte-identical** across implementations in both directions, at every level
(public keys and ciphertexts are standardized raw encodings, so no format
conversion is needed).

> **The library stays 100% pure Dart.** This interop check is a developer/CI
> tool under [`tool/`](tool/openssl_interop/) that uses `dart:ffi` to call
> OpenSSL's `libcrypto`. It is **not** part of the `pqcrypto` package or its
> dependencies — `lib/` imports no FFI, nothing native ships to consumers, and
> the tool is excluded from the published package (see `.pubignore`).

- **Linux:** verified against **OpenSSL 3.5.4 and 3.5.6** (Dart 3.12.0) on
  2026-06-03; CI also builds and runs **OpenSSL 4.0.0**.
- **macOS:** runs against Homebrew OpenSSL ≥ 3.5 (`brew install openssl@3.5`).

```sh
cd tool/openssl_interop
dart pub get
dart test                                    # rigorous suite: tests A–G × all three levels
dart run bin/openssl_pqcrypto_interop.dart   # human-readable harness
# Linux: prefix LIBCRYPTO_PATH=/path/to/libcrypto.so (OpenSSL >= 3.5)
```

CI runs the full suite on every push via
[`.github/workflows/interop.yml`](.github/workflows/interop.yml).

**Full details:** [doc/OPENSSL_INTEROP.md](doc/OPENSSL_INTEROP.md) — FFI
bindings, the FIPS 203 fixes interop required, exact versions/results, and use
cases (hybrid TLS `X25519MLKEM768`, Dart ↔ OpenSSL services, migration).

---

## 🛠️ Implementation Highlights

This library follows the FIPS 203 specification structure where practical while keeping validation claims scoped to the tests in this repository.

### 1. Number Theoretic Transform (NTT)

Uses **pure modular arithmetic** (not Montgomery) matching the FIPS 203 Algorithms 8 and 9:

- **NTT/InvNTT**: Cooley-Tukey butterfly operations with modular reduction.
- **Base Multiplication**: Karatsuba-style in NTT domain using $\gamma$ coefficients (Algorithm 10).
- **Polynomial Ring**: Operations in $\mathbb{Z}_q[X]/(X^{256}+1)$ where $q = 3329$.

### 2. Compression & Serialization

Compression functions follow FIPS 203 Definitions 4.7-4.8:

- **compress(x, d)**: Standard rounding logic $\lceil (2^d/q) \cdot x \rfloor \bmod 2^d$.
- **Formula**: `(2 * x * 2^d + q) / (2 * q)` with modulo `2^d` wrap at the boundary.
- **ByteEncode support**:
  - **12-bit**: Public Keys (`ByteEncode₁₂`)
  - **11-bit**: ML-KEM-1024 Ciphertext $u$ (`ByteEncode₁₁`)
  - **10-bit**: ML-KEM-768 Ciphertext $u$ (`ByteEncode₁₀`)
  - **5-bit**: ML-KEM-1024 Ciphertext $v$ (`ByteEncode₅`)
  - **4-bit**: ML-KEM-512/768 Ciphertext $v$ (`ByteEncode₄`)
  - **1-bit**: Messages (`ByteEncode₁`)

### 3. Cryptographic Primitives

- **XOF**: SHAKE-128 for matrix generation (Algorithm 7).
- **PRF**: SHAKE-256 for noise sampling.
- **Hash Functions**: SHA3-256, SHA3-512 for key derivation.
- **CBD Sampling**: Centered Binomial Distribution with $\eta \in \{2,3\}$.
- **Vendored FIPS 202**: SHA-3 and SHAKE are implemented in-tree (`lib/src/common/keccak.dart`) with **no third-party dependency**, using web-safe 32-bit lane arithmetic verified on the VM, `dart2js`, and `dart2wasm`.

### 4. Security Hardening

- **Implicit Rejection**: Implementation of the modified Fujisaki-Okamoto transform guarantees that invalid ciphertexts produce a pseudo-random shared secret (derived from internal secret $z$) rather than failing. This prevents chosen-ciphertext timing attacks.
- **Domain Separation**: All hash calls include the standardized domain separation bytes.
- **Input Validation**: `encapsulate` rejects malformed public keys, and `decapsulate` rejects malformed secret keys or ciphertext lengths before running decapsulation.

---

## 📂 Project Structure

```text
lib/
├── pqcrypto.dart                 # 📦 Library Entrypoint
└── src/
    ├── algos/
    │   └── kyber/
    │       ├── kem.dart          # 🚀 ML-KEM High-Level API (Algorithms 16-19)
    │       │                     # - KeyGen_internal (Algorithm 15)
    │       │                     # - ML-KEM.KeyGen (Algorithm 16)
    │       │                     # - ML-KEM.Encaps (Algorithm 17)
    │       │                     # - ML-KEM.Decaps (Algorithm 18)
    │       │
    │       ├── indcpa.dart       # 🔐 IND-CPA Encryption K-PKE (Algorithms 12-14)
    │       │                     # - K-PKE.KeyGen (Algorithm 12)
    │       │                     # - K-PKE.Encrypt (Algorithm 13)
    │       │                     # - K-PKE.Decrypt (Algorithm 14)
    │       │
    │       ├── pack.dart         # 💾 Serialization & Compression (Defs 4.7-4.8)
    │       │                     # - ByteEncode/ByteDecode (Algorithms 4-5)
    │       │                     # - Compress/Decompress (d=1,4,5,10,11,12)
    │       │
    │       └── params.dart       # 📏 Security Parameters
    │                             # - Constants for k, eta1, eta2, du, dv
    │
    └── common/
        ├── poly.dart             # 🧮 Polynomial Arithmetic & NTT
        │                         # - NTT / InvNTT (Algorithms 8-9)
        │                         # - BaseMul [MultiplyNTTs] (Algorithm 10)
        │                         # - SampleNTT [Parse] (Algorithm 7)
        │                         # - PolyAdd, PolySub, PolyReduce
        │
        ├── shake.dart            # 🎲 SHAKE-128 / SHAKE-256 wrappers
        │
        └── keccak.dart           # 🧱 Vendored FIPS 202 (zero-dependency)
                                  # - SHA3-256/512, SHAKE128/256
                                  # - web-safe 32-bit lanes (dart2js/dart2wasm)

test/
├── kat_evaluator_test.dart       # 🧪 Checked-in ML-KEM KAT runner (3000 vectors, VM-only)
├── keccak_test.dart              # 🧱 FIPS 202 (SHA3/SHAKE) known-answer tests
├── roundtrip_test.dart           # 🔁 End-to-end KEM round-trip (runs on VM + web)
├── kem_validation_test.dart      # 🔎 Public key, secret key, and ciphertext checks
├── keygen_derivation_test.dart   # 🔑 G(d‖k) + matrix XOF-ordering unit tests
├── pack_test.dart                # 📦 Serialization round-trip bounds
├── poly_test.dart                # 🧮 Modular reduction properties
├── cbd_test.dart                 # 📊 Statistical distribution checks
└── data/
    ├── kat_MLKEM_512.rsp         # ML-KEM-512 checked-in KAT corpus
    ├── kat_MLKEM_768.rsp         # ML-KEM-768 checked-in KAT corpus
    └── kat_MLKEM_1024.rsp        # ML-KEM-1024 checked-in KAT corpus

tool/
└── openssl_interop/              # 🔗 OpenSSL FFI interop harness (dev tool, separate package)
    ├── lib/openssl_ml_kem.dart   #    generalized EVP bindings (512/768/1024)
    ├── bin/openssl_pqcrypto_interop.dart
    └── test/interop_test.dart    #    rigorous A–G interop suite

.github/
└── workflows/
    ├── ci.yml                    # analyze + format + unit/KAT suite + web (dart2js/dart2wasm)
    └── interop.yml               # OpenSSL ↔ pqcrypto ML-KEM-512/768/1024 interop
```

---

## 💻 Usage

### Quick Start

> **Serverpod Users:** Check out the [Full Stack Integration Guide](doc/SERVERPOD_FLUTTER_GUIDE.md) for a complete backend + client implementation pattern.

```dart
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  // 1. Select the security level
  // Options: PqcKem.kyber512, PqcKem.kyber768, PqcKem.kyber1024
  final kem = PqcKem.kyber768;

  // 2. Generate Keypair (Server Side)
  // Returns Public Key (pk) and Secret Key (sk)
  final (pk, sk) = kem.generateKeyPair();
  print('Public Key size: ${pk.length} bytes');
  print('Secret Key size: ${sk.length} bytes');

  // 3. Encapsulate (Client Side)
  // Uses the Public Key to generate a Shared Secret and Ciphertext
  final (ct, ssAlice) = kem.encapsulate(pk);
  print('Ciphertext size: ${ct.length} bytes');

  // 4. Decapsulate (Server Side)
  // Server recovers the same Shared Secret using Secret Key
  final ssBob = kem.decapsulate(sk, ct);

  // Check that secrets match
  assert(_bytesEqual(ssAlice, ssBob));
  print('Shared Secret derived successfully!');
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
```

---

## 🧪 Verification & Testing

The quality of this cryptographic library is verified through these repository-local layers:

### 1. ML-KEM Known Answer Tests (KAT)

Validates against the `.rsp` files checked into `test/data`.

- **Parser**: `test/kat_evaluator_test.dart` handles `.rsp` files with `z`, `d`, `msg`, `seed`, `pk`, `sk`, `ct`, `ss`, `ct_n`, and `ss_n`.
- **Coverage**:
  - ✅ **ML-KEM-512**: 1000/1000 vectors
  - ✅ **ML-KEM-768**: 1000/1000 vectors
  - ✅ **ML-KEM-1024**: 1000/1000 vectors

### 2. Unit & Property Tests

- **Serialization (`test/pack_test.dart`)**: Round-trip validation for all compressed bit-depths using modular distance over `q`.
- **Reduction (`test/poly_test.dart`)**: Verifies `barrettReduce` returns canonical residues in `[0, q - 1]`, including negative and boundary cases.
- **Statistical (`test/cbd_test.dart`)**: Verifies the output distribution of the CBD sampler matches theoretical binomial probabilities.

### 3. Validation & Negative Testing

- **Input validation (`test/kem_validation_test.dart`)**: Confirms malformed public keys, malformed secret keys, and wrong ciphertext lengths are rejected.
- **Invalid decapsulation KATs (`test/kat_evaluator_test.dart`)**: Confirms checked-in `ct_n` vectors produce their expected `ss_n` shared secrets.

---

## ⚡ Performance

Benchmarks on commodity Linux x64 hardware (Dart 3.x VM, JIT):

| Algorithm       | Key Generation | Encapsulation | Decapsulation | Security Level   |
| :-------------- | :------------- | :------------ | :------------ | :--------------- |
| **ML-KEM-512**  | ~0.7 ms        | ~0.7 ms       | ~0.6 ms       | 128-bit security |
| **ML-KEM-768**  | ~1.3 ms        | ~1.4 ms       | ~1.0 ms       | 192-bit security |
| **ML-KEM-1024** | ~1.8 ms        | ~1.8 ms       | ~1.7 ms       | 256-bit security |

---

## 🔮 Roadmap

- ✅ **Phase 1: Foundation** (Project structure, Poly math)
- ✅ **Phase 2: Correctness** (GenMatrix, CBD, FO Transform)
- ✅ **Phase 3: FIPS 203 Alignment** (NTT, Compression, ByteEncode)
- ✅ **Phase 4: Full Suite** (ML-KEM-512/768/1024 support)
- ⬜ **Phase 5: ML-DSA validation** (fix current ML-DSA test failures, add repo-local KATs)
- ⬜ **Phase 6: Hardening and expansion** (zeroization, side-channel review, SLH-DSA/HQC research)

See [doc/ROADMAP.md](doc/ROADMAP.md) for the evidence-scoped roadmap.

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  pqcrypto: ^0.2.1
```

`pqcrypto` pulls in no third-party dependencies of its own.

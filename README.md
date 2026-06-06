# pqcrypto: Pure Dart Post-Quantum Cryptography

[![Pub Version](https://img.shields.io/pub/v/pqcrypto?color=blue&logo=dart)](https://pub.dev/packages/pqcrypto)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue)](pubspec.yaml)
[![ML-KEM](https://img.shields.io/badge/FIPS_203-ML--KEM-brightgreen?logo=shield)](doc/FIPS_COMPLIANCE.md)
[![ML-DSA](https://img.shields.io/badge/FIPS_204-ML--DSA-brightgreen?logo=shield)](doc/MLDSA_FIPS204_RELEASE_GUIDE.md)
[![KATs](https://img.shields.io/badge/NIST_KATs-Byte_Exact-success)](doc/MLKEM_TESTING.md)
[![Flutter Platforms](https://img.shields.io/badge/Platforms-iOS_%7C_Android_%7C_Web_%7C_macOS_%7C_Windows_%7C_Linux-lightgrey?logo=flutter)](doc/PROGRESS_TRACKER.md)

**pqcrypto** is a pure Dart library implementing Post-Quantum Cryptography (PQC) algorithms, targeting compatibility with Flutter and the Dart web ecosystem.

The supported release surface provides a **FIPS 203-aligned implementation of ML-KEM (Kyber)** and a **FIPS 204-aligned implementation of ML-DSA (Dilithium)**, each with checked-in known-answer tests and focused unit coverage. ML-KEM additionally carries OpenSSL interoperability evidence. ML-DSA is byte-exact against the official FIPS 204 KAT corpus across every parameter set, signing mode, and implementation flavour (see below). Neither algorithm claims CMVP/FIPS 140 module validation — see [doc/FIPS_140_BOUNDARY.md](doc/FIPS_140_BOUNDARY.md) for exactly what is and is not claimed.

**📚 Documentation:** [Website](https://turkananation.github.io/pqcrypto/) · [Wiki](https://github.com/turkananation/pqcrypto/wiki) · [Quickstart](https://github.com/turkananation/pqcrypto/wiki/Quickstart) · [Cookbook (project ideas)](doc/cookbook/README.md) · [API reference](https://pub.dev/documentation/pqcrypto/latest/) · [Documentation index](doc/INDEX.md)

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
- **FIPS 204-aligned ML-DSA support**:
  - **Algorithm Support**: ML-DSA-44, ML-DSA-65, ML-DSA-87 (internal, external, and HashML-DSA).
  - **Hedged-by-default signing** with explicit deterministic and pre-hash paths and FIPS 204 context strings (≤ 255 bytes).
  - **Byte-exact** against the official FIPS 204 KAT corpus (1800 signatures + 300 key generations) and **vendored SHA-2** (SHA-256/384/512) for HashML-DSA pre-hashing.
  - **Defensive verification**: returns `false` (never throws) on malformed public keys, signatures, hints, or over-long contexts; unbounded XOF rejection sampling; best-effort secret zeroization.
- **Platform Agnostic**:
  - 100% Pure Dart. Works on Android, iOS, Windows, Linux, macOS, and Web (dart2js/dart2wasm) — verified on all three backends in CI.
  - **Zero dependencies.** No third-party packages at all: the current FIPS 202 surface (SHA3-256/512, SHAKE128/256) is vendored in-tree, so `lib/` depends only on `dart:typed_data`; full FIPS 202 and SP 800-185 completion targets 0.7.0, with 0.8.0 spillover if needed, and is tracked in [doc/FIPS202_SP800185_RELEASE_GUIDE.md](doc/FIPS202_SP800185_RELEASE_GUIDE.md).

---

## 🛡️ ML-KEM Validation Status

This implementation tracks [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), but this repository does not claim CMVP/FIPS 140 module validation ([why?](doc/FIPS_140_BOUNDARY.md)). The current evidence is the checked-in KAT corpus plus unit tests for the algorithm surfaces listed below.

| Algorithm         | Status         | Checked-in KAT Vectors   | Security Level           |
| ----------------- | -------------- | ------------------------ | ------------------------ |
| **ML-KEM-512**    | **KAT pass**   | **1000/1000 PASS**       | NIST Level 1 (AES-128)   |
| **ML-KEM-768**    | **KAT pass**   | **1000/1000 PASS**       | NIST Level 3 (AES-192)   |
| **ML-KEM-1024**   | **KAT pass**   | **1000/1000 PASS**       | NIST Level 5 (AES-256)   |

**Total checked-in vectors:** 3000/3000 pass locally as of June 3, 2026.

See [doc/MLKEM_TESTING.md](doc/MLKEM_TESTING.md) for the KAT file hashes, coverage boundaries, and release-gate commands.

---

## 🛡️ ML-DSA Validation Status

This implementation tracks [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
As with ML-KEM, this repository does **not** claim CMVP/FIPS 140 module
validation ([why?](doc/FIPS_140_BOUNDARY.md)); the evidence is the checked-in KAT
corpus plus focused unit tests. The package exports `MlDsa`, `DilithiumParams`,
and `DilithiumParameter`.

Every signature in the official KAT corpus (`test/data/MLDSA`) is reproduced
**byte-for-byte**, and every KAT signature **verifies**, across the full matrix
of parameter set × signing mode × implementation flavour:

| Parameter set   | Security level   | KeyGen (raw/det)   | Sign + Verify (all flavours)   |
| --------------- | ---------------- | ------------------ | ------------------------------ |
| **ML-DSA-44**   | NIST Level 2     | 100/100 PASS       | 600/600 PASS                   |
| **ML-DSA-65**   | NIST Level 3     | 100/100 PASS       | 600/600 PASS                   |
| **ML-DSA-87**   | NIST Level 5     | 100/100 PASS       | 600/600 PASS                   |

- **Flavours:** `raw` (internal `*_internal`, Algorithms 6/7/8), `pure`
  (external ML-DSA with a context string, Algorithms 1/2/3), and `hashed`
  (HashML-DSA with SHA-256/384/512 pre-hash, Algorithms 1/4/5).
- **Modes:** `deterministic` (`rnd = 0`) and `hedged` (`rnd` from the vector).
- **Totals:** 300/300 byte-exact key generations and 1800/1800 byte-exact
  signatures that all verify (3 levels × 2 modes × 3 flavours × 100 vectors).

The public API is **hedged by default** (fresh `rnd` from `Random.secure()`),
supports FIPS 204 context strings (≤ 255 bytes), exposes explicit deterministic
and HashML-DSA paths, and returns `false` (never throws) for any malformed
public key, signature, hint, or over-long context. See the controlling guide
[doc/MLDSA_FIPS204_RELEASE_GUIDE.md](doc/MLDSA_FIPS204_RELEASE_GUIDE.md) and the
corpus description in [test/data/MLDSA/README.md](test/data/MLDSA/README.md).

```dart
final params = DilithiumParams.mlDsa65;
final (pk, sk) = MlDsa.generateKeyPair(params);          // fresh randomness
final sig = MlDsa.sign(sk, message, params, ctx: appCtx); // hedged by default
final ok  = MlDsa.verify(pk, message, sig, params, ctx: appCtx);
```

---

## 🔗 OpenSSL Interoperability

`pqcrypto`'s ML-KEM is **wire-compatible with OpenSSL's** native ML-KEM at **all
three parameter sets** — ML-KEM-512, ML-KEM-768, and ML-KEM-1024. OpenSSL
exposes those native ML-KEM algorithms in the 3.5 line and newer; the local
interop harness ([`tool/openssl_interop/`](tool/openssl_interop/)) drives both
implementations over `dart:ffi` and proves byte-level agreement on each:

| Test        | What it proves                                                           |
| ----------- | ------------------------------------------------------------------------ |
| **A / B**   | each implementation is internally self-consistent (sanity)               |
| **C**       | OpenSSL decapsulates a **pqcrypto** ciphertext → same secret (fuzzed)    |
| **D**       | pqcrypto decapsulates an **OpenSSL** ciphertext → same secret (fuzzed)   |
| **E**       | same seed `(d‖z)` ⇒ **byte-identical public keys**                       |
| **F**       | public-key wire round-trip (pqcrypto → OpenSSL → bytes) is identical     |
| **G**       | implicit-rejection secret `J(z‖c)` agrees on an invalid ciphertext       |

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

This library follows the FIPS 203 and FIPS 204 specification structures where
practical while keeping validation claims scoped to the tests in this
repository. ML-KEM and ML-DSA use separate polynomial types, moduli, NTTs,
packing code, and parameter objects so the two lattice schemes do not share
algorithm-specific arithmetic accidentally.

### 1. ML-KEM Number Theoretic Transform (NTT)

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

### 3. ML-DSA Signature Architecture

ML-DSA lives under `lib/src/algos/dilithium/` and tracks FIPS 204's external
and internal function split:

- **Public API layering**: `MlDsa.generateKeyPair`, `sign`, and `verify` expose
  external ML-DSA Algorithms 1-3; `hashSign` and `hashVerify` expose HashML-DSA
  Algorithms 4-5; `generateKeyPairSeeded`, `signInternal`, and `verifyInternal`
  remain available for deterministic KAT/CAVP-style vectors.
- **Parameter sets**: `DilithiumParams` carries ML-DSA-44/65/87 parameters,
  FIPS 204 Table 2 public-key, secret-key, and signature sizes, and the
  per-level `tau`, `gamma1`, `gamma2`, `omega`, and challenge length values.
- **Hedged-by-default signing**: external signing draws a fresh 32-byte `rnd`
  from `Random.secure`; deterministic signing is explicit through
  `signDeterministic` or a supplied KAT `rnd`.
- **FIPS 204 message domains**: external ML-DSA signs
  `0x00 || len(ctx) || ctx || M`; HashML-DSA signs
  `0x01 || len(ctx) || ctx || DER(OID(PH)) || PH(M)`.
- **Signing core**: key generation expands `xi` into `rho`, `rho'`, and `K`,
  builds `A`, samples `s1/s2`, applies `Power2Round`, and packs `pk/sk`;
  signing derives `mu`, samples `y`, computes the challenge, applies
  rejection checks, builds hints, and packs `(c_tilde, z, h)`.
- **Verification core**: verification reconstructs `w1'`, re-hashes
  `mu || w1Encode(w1')`, and compares challenge hashes without early exit.

### 4. ML-DSA Arithmetic, Sampling & Encoding

ML-DSA uses a different ring from ML-KEM:

- **Polynomial Ring**: operations in $\mathbb{Z}_q[X]/(X^{256}+1)$ where
  $q = 8380417$.
- **Complete NTT**: `DilithiumNTT` uses the FIPS 204 Appendix B zeta table and a
  complete coefficient-wise NTT shape, separate from ML-KEM's incomplete NTT and
  base-multiplication path.
- **Sampling**: `ExpandA` uses SHAKE-128 rejection sampling for NTT-domain matrix
  coefficients; `ExpandS`, `ExpandMask`, and `SampleInBall` use SHAKE-256 with
  unbounded XOF squeezing so the samplers do not exhaust fixed buffers.
- **Signed-domain packing**: `packing.dart` handles public keys, secret keys,
  signatures, `t0/t1`, `z`, and sparse hints with FIPS 204-derived sizes.
- **HashML-DSA pre-hash**: vendored SHA-256/384/512 are selected by level
  (ML-DSA-44/65/87) and paired with the DER OID bytes required by FIPS 204
  domain separation.

### 5. Cryptographic Primitives

- **ML-KEM XOF/PRF**: SHAKE-128 for FIPS 203 matrix/sample generation and
  SHAKE-256 for noise sampling.
- **ML-KEM hash functions**: SHA3-256 and SHA3-512 for FIPS 203 key derivation,
  ciphertext binding, and implicit rejection.
- **ML-KEM CBD Sampling**: Centered Binomial Distribution with
  $\eta \in \{2,3\}$.
- **ML-DSA XOF/CRH**: SHAKE-128 for `ExpandA`; SHAKE-256 for `H`, `G`, `CRH`,
  bounded sampling, mask expansion, and challenge sampling.
- **Vendored FIPS 202 foundation**: SHA3-256/512 and SHAKE128/256 are implemented in-tree (`lib/src/common/keccak.dart`) with **no third-party dependency**, using web-safe 32-bit lane arithmetic verified on the VM, `dart2js`, and `dart2wasm`. Full FIPS 202 plus SP 800-185 work targets 0.7.0, with 0.8.0 spillover if needed, and is tracked in [doc/FIPS202_SP800185_RELEASE_GUIDE.md](doc/FIPS202_SP800185_RELEASE_GUIDE.md).
- **Vendored FIPS 180-4**: SHA-256/384/512 are implemented in-tree
  (`lib/src/common/sha2.dart`) for HashML-DSA pre-hashing, using 32-bit word
  pairs for SHA-384/512 portability across the VM and web compilers.

### 6. Security Hardening

- **Implicit Rejection**: Implementation of the modified Fujisaki-Okamoto transform guarantees that invalid ciphertexts produce a pseudo-random shared secret (derived from internal secret $z$) rather than failing. This prevents chosen-ciphertext timing attacks.
- **Constant-time output selection**: ML-KEM decapsulation always computes both the re-encryption secret `K'` and the implicit-rejection secret `J(z‖c)` and selects between them with a branchless mask, so success vs. rejection does not leak through control flow.
- **Best-effort zeroization**: secret intermediates in ML-KEM decapsulation and ML-DSA key generation / signing are overwritten in `finally` blocks (`lib/src/common/zeroize.dart`); see [doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md) for the Dart limitations.
- **ML-DSA norm checks**: `_normExceeds` scans all 256 coefficients with no
  early exit; residual branch-direction timing remains documented as
  best-effort Dart hardening, not a constant-time proof.
- **Domain Separation**: ML-KEM uses the standardized FIPS 203 hash/XOF inputs;
  ML-DSA and HashML-DSA include FIPS 204 domain bytes, context length, context,
  and HashML-DSA OID/domain material.
- **Input Validation**: `encapsulate` rejects malformed public keys, and
  `decapsulate` rejects malformed secret keys or ciphertext lengths before
  running decapsulation. ML-DSA verification returns `false` for malformed
  public keys, signatures, hints, norm violations, or over-long contexts.
- **Validation evidence**: `test/kat_evaluator_test.dart` covers the checked-in
  ML-KEM corpus; `test/mldsa_kat_test.dart` covers all 18 ML-DSA KAT files
  across raw/pure/hashed and deterministic/hedged signing.

---

## 📂 Project Structure

```text
lib/
├── pqcrypto.dart                 # 📦 Library Entrypoint
└── src/
    ├── algos/
    │   ├── kyber/                # 🔑 ML-KEM (FIPS 203) implementation
    │   │   ├── kem.dart          # 🚀 High-level API + KeyGen/Encaps/Decaps (Alg 15-18)
    │   │   ├── indcpa.dart       # 🔐 IND-CPA K-PKE core (Algorithms 12-14)
    │   │   ├── pack.dart         # 💾 ByteEncode/Decode + Compress (Algs 4-5)
    │   │   └── params.dart       # 📏 ML-KEM params (k, eta1, eta2, du, dv)
    │   │
    │   └── dilithium/            # ✍️ ML-DSA (FIPS 204) implementation
    │       ├── dsa.dart          # 🖊️ MlDsa: external + internal + HashML-DSA
    │       │                     #    KeyGen/Sign/Verify (Algs 1-3), *_internal
    │       │                     #    (Algs 6-8), HashML-DSA sign/verify (Algs 4-5)
    │       ├── params.dart       # 📏 ML-DSA-44/65/87 params + Table 2 sizes
    │       ├── poly.dart         # 🧮 DilithiumPoly / vector types (q=8380417)
    │       ├── ntt.dart          # 🔁 Complete NTT + Appendix B zetas
    │       ├── packing.dart      # 💾 pk/sk/sig encode/decode (signed domains)
    │       ├── rounding.dart     # 📐 Power2Round/Decompose/MakeHint/UseHint
    │       └── symmetric.dart    # 🎲 ExpandA/S, ExpandMask, SampleInBall, pre-hash
    │
    └── common/
        ├── poly.dart             # 🧮 ML-KEM Polynomial Arithmetic & NTT
        │                         # - NTT / InvNTT (Algorithms 8-9)
        │                         # - BaseMul [MultiplyNTTs] (Algorithm 10)
        │                         # - SampleNTT [Parse] (Algorithm 7)
        │                         # - PolyAdd, PolySub, PolyReduce
        │
        ├── shake.dart            # 🎲 SHAKE-128/256 wrappers + incremental XOF
        │
        ├── keccak.dart           # 🧱 Vendored FIPS 202 foundation (zero-dependency)
        │                         # - SHA3-256/512, SHAKE128/256, KeccakXof
        │                         # - Full FIPS 202 + SP 800-185 tracked in doc/
        │                         # - web-safe 32-bit lanes (dart2js/dart2wasm)
        │
        ├── sha2.dart             # #️⃣ Vendored FIPS 180-4 SHA-256/384/512
        │                         # - HashML-DSA pre-hash; web-safe 64-bit pairs
        │
        └── zeroize.dart          # 🧹 Best-effort secret zeroization helpers

test/
├── kat_evaluator_test.dart       # 🧪 Checked-in ML-KEM KAT runner (3000 vectors, VM-only)
├── mldsa_kat_test.dart           # 🧪 Discovered ML-DSA KAT runner (18 files, all flavours, VM-only)
├── dsa_zetas_test.dart           # 🧮 FIPS 204 Appendix B zetas + negacyclic NTT property
├── dsa_rounding_test.dart        # 📐 Power2Round/Decompose/MakeHint/UseHint boundaries
├── dsa_negative_test.dart        # 🚫 Malformed pk/sig/hint/context: verify returns false
├── dsa_api_test.dart             # 🔐 Context binding, hedged vs deterministic, domain separation
├── sha2_test.dart                # #️⃣ SHA-256/384/512 (FIPS 180-4) for HashML-DSA pre-hash
├── keccak_test.dart              # 🧱 FIPS 202 (SHA3/SHAKE) known-answer tests
├── roundtrip_test.dart           # 🔁 End-to-end KEM round-trip (runs on VM + web)
├── kem_validation_test.dart      # 🔎 Public key, secret key, and ciphertext checks
├── keygen_derivation_test.dart   # 🔑 G(d‖k) + matrix XOF-ordering unit tests
├── pack_test.dart                # 📦 Serialization round-trip bounds
├── poly_test.dart                # 🧮 Modular reduction properties
├── cbd_test.dart                 # 📊 Statistical distribution checks
└── data/
    ├── MLKEM/                    # ML-KEM KAT corpus (512/768/1024) + README
    │   └── kat_MLKEM_*.rsp
    └── MLDSA/                    # ML-DSA KAT corpus + README
        └── kat_MLDSA_{44,65,87}_{det,hedged}_{raw,pure,hashed}.rsp

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

> **Looking for project ideas?** The [Cookbook](doc/cookbook/README.md) catalogs
> things you can build across servers, mobile, desktop, CLI, embedded Linux, web,
> and cross-language interop — each composed from reusable, API-correct
> [building blocks](doc/cookbook/BUILDING_BLOCKS.md). Browse the
> [project catalog](doc/cookbook/PROJECT_CATALOG.md), or the machine-readable
> [`project-ideas.yaml`](doc/cookbook/project-ideas.yaml) for AI agents.
> **Serverpod Users:** Check out the [Full Stack Integration Guide](doc/SERVERPOD_FLUTTER_GUIDE.md) for a complete backend + client implementation pattern.
> **Agent Workflows:** The project-level
> [Universal Multi-Agent PQC Framework](doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md)
> provides Codex, Claude Code, and Antigravity wrappers plus an LLM-readable
> manifest for evidence-scoped Serverpod/Flutter PQC planning.

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

| Algorithm         | Key Generation   | Encapsulation   | Decapsulation   | Security Level     |
| ----------------- | ---------------- | --------------- | --------------- | ------------------ |
| **ML-KEM-512**    | ~0.7 ms          | ~0.7 ms         | ~0.6 ms         | 128-bit security   |
| **ML-KEM-768**    | ~1.3 ms          | ~1.4 ms         | ~1.0 ms         | 192-bit security   |
| **ML-KEM-1024**   | ~1.8 ms          | ~1.8 ms         | ~1.7 ms         | 256-bit security   |

---

## 🔮 Roadmap

- ✅ **Phase 1: Foundation** (Project structure, Poly math)
- ✅ **Phase 2: Correctness** (GenMatrix, CBD, FO Transform)
- ✅ **Phase 3: FIPS 203 Alignment** (NTT, Compression, ByteEncode)
- ✅ **Phase 4: Full Suite** (ML-KEM-512/768/1024 support)
- ✅ **Phase 5: ML-DSA validation** (byte-exact FIPS 204 KATs for 44/65/87 across raw/pure/hashed × det/hedged; external hedged API; HashML-DSA; repo-local corpus)
- 🔄 **Phase 6: Hardening and expansion** (best-effort zeroization and constant-time review landed; ongoing side-channel review, SLH-DSA/HQC research)

See [doc/ROADMAP.md](doc/ROADMAP.md) for the evidence-scoped roadmap.

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  pqcrypto: ^0.3.1
```

`pqcrypto` pulls in no third-party dependencies of its own.

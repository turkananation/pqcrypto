# pqcrypto: Pure Dart Post-Quantum Cryptography

## Project Signals

### Package & Reach

[![pub.dev](https://img.shields.io/pub/v/pqcrypto?style=for-the-badge&logo=dart&logoColor=white&label=pub.dev&color=0175c2)](https://pub.dev/packages/pqcrypto)
[![pub points](https://img.shields.io/pub/points/pqcrypto?style=for-the-badge&logo=dart&logoColor=white&label=pub%20points&color=0175c2)](https://pub.dev/packages/pqcrypto/score)
[![pub likes](https://img.shields.io/pub/likes/pqcrypto?style=for-the-badge&logo=dart&logoColor=white&label=likes&color=00a67e)](https://pub.dev/packages/pqcrypto/score)
[![pub popularity](https://img.shields.io/pub/popularity/pqcrypto?style=for-the-badge&logo=dart&logoColor=white&label=popularity&color=00a67e)](https://pub.dev/packages/pqcrypto/score)
[![license](https://img.shields.io/github/license/turkananation/pqcrypto?style=for-the-badge&label=license&color=2ea043)](LICENSE)
[![Dart SDK](https://img.shields.io/badge/Dart-%5E3.10.0-0175c2?style=for-the-badge&logo=dart&logoColor=white)](pubspec.yaml)
[![stars](https://img.shields.io/github/stars/turkananation/pqcrypto?style=for-the-badge&logo=github&label=stars&color=181717)](https://github.com/turkananation/pqcrypto/stargazers)
[![last commit](https://img.shields.io/github/last-commit/turkananation/pqcrypto?style=for-the-badge&logo=github&label=last%20commit&color=6f42c1)](https://github.com/turkananation/pqcrypto/commits/develop)

### Standards & Cryptographic Surface

[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-2ea043?style=for-the-badge&logo=shield&logoColor=white)](doc/FIPS_COMPLIANCE.md)
[![ML-KEM levels](https://img.shields.io/badge/ML--KEM-512%20%7C%20768%20%7C%201024-2ea043?style=for-the-badge)](doc/MLKEM_TESTING.md)
[![FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA-2ea043?style=for-the-badge&logo=shield&logoColor=white)](doc/MLDSA_FIPS204_RELEASE_GUIDE.md)
[![ML-DSA levels](https://img.shields.io/badge/ML--DSA-44%20%7C%2065%20%7C%2087-2ea043?style=for-the-badge)](doc/MLDSA_FIPS204_RELEASE_GUIDE.md)
[![FIPS 205](https://img.shields.io/badge/FIPS%20205-SLH--DSA-2ea043?style=for-the-badge&logo=shield&logoColor=white)](doc/SLHDSA_FIPS205_RELEASE_GUIDE.md)
[![SLH-DSA sets](https://img.shields.io/badge/SLH--DSA-12%20sets%20(SHAKE%20%2B%20SHA--2)-2ea043?style=for-the-badge)](doc/SLHDSA_FIPS205_RELEASE_GUIDE.md)
[![FIPS 202](https://img.shields.io/badge/FIPS%20202-partial%20SHA--3%2FSHAKE-f59e0b?style=for-the-badge&logo=shield&logoColor=white)](doc/FIPS202_SP800185_RELEASE_GUIDE.md)
[![SP 800-185](https://img.shields.io/badge/SP%20800--185-planned%200.6.0-0969da?style=for-the-badge&logo=shield&logoColor=white)](doc/FIPS202_SP800185_RELEASE_GUIDE.md)
[![CMVP boundary](https://img.shields.io/badge/CMVP%20%2F%20FIPS%20140-not%20validated-bf8700?style=for-the-badge)](doc/FIPS_140_BOUNDARY.md)
[![zero dependencies](https://img.shields.io/badge/runtime%20dependencies-0-2ea043?style=for-the-badge)](pubspec.yaml)

### Evidence, Portability & Interoperability

[![ML-KEM KATs](https://img.shields.io/badge/ML--KEM%20KATs-3000%2F3000-2ea043?style=for-the-badge)](doc/MLKEM_TESTING.md)
[![ML-DSA keygen KATs](https://img.shields.io/badge/ML--DSA%20keygen-300%2F300-2ea043?style=for-the-badge)](doc/MLDSA_FIPS204_RELEASE_GUIDE.md)
[![ML-DSA signature KATs](https://img.shields.io/badge/ML--DSA%20signatures-1800%2F1800-2ea043?style=for-the-badge)](doc/MLDSA_FIPS204_RELEASE_GUIDE.md)
[![SLH-DSA ACVP](https://img.shields.io/badge/SLH--DSA%20ACVP-1248%2F1248-2ea043?style=for-the-badge)](doc/SLHDSA_FIPS205_RELEASE_GUIDE.md)
[![OpenSSL interop](https://img.shields.io/badge/OpenSSL%20interop-ML--KEM%20%7C%20ML--DSA%20%7C%20SLH--DSA-2ea043?style=for-the-badge&logo=openssl&logoColor=white)](doc/OPENSSL_INTEROP.md)
[![liboqs interop](https://img.shields.io/badge/liboqs%20interop-18%20native%20algorithms-2ea043?style=for-the-badge)](tool/liboqs_interop/README.md)
[![pure Dart](https://img.shields.io/badge/pure%20Dart-no%20native%20runtime-0175c2?style=for-the-badge&logo=dart&logoColor=white)](lib/)
[![Flutter platforms](https://img.shields.io/badge/Flutter-iOS%20%7C%20Android%20%7C%20Web%20%7C%20Desktop-02569b?style=for-the-badge&logo=flutter&logoColor=white)](doc/PROGRESS_TRACKER.md)
[![web backends](https://img.shields.io/badge/Web-dart2js%20%2B%20dart2wasm-7c3aed?style=for-the-badge)](.github/workflows/ci.yml)
[![vendored SHA-3](https://img.shields.io/badge/SHA--3%20%2F%20SHAKE-vendored%20FIPS%20202%20core-0969da?style=for-the-badge)](lib/src/common/keccak.dart)

### Automation & Security Gates

[![CI](https://img.shields.io/github/actions/workflow/status/turkananation/pqcrypto/ci.yml?branch=develop&style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqcrypto/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/turkananation/pqcrypto/codeql.yml?branch=develop&style=for-the-badge&label=CodeQL&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqcrypto/actions/workflows/codeql.yml)
[![OpenSSL workflow](https://img.shields.io/github/actions/workflow/status/turkananation/pqcrypto/interop.yml?branch=develop&style=for-the-badge&label=OpenSSL%20interop&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqcrypto/actions/workflows/interop.yml)
[![visibility workflow](https://img.shields.io/github/actions/workflow/status/turkananation/pqcrypto/visibility.yml?branch=develop&style=for-the-badge&label=Visibility&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqcrypto/actions/workflows/visibility.yml)
[![Pages deploy](https://img.shields.io/github/actions/workflow/status/turkananation/pqcrypto/pages.yml?branch=develop&style=for-the-badge&label=Pages&logo=githubpages&logoColor=white)](https://github.com/turkananation/pqcrypto/actions/workflows/pages.yml)
[![Wiki sync](https://img.shields.io/github/actions/workflow/status/turkananation/pqcrypto/sync-wiki.yml?branch=develop&style=for-the-badge&label=Wiki%20sync&logo=github&logoColor=white)](https://github.com/turkananation/pqcrypto/actions/workflows/sync-wiki.yml)

### Docs, Citation & Coding-Agent Discovery

[![Website](https://img.shields.io/badge/Website-GitHub%20Pages-0969da?style=for-the-badge&logo=githubpages&logoColor=white)](https://turkananation.github.io/pqcrypto/)
[![API reference](https://img.shields.io/badge/API-pub.dev%20docs-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://pub.dev/documentation/pqcrypto/latest/)
[![Wiki](https://img.shields.io/badge/Wiki-synced%20from%20repo-6f42c1?style=for-the-badge&logo=github&logoColor=white)](https://github.com/turkananation/pqcrypto/wiki)
[![Cookbook](https://img.shields.io/badge/Cookbook-project%20ideas-f59e0b?style=for-the-badge)](doc/cookbook/README.md)
[![llms.txt](https://img.shields.io/badge/llms.txt-agent%20ready-7c3aed?style=for-the-badge)](llms.txt)
[![Copilot](https://img.shields.io/badge/GitHub%20Copilot-repo%20instructions-8957e5?style=for-the-badge&logo=githubcopilot&logoColor=white)](.github/copilot-instructions.md)
[![Cursor](https://img.shields.io/badge/Cursor-rule%20pack-000000?style=for-the-badge)](.cursor/rules/pqcrypto.mdc)
[![Windsurf](https://img.shields.io/badge/Windsurf-rule%20pack-00a67e?style=for-the-badge)](.windsurfrules)
[![Citation](https://img.shields.io/badge/Citation-CFF-2ea043?style=for-the-badge)](CITATION.cff)

**pqcrypto** is a pure Dart library implementing Post-Quantum Cryptography (PQC) algorithms, targeting compatibility with Flutter and the Dart web ecosystem.

The `0.4.0` package provides a **FIPS 203-aligned implementation of ML-KEM
(Kyber)**, a **FIPS 204-aligned implementation of ML-DSA (Dilithium)**, and a
**FIPS 205-aligned implementation of SLH-DSA (SPHINCS+) across all 12 parameter
sets** — each with checked-in known-answer / ACVP vectors and focused unit
coverage. SLH-DSA covers both hash families (SHAKE and SHA-2) over 128/192/256
and the small/fast (`s`/`f`) variants, and is byte-exact on the 1,248 official
NIST ACVP sample cases.

Native-provider tooling cross-checks the delivered primitives against OpenSSL
and liboqs without changing the runtime package boundary: ML-KEM has the A-G
OpenSSL proof for all three levels, OpenSSL also byte-checks seeded ML-DSA and
SLH-DSA signatures, and liboqs exercises bidirectional ML-KEM, ML-DSA, and
SLH-DSA interoperability. ML-DSA is byte-exact against the official FIPS 204 KAT
corpus across every parameter set, signing mode, and implementation flavour
(see below). No algorithm in this package claims CMVP/FIPS 140 module
validation. See
[doc/FIPS_140_BOUNDARY.md](doc/FIPS_140_BOUNDARY.md) for exactly what is and is
not claimed.

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
- **FIPS 205-aligned SLH-DSA support (all 12 sets)**:
  - **Algorithm support**: all 12 sets — SLH-DSA-{SHAKE,SHA2}-128s/128f/192s/192f/256s/256f.
  - **Byte-exact evidence**: all 1,248 cases in the pinned official NIST
    ACVP sample corpus across keyGen, sigGen, and sigVer.
  - **Hardened API**: hedged signing by default, explicit deterministic and
    slow-signing paths, optional verify-after-sign, total malformed-input
    verification, and source-only ACVP internals.
  - **Measured costs**: 7,856-49,856 byte signatures; the published
    single-sample SHAKE baselines and benchmark commands are in
    [doc/PERFORMANCE.md](doc/PERFORMANCE.md).
- **Platform Agnostic**:
  - 100% Pure Dart. Works on Android, iOS, Windows, Linux, macOS, and Web (dart2js/dart2wasm) — verified on all three backends in CI.
  - **Zero dependencies.** No third-party packages at all: the current FIPS 202 surface (SHA3-224/256/384/512, SHAKE128/256, and incremental SHAKE XOFs) is vendored in-tree, so `lib/` depends only on Dart SDK libraries; full SP 800-185 completion targets 0.6.0, with 0.7.0 spillover if needed, and is tracked in [doc/FIPS202_SP800185_RELEASE_GUIDE.md](doc/FIPS202_SP800185_RELEASE_GUIDE.md).

---

## 🛡️ ML-KEM Validation Status

This implementation tracks [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), but this repository does not claim CMVP/FIPS 140 module validation ([why?](doc/FIPS_140_BOUNDARY.md)). The current evidence is the checked-in KAT corpus plus unit tests for the algorithm surfaces listed below.

| Algorithm       | Status       | Checked-in KAT Vectors | Security Level         |
| --------------- | ------------ | ---------------------- | ---------------------- |
| **ML-KEM-512**  | **KAT pass** | **1000/1000 PASS**     | NIST Level 1 (AES-128) |
| **ML-KEM-768**  | **KAT pass** | **1000/1000 PASS**     | NIST Level 3 (AES-192) |
| **ML-KEM-1024** | **KAT pass** | **1000/1000 PASS**     | NIST Level 5 (AES-256) |

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

| Parameter set | Security level | KeyGen (raw/det) | Sign + Verify (all flavours) |
| ------------- | -------------- | ---------------- | ---------------------------- |
| **ML-DSA-44** | NIST Level 2   | 100/100 PASS     | 600/600 PASS                 |
| **ML-DSA-65** | NIST Level 3   | 100/100 PASS     | 600/600 PASS                 |
| **ML-DSA-87** | NIST Level 5   | 100/100 PASS     | 600/600 PASS                 |

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

## 🛡️ SLH-DSA Validation Status

This implementation tracks [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
As with ML-KEM and ML-DSA, this repository does **not** claim CMVP/FIPS 140
module validation ([why?](doc/FIPS_140_BOUNDARY.md)); the evidence is the
checked-in official NIST ACVP sample corpus plus focused component, API, and
negative tests. The package exports `SlhDsa`, `SlhDsaParams`, `SlhDsaParameter`,
and `SlhDsaPreHash`.

All 12 FIPS 205 parameter sets are implemented — both hash families (`SHAKE` and
`SHA-2`), each across `128/192/256` and the small/fast (`s`/`f`) variants — and
every case in the pinned official NIST ACVP sample corpus is reproduced
**byte-for-byte**:

| Parameter set          | Security level | Signature bytes | ACVP       |
| ---------------------- | -------------- | --------------: | ---------- |
| **SLH-DSA-SHAKE-128s** | NIST Level 1   |           7,856 | byte-exact |
| **SLH-DSA-SHAKE-128f** | NIST Level 1   |          17,088 | byte-exact |
| **SLH-DSA-SHAKE-192s** | NIST Level 3   |          16,224 | byte-exact |
| **SLH-DSA-SHAKE-192f** | NIST Level 3   |          35,664 | byte-exact |
| **SLH-DSA-SHAKE-256s** | NIST Level 5   |          29,792 | byte-exact |
| **SLH-DSA-SHAKE-256f** | NIST Level 5   |          49,856 | byte-exact |
| **SLH-DSA-SHA2-128s**  | NIST Level 1   |           7,856 | byte-exact |
| **SLH-DSA-SHA2-128f**  | NIST Level 1   |          17,088 | byte-exact |
| **SLH-DSA-SHA2-192s**  | NIST Level 3   |          16,224 | byte-exact |
| **SLH-DSA-SHA2-192f**  | NIST Level 3   |          35,664 | byte-exact |
| **SLH-DSA-SHA2-256s**  | NIST Level 5   |          29,792 | byte-exact |
| **SLH-DSA-SHA2-256f**  | NIST Level 5   |          49,856 | byte-exact |

**Totals:** all 1,248 official NIST ACVP sample cases (120 keyGen, 624 sigGen,
504 sigVer) reproduce byte-for-byte across every parameter set. The public API
is **hedged by default**, supports FIPS 205 context strings, exposes explicit
deterministic and slow-signing paths, offers optional verify-after-sign fault
detection, and returns `false` (never throws) for malformed inputs.

**Choosing a parameter set.** The default is `SLH-DSA-SHAKE-128f`. As with
SPHINCS+ generally, SLH-DSA's message-bound (BUFF) property is
parameter-dependent (FIPS 205 §11): only the `*-128f` sets reach the category-1
message-binding bound, so when a signature authorizes an action, bind it to its
purpose with a context string and a unique message identity (a nonce or resource
id) — standard practice for any signature scheme. The small-signature `s` sets
trade roughly 29–56 s per signature in pure Dart for shorter signatures and
require explicit `allowSlowSigning: true`.

```dart
final params = SlhDsaParams.shake128f;
final context = Uint8List.fromList('com.example.artifact-signing/v1'.codeUnits);
final message = Uint8List.fromList(<int>[
  ...artifactDigest,
  ...uniqueReleaseNonce,
]);

final (pk, sk) = SlhDsa.generateKeyPair(params);
final sig = SlhDsa.sign(
  sk,
  message,
  params,
  context: context,
  verifyAfterSign: true,
);
final ok = SlhDsa.verify(pk, message, sig, params, context: context);
```

`verifyAfterSign` is optional fault detection: it adds a full verification and
does not prove resistance to hardware fault injection. Deterministic signing is
also explicit because repeated computations can amplify fault attacks. See the
controlling guide
[doc/SLHDSA_FIPS205_RELEASE_GUIDE.md](doc/SLHDSA_FIPS205_RELEASE_GUIDE.md),
[doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md), and
[doc/PERFORMANCE.md](doc/PERFORMANCE.md). This is checked-in ACVP/regression
evidence, not a CMVP/FIPS 140 validation claim.

---

## 🔗 Native Interoperability

`pqcrypto` stays pure Dart at runtime, but the repository carries unpublished
FFI tool packages that cross-check the wire formats and signatures against two
native providers. These tools live under `tool/`, use path dependencies on the
current checkout, and are excluded from the published package.

| Provider | Tool package                                     | Current coverage                                                                                                                                                                                                              |
| -------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenSSL  | [`tool/openssl_interop/`](tool/openssl_interop/) | ML-KEM-512/768/1024 A-G matrix; ML-DSA-44/65/87 seeded keys and hedged pure signatures byte-exact; all 12 SLH-DSA seeded keys plus internal/external signatures byte-exact.                                                   |
| liboqs   | [`tool/liboqs_interop/`](tool/liboqs_interop/)   | ML-KEM deterministic and bidirectional exchanges, including implicit rejection; ML-DSA-44/65/87 context-string signatures verify in both directions; all 12 pure SLH-DSA context-string signatures verify in both directions. |

`pqcrypto` cross-checks **all three algorithm families** against the native
providers — not just ML-KEM. The OpenSSL and liboqs harnesses prove the
standardized byte contracts and signature interoperability across ML-KEM,
ML-DSA, and SLH-DSA.

**ML-KEM (A–G).** `pqcrypto`'s ML-KEM is **wire-compatible with OpenSSL's**
native ML-KEM at **all three parameter sets** — ML-KEM-512, ML-KEM-768, and
ML-KEM-1024. The ML-KEM OpenSSL harness proves:

| Test      | What it proves                                                         |
| --------- | ---------------------------------------------------------------------- |
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

**ML-DSA (44/65/87).** From a shared seed, OpenSSL derives the same key pairs and
produces **byte-identical** signatures for the same message, context, and hedging
randomness; signatures verify in both directions. liboqs independently verifies
`pqcrypto` context-string signatures, and vice versa.

**SLH-DSA (all 12 sets).** OpenSSL derives byte-identical key pairs and signatures
(internal and external context-string) for every parameter set; liboqs verifies
`pqcrypto` context-string signatures in both directions across all 12 sets.

> **The library stays 100% pure Dart.** The native-provider checks are
> developer/CI tools that use `dart:ffi` to call OpenSSL `libcrypto` or
> `liboqs.so`. They are **not** part of the `pqcrypto` package or its
> dependencies — `lib/` imports no FFI, nothing native ships to consumers, and
> the tools are excluded from the published package (see `.pubignore`).

- **OpenSSL:** the build script pins **OpenSSL 4.0.1** and verifies the source
  archive digest before compiling. `LIBCRYPTO_PATH` can point at any compatible
  `libcrypto` that exposes the standardized PQC algorithms.
- **liboqs:** the build script pins **liboqs 0.15.0** to an exact commit,
  enables only the 18 algorithms under test, and disables OpenSSL acceleration
  so it remains an independent native provider.

```sh
cd tool/openssl_interop
dart pub get
bash tool/build_openssl.sh
LIBCRYPTO_PATH=.native/openssl-4.0.1/lib/libcrypto.so dart test --concurrency=1
dart run bin/openssl_pqcrypto_interop.dart   # human-readable ML-KEM harness

cd ../liboqs_interop
dart pub get
bash tool/build_liboqs.sh
LIBOQS_PATH=.native/liboqs-0.15.0/lib/liboqs.so dart test --concurrency=1
```

CI runs both provider suites on every push via
[`.github/workflows/interop.yml`](.github/workflows/interop.yml).

**Full details:** [doc/OPENSSL_INTEROP.md](doc/OPENSSL_INTEROP.md) — provider
requirements, FFI boundaries, exact test semantics, and use cases (hybrid TLS
`X25519MLKEM768`, Dart ↔ native services, and ML-DSA/SLH-DSA signature migration
and cross-checking).

---

## 🛠️ Implementation Highlights

This library follows the FIPS 203, FIPS 204, and FIPS 205 specification
structures where practical while keeping validation claims scoped to the tests
in this repository. ML-KEM and ML-DSA use separate polynomial types, moduli,
NTTs, packing code, and parameter objects so the two lattice schemes do not
share algorithm-specific arithmetic accidentally; SLH-DSA is kept in its own
hash-based implementation tree.

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

### 5. SLH-DSA Hash-Based Architecture

SLH-DSA lives under `lib/src/algos/slhdsa/` and is hash-only — no lattice
arithmetic — so it diversifies against any future lattice cryptanalysis:

- **Public API layering**: `SlhDsa.generateKeyPair`, `sign`, `verify`, and the
  HashSLH-DSA pre-hash surface expose FIPS 205 Algorithms 21-25; internal
  Algorithms 18-20 stay source-only behind `SlhDsaInternal` for ACVP execution.
- **Parameter sets**: `SlhDsaParams` carries all 12 sets (both `SHAKE` and
  `SHA-2` families) with FIPS 205 Table 2 byte sizes and the structural
  parameters (hypertree height and layers, Winternitz width, and FORS
  dimensions).
- **Composition**: `wots.dart` (WOTS+), `xmss.dart` (XMSS), `hypertree.dart`,
  and `fors.dart` build the one-time/few-time trees the signature algorithms
  compose, using the 32-byte `ADRS` and 22-byte `ADRS^c` addressing in
  `address.dart`.
- **Hash instantiation**: `hashing.dart` selects the SHAKE-256 family or the
  HMAC-SHA-256/512 + MGF1 SHA-2 family (security category 1 vs 3/5) per set.
- **Hardened signing**: hedged by default, explicit deterministic and
  slow-signing (`allowSlowSigning`) paths, context binding (≤ 255 bytes),
  HashSLH-DSA pre-hash with DER OIDs, optional verify-after-sign, and total
  malformed-input verification.

### 6. Cryptographic Primitives

- **ML-KEM XOF/PRF**: SHAKE-128 for FIPS 203 matrix/sample generation and
  SHAKE-256 for noise sampling.
- **ML-KEM hash functions**: SHA3-256 and SHA3-512 for FIPS 203 key derivation,
  ciphertext binding, and implicit rejection.
- **ML-KEM CBD Sampling**: Centered Binomial Distribution with
  $\eta \in \{2,3\}$.
- **ML-DSA XOF/CRH**: SHAKE-128 for `ExpandA`; SHAKE-256 for `H`, `G`, `CRH`,
  bounded sampling, mask expansion, and challenge sampling.
- **Vendored FIPS 202 foundation**: SHA3-224/256/384/512, SHAKE128/256, and incremental SHAKE XOFs are implemented in-tree (`lib/src/common/keccak.dart`) with **no third-party dependency**, using web-safe 32-bit lane arithmetic verified on the VM, `dart2js`, and `dart2wasm`. Full SP 800-185 work targets 0.6.0, with 0.7.0 spillover if needed, and is tracked in [doc/FIPS202_SP800185_RELEASE_GUIDE.md](doc/FIPS202_SP800185_RELEASE_GUIDE.md).
- **Vendored FIPS 180-4**: SHA-256/384/512 are implemented in-tree
  (`lib/src/common/sha2.dart`) for HashML-DSA pre-hashing, using 32-bit word
  pairs for SHA-384/512 portability across the VM and web compilers.

### 7. Security Hardening

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
  across raw/pure/hashed and deterministic/hedged signing; and
  `test/slhdsa_kat_test.dart` covers all 1,248 SLH-DSA ACVP cases across all
  12 parameter sets.

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
    │   ├── dilithium/            # ✍️ ML-DSA (FIPS 204) implementation
    │   │   ├── dsa.dart          # 🖊️ MlDsa: external + internal + HashML-DSA
    │   │   │                     #    KeyGen/Sign/Verify (Algs 1-3), *_internal
    │   │   │                     #    (Algs 6-8), HashML-DSA sign/verify (Algs 4-5)
    │   │   ├── params.dart       # 📏 ML-DSA-44/65/87 params + Table 2 sizes
    │   │   ├── poly.dart         # 🧮 DilithiumPoly / vector types (q=8380417)
    │   │   ├── ntt.dart          # 🔁 Complete NTT + Appendix B zetas
    │   │   ├── packing.dart      # 💾 pk/sk/sig encode/decode (signed domains)
    │   │   ├── rounding.dart     # 📐 Power2Round/Decompose/MakeHint/UseHint
    │   │   └── symmetric.dart    # 🎲 ExpandA/S, ExpandMask, SampleInBall, pre-hash
    │   │
    │   └── slhdsa/               # 🌲 SLH-DSA (FIPS 205) all 12 sets
    │       ├── params.dart       # 📏 SHA2/SHAKE params + derived sizes
    │       ├── slhdsa.dart       # ✍️ Algorithms 21-25 public API + internals
    │       ├── hashing.dart      # 🧱 SHAKE/SHA-2 hash instantiations
    │       ├── address.dart      # 🧭 ADRS and ADRS^c addressing
    │       ├── fors.dart         # 🌳 FORS few-time signatures
    │       ├── wots.dart         # 🔗 WOTS+ one-time signatures
    │       ├── xmss.dart         # 🌲 XMSS layer
    │       └── hypertree.dart    # 🏗️ Hypertree composition
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
        │                         # - SHA3-224/256/384/512, SHAKE128/256, KeccakXof
        │                         # - SP 800-185 tracked in doc/
        │                         # - web-safe 32-bit lanes (dart2js/dart2wasm)
        │
        ├── sha2.dart             # #️⃣ Vendored FIPS 180-4 SHA-2 family
        │                         # - HashML-DSA/HashSLH-DSA pre-hash; web-safe 64-bit pairs
        ├── hmac.dart             # 🔐 HMAC-SHA-256/512 for SLH-DSA SHA-2 sets
        ├── mgf1.dart             # 🎭 MGF1-SHA-256/512 for SLH-DSA SHA-2 sets
        │
        └── zeroize.dart          # 🧹 Best-effort secret zeroization helpers

test/
├── kat_evaluator_test.dart       # 🧪 Checked-in ML-KEM KAT runner (3000 vectors, VM-only)
├── mldsa_kat_test.dart           # 🧪 Discovered ML-DSA KAT runner (18 files, all flavours, VM-only)
├── slhdsa_kat_test.dart          # 🧪 ACVP SLH-DSA runner (1,248 cases, VM-only)
├── slhdsa_*_test.dart            # 🌲 SLH-DSA component/API/negative regressions
├── dsa_zetas_test.dart           # 🧮 FIPS 204 Appendix B zetas + negacyclic NTT property
├── dsa_rounding_test.dart        # 📐 Power2Round/Decompose/MakeHint/UseHint boundaries
├── dsa_negative_test.dart        # 🚫 Malformed pk/sig/hint/context: verify returns false
├── dsa_api_test.dart             # 🔐 Context binding, hedged vs deterministic, domain separation
├── sha2_test.dart                # #️⃣ SHA-2 family for HashML-DSA/HashSLH-DSA
├── hmac_test.dart                # 🔐 RFC 4231 HMAC-SHA-256/512
├── mgf1_test.dart                # 🎭 RFC 8017 MGF1-SHA-256/512
├── keccak_test.dart              # 🧱 FIPS 202 (SHA3/SHAKE) known-answer tests
├── fips202_examples_test.dart    # 📚 Selected official FIPS 202 byte examples
├── roundtrip_test.dart           # 🔁 End-to-end KEM round-trip (runs on VM + web)
├── kem_validation_test.dart      # 🔎 Public key, secret key, and ciphertext checks
├── keygen_derivation_test.dart   # 🔑 G(d‖k) + matrix XOF-ordering unit tests
├── pack_test.dart                # 📦 Serialization round-trip bounds
├── poly_test.dart                # 🧮 Modular reduction properties
├── cbd_test.dart                 # 📊 Statistical distribution checks
└── data/
    ├── MLKEM/                    # ML-KEM KAT corpus (512/768/1024) + README
    │   └── kat_MLKEM_*.rsp
    ├── MLDSA/                    # ML-DSA KAT corpus + README
    │   └── kat_MLDSA_{44,65,87}_{det,hedged}_{raw,pure,hashed}.rsp
    ├── SLHDSA/                   # SLH-DSA official ACVP sample corpus + README
    └── FIPS202/                  # Selected official byte examples + README

tool/
├── interop_common/               # 🔗 Provider-neutral algorithm metadata
├── openssl_interop/              # 🔗 OpenSSL FFI interop harness (dev tool)
│   ├── lib/openssl_ml_kem.dart   #    EVP ML-KEM bindings
│   ├── lib/openssl_signature.dart#    EVP ML-DSA/SLH-DSA bindings
│   ├── bin/openssl_pqcrypto_interop.dart
│   └── test/{mlkem,mldsa,slhdsa}_interop_test.dart
├── liboqs_interop/               # 🔗 liboqs FFI interop harness (dev tool)
│   └── test/{mlkem,mldsa,slhdsa}_interop_test.dart
└── bench/                        # ⚡ SLH-DSA VM/dart2js/dart2wasm benchmark tooling

.github/
└── workflows/
    ├── ci.yml                    # analyze + format + unit/KAT suite + web (dart2js/dart2wasm)
    └── interop.yml               # OpenSSL/liboqs ↔ pqcrypto native interop
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

### 2. ML-DSA and SLH-DSA KATs

- **ML-DSA**: `test/mldsa_kat_test.dart` executes 18 files under
  `test/data/MLDSA` for 300 byte-exact key generations and 1800 byte-exact
  signatures across ML-DSA-44/65/87 × deterministic/hedged × raw/pure/hashed.
- **SLH-DSA**: `test/slhdsa_kat_test.dart` executes the official ACVP sample
  corpus under `test/data/SLHDSA`: 120 keyGen cases, 624 sigGen cases, and 504
  sigVer outcomes across all 12 SHA2/SHAKE sets.

### 3. Unit & Property Tests

- **Serialization (`test/pack_test.dart`)**: Round-trip validation for all compressed bit-depths using modular distance over `q`.
- **Reduction (`test/poly_test.dart`)**: Verifies `barrettReduce` returns canonical residues in `[0, q - 1]`, including negative and boundary cases.
- **Statistical (`test/cbd_test.dart`)**: Verifies the output distribution of the CBD sampler matches theoretical binomial probabilities.
- **FIPS 202 and FIPS 180-4 primitives**: `test/keccak_test.dart`,
  `test/fips202_examples_test.dart`, `test/sha2_test.dart`, `test/hmac_test.dart`,
  and `test/mgf1_test.dart` pin the vendored hash foundations used by the
  algorithms.

### 4. Validation, Negative, Web, and Interop Testing

- **Input validation (`test/kem_validation_test.dart`)**: Confirms malformed public keys, malformed secret keys, and wrong ciphertext lengths are rejected.
- **Invalid decapsulation KATs (`test/kat_evaluator_test.dart`)**: Confirms checked-in `ct_n` vectors produce their expected `ss_n` shared secrets.
- **Negative signature tests**: `dsa_negative_test.dart` and
  `slhdsa_negative_test.dart` cover malformed keys/signatures, wrong contexts,
  and domain confusion.
- **Web portability**: CI runs the portable suite under Chrome with both
  `dart2js` and `dart2wasm`; VM-only corpus readers use `@TestOn('vm')`.
- **Native interop**: `.github/workflows/interop.yml` builds OpenSSL 4.0.1 and
  liboqs 0.15.0, then runs the unpublished FFI test packages under `tool/`.

---

## ⚡ Performance

Benchmarks on commodity Linux x64 hardware (Dart 3.x VM, JIT):

| Algorithm       | Key Generation | Encapsulation | Decapsulation | Security Level   |
| --------------- | -------------- | ------------- | ------------- | ---------------- |
| **ML-KEM-512**  | ~0.7 ms        | ~0.7 ms       | ~0.6 ms       | 128-bit security |
| **ML-KEM-768**  | ~1.3 ms        | ~1.4 ms       | ~1.0 ms       | 192-bit security |
| **ML-KEM-1024** | ~1.8 ms        | ~1.8 ms       | ~1.7 ms       | 256-bit security |

SLH-DSA signing cost varies widely by parameter set: the `f` (fast) sets sign in
well under a second, while the `s` (small-signature) sets take tens of seconds
per signature in pure Dart and require explicit `allowSlowSigning: true`.
Published single-sample SLH-DSA baselines across the VM, `dart2js`, and
`dart2wasm` are in [doc/PERFORMANCE.md](doc/PERFORMANCE.md).

---

## 🔮 Roadmap

- ✅ **Phase 1: Foundation** (Project structure, Poly math)
- ✅ **Phase 2: Correctness** (GenMatrix, CBD, FO Transform)
- ✅ **Phase 3: FIPS 203 Alignment** (NTT, Compression, ByteEncode)
- ✅ **Phase 4: Full Suite** (ML-KEM-512/768/1024 support)
- ✅ **Phase 5: ML-DSA validation** (byte-exact FIPS 204 KATs for 44/65/87 across raw/pure/hashed × det/hedged; external hedged API; HashML-DSA; repo-local corpus)
- ✅ **Phase 6: SLH-DSA (FIPS 205, all 12 sets)** (API for all 12 sets exported;
  all 1,248 ACVP cases byte-exact across both hash families; verify-after-sign,
  SHAKE benchmark baselines, VM/web matrix, and native-provider interop — shipped
  in 0.4.0)

See [doc/ROADMAP.md](doc/ROADMAP.md) for the evidence-scoped roadmap.

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  pqcrypto: ^0.4.0
```

`pqcrypto` pulls in no third-party dependencies of its own.

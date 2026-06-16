# Changelog

## Unreleased

## 0.4.0

### Added

- Added FIPS 205 SLH-DSA for **all 12 parameter sets** — both hash families
  (SHAKE and SHA-2) across 128/192/256 and the small/fast `s`/`f` variants —
  exported at the package root as `SlhDsa`, `SlhDsaParams`, `SlhDsaParameter`,
  and `SlhDsaPreHash`. Internal Algorithms 18-20 stay source-only for ACVP
  execution; WOTS+/XMSS/hypertree/FORS remain internal components, not public
  APIs.
- Added the pinned official NIST ACVP SLH-DSA sample corpus for all 12
  parameter sets (1,248 keyGen/sigGen/sigVer cases), with source provenance,
  SHA-256 integrity checks, and ACVP structure/coverage tests. A VM-only ACVP
  runner is byte-exact on all 1,248 cases.
- Vendored the SHA-2-family primitives beneath the six SHA-2 sets: HMAC-SHA-256/512
  (RFC 4231) and MGF1-SHA-256/512 (RFC 8017), each independently KAT-gated, plus
  the 22-byte compressed address (`ADRS^c`) and the security-category 1 vs 3/5
  SHA-256/SHA-512 instantiation split. Added SHA-224, SHA-512/224, and
  SHA-512/256 to the vendored FIPS 180-4 core for the complete HashSLH-DSA
  pre-hash matrix.
- Implemented the FIPS 205 component and signature algorithms (5-25) with
  portable `BigInt` tree indices, hedged-by-default signing, explicit
  deterministic and slow-signing (`allowSlowSigning`) paths, context binding
  (<= 255 bytes), HashSLH-DSA pre-hash with DER OIDs, optional verify-after-sign
  fault detection, best-effort secret zeroization, and total malformed-input
  verification (length-checked before parsing).
- Added component, negative, and package-root API/misuse tests, and a portable
  SLH-DSA benchmark harness covering all 12 sets. Published single-sample
  keygen/sign/verify baselines under VM JIT, compiled JavaScript, and compiled
  Wasm.
- Added SHA3-224 and SHA3-384 to the vendored FIPS 202 implementation, direct
  Keccak-f[1600] constants/profile tests, and a normalized selected NIST
  byte-example corpus with source provenance.

### Changed

- Added explicit Keccak sponge/output validation and broader VM/web regression
  coverage for rate boundaries and incremental XOF squeezing.
- Surfaced the SLH-DSA message-bound (BUFF), deterministic-signing,
  slow-parameter, RBG, and best-effort zeroization boundaries in API and release
  documentation. This remains KAT/regression evidence, not a CMVP/FIPS 140
  validation claim.
- Promoted SLH-DSA to a first-class released algorithm alongside ML-KEM and
  ML-DSA: the package version is now `0.4.0`, and the generated website,
  AI-discovery files, and coding-agent rules list all 12 SLH-DSA sets with
  1,248/1,248 ACVP evidence as part of the 0.4.0 surface.

## 0.3.1

### Changed

- Updated package description to highlight zero-dependency, byte-exact FIPS 203 ML-KEM, and full FIPS 204 ML-DSA support, removing the "experimental" label.

## 0.3.0

### Added

- Project-level Universal Multi-Agent PQC Framework setup:
  - canonical framework guide in `doc/UNIVERSAL_MULTI_AGENT_PQC_FRAMEWORK.md`;
  - machine-readable manifest in `tool/agent_framework/pqc_framework.yaml`;
  - native thin wrappers for Codex, Claude Code, and Antigravity.
- `example/main.dart` now demonstrates ML-KEM shared-secret agreement,
  ML-DSA signing/verification, and an ML-DSA-signed ML-KEM-768 handshake
  transcript.
- `doc/SERVERPOD_FLUTTER_GUIDE.md` now covers ML-KEM + ML-DSA Serverpod/Flutter
  integration, strict byte contracts, generated model sketches, Flutter isolate
  guidance, and framework-driven implementation prompts.
- **ML-DSA (FIPS 204) is now byte-exact against the official KAT corpus** for
  ML-DSA-44, ML-DSA-65, and ML-DSA-87 across the full matrix of signing mode
  (`deterministic`, `hedged`) × implementation flavour (`raw`/internal,
  `pure`/external-with-context, `hashed`/HashML-DSA): 300/300 key generations
  and 1800/1800 signatures reproduced byte-for-byte, all verifying.
- **External FIPS 204 API** on `MlDsa`: `generateKeyPair(params)` (fresh
  randomness), `sign`/`verify` with a context string (≤ 255 bytes) and
  **hedged-by-default** signing, `signDeterministic`, and the internal/CAVP
  helpers `generateKeyPairSeeded`, `signInternal`, `verifyInternal`.
- **HashML-DSA** (`hashSign`/`hashVerify`) with the FIPS 204 §5.4 pre-hash:
  SHA-256 (ML-DSA-44), SHA-384 (ML-DSA-65), SHA-512 (ML-DSA-87), with DER OID
  domain separation.
- **Vendored FIPS 180-4 SHA-2** (`lib/src/common/sha2.dart`): SHA-256/384/512,
  web-safe 64-bit (hi/lo pair) arithmetic, pinned by direct NIST vectors.
- Repo-local ML-DSA KAT corpus under `test/data/MLDSA` (18 `.rsp` files) with a
  discovered, deterministic runner `test/mldsa_kat_test.dart`; ML-KEM corpus
  moved to `test/data/MLKEM`.
- New focused tests: Appendix B zetas + negacyclic NTT property, rounding
  boundary cases, malformed-input/negative verification, external-API behavior,
  and direct SHA-2 vectors. All run on the VM, `dart2js`, and `dart2wasm`.
- `SECURITY.md` (vulnerability reporting / coordinated disclosure policy) and
  `doc/FIPS_140_BOUNDARY.md` (why algorithm conformance is not CMVP/FIPS 140
  module validation), linked from every place the claim boundary is raised.

### Changed

- **ML-KEM decapsulation hardening**: the FIPS 203 output is now selected with a
  constant-time branchless mask — both `K'` and `J(z || c)` are always computed,
  so success vs. implicit-rejection no longer differs in control flow. Secret
  intermediates (`m'`, `K' || r'`, `J(z || c)`, `c'`, `z`) are zeroized in a
  `finally` block, and the KEM now reuses a cached `Random.secure()`. The
  3000-vector ML-KEM KAT corpus (including invalid-ciphertext vectors) remains
  byte-exact.

- ML-DSA rejection samplers (`RejNTTPoly`, `RejBoundedPoly`, `SampleInBall`) now
  use an **incremental SHAKE XOF** (`KeccakXof`) instead of fixed buffers, so
  they cannot exhaust output during normal operation.
- ML-DSA packing preserves **signed coefficient domains** for `s1`/`s2`/`t0`/`z`
  instead of folding negatives into `[0, q-1]`.
- `_normExceeds` (the ML-DSA norm gate) evaluates all 256 coefficients with no
  secret-dependent early exit, and uses only VM/web-portable arithmetic.
- Verification is **total**: `MlDsa.verify`/`verifyInternal` return `false`
  (never throw) for wrong pk/sig lengths, malformed hints, or over-long context.
- `DilithiumParams` exposes computed FIPS 204 Table 2 sizes
  (`publicKeyBytes`, `secretKeyBytes`, `signatureBytes`, plus per-poly sizes,
  `lambda`, `securityCategory`) as the single source of truth; the unused
  `crhBytes` constant was removed.

### Fixed

- **`RejBoundedPoly` (`ExpandS`) for η=2**: now accepts half-bytes `< 15` mapping
  to `2 − (b mod 5)` per FIPS 204, fixing the stream-consumption rate that made
  key generation diverge from the standard. This was the sole core defect.
- ML-DSA verification no longer used a 32-bit left shift (`<< d`) that overflowed
  on `dart2js`; it multiplies by `2^d` so web results match the VM.

### Security

- Best-effort secret zeroization (`lib/src/common/zeroize.dart`) applied in
  `finally` blocks around key generation and signing intermediates. Dart cannot
  guarantee hard memory erasure; see `doc/SECURITY_AUDIT.md` for the boundary.

### Notes

- This repository continues to make **no CMVP/FIPS 140 module validation claim**.
  ML-DSA conformance evidence is the checked-in KAT corpus and regression suite.

## 0.2.1

### Added

- Expanded the OpenSSL interoperability harness from ML-KEM-768 only to
  **ML-KEM-512, ML-KEM-768, and ML-KEM-1024**.
- Added stronger OpenSSL interop checks:
  - Deterministic shared-seed key generation proves byte-identical public keys.
  - Public-key import/export round-trip proves raw wire encoding compatibility.
  - Invalid-ciphertext implicit rejection proves `J(z || c)` agreement.
  - Negative coverage confirms truncated OpenSSL public keys are rejected.
- Added VM + web round-trip tests so KEM keygen/encaps/decaps is exercised under
  the Dart VM, `dart2js`, and `dart2wasm`.
- Added FIPS 202 SHA-3/SHAKE known-answer coverage for the vendored Keccak
  implementation.

### Changed

- Removed the `pointycastle` runtime dependency by vendoring the FIPS 202
  SHA3-256, SHA3-512, SHAKE128, and SHAKE256 implementation in-tree.
- Updated the README and OpenSSL interop documentation to describe the
  all-parameter-set A-G interop suite, OpenSSL >= 3.5 requirement, and
  zero-dependency pure-Dart package boundary.
- Updated CI to include web compiler testing and the expanded OpenSSL
  interoperability suite.

## 0.2.0

### Added

- **Input validation** for `encapsulate()` and `decapsulate()` per FIPS 203 §7.2/§7.3:
  - Public key length and modulus checks (non-canonical coefficient rejection via `ByteEncode₁₂ ∘ ByteDecode₁₂` round-trip).
  - Secret key length and embedded `H(pk)` integrity check.
  - Ciphertext length check.
  - `Pack.decodeSecretKey` length guard.
- **OpenSSL interoperability tool** (`tool/openssl_interop/`): `dart:ffi`-based harness proving wire-level ML-KEM-768 compatibility with OpenSSL ≥ 3.5. Four-way test matrix (A/B/C/D) validates byte-identical shared secrets across implementations.
- **CI workflows**:
  - `ci.yml`: format check, static analysis, and full test suite (unit + 3000-vector KAT corpus) on every push/PR.
  - `interop.yml`: builds OpenSSL 4.0.0 from source (cached), runs the four interop tests on every push/PR.
- **New tests**:
  - `kem_validation_test.dart`: exercises all input validation paths across ML-KEM-512/768/1024.
  - `keygen_derivation_test.dart`: isolates FIPS 203 domain separation (`G(d || k)`) and matrix expansion ordering.
  - `poly_test.dart`: verifies `barrettReduce` returns canonical residues in `[0, q)`.
- **Documentation**:
  - `doc/MLKEM_TESTING.md`: KAT file hashes, coverage boundaries, release-gate commands, and scoped claim boundary.
  - `doc/OPENSSL_INTEROP.md`: full interop guide with FFI bindings, versions, results, and use cases.
- Test hooks `genMatrixEntryForTest` / `sampleNttForTest` on `Indcpa` (internal, not exported).
- `.pubignore` to exclude dev-only files from the published package.

### Changed

- **Naming conventions**: renamed internal identifiers to idiomatic Dart `lowerCamelCase` (`_H`/`_G`/`_J` → `_h`/`_g`/`_j`; `A_hat`/`t_hat`/`r_hat` → `aHat`/`tHat`/`rHat`; etc.). No behavioral change.
- `barrettReduce()`: use `const` for compile-time constants and add a fallback `res %= q` guard for edge-case residues.
- Renamed `test/kat_evaluator.dart` → `test/kat_evaluator_test.dart` so `dart test` discovers it automatically.
- README rewritten with scoped validation claims, OpenSSL interop section, and corrected Markdown formatting.
- `pubspec.yaml` description: fixed typo ("Startss" → "Starts"), updated wording to "FIPS 203-aligned".

### Removed

- Unused `Poly.montgomeryReduce()` (the implementation uses Barrett reduction exclusively).

## 0.1.0

- Initial release of `pqcrypto`.
- Implements **ML-KEM (Kyber)** FIPS 203 standard.
- Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- Pure Dart implementation with 3000/3000 NIST KAT vectors passing.
- Compatible with Flutter and Dart Web (Wasm/JS).

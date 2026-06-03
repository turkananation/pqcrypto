# Changelog

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

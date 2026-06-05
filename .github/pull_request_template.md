# Pull Request Checklist

Thank you for contributing to `pqcrypto`! To ensure cryptographic correctness, portability, and compliance integrity, please review and complete this checklist before submitting your PR.

## 📝 Description
<!-- Summarize the changes introduced, their rationale, and any related issues. -->

## 🛡️ Cryptographic & Compliance Check (Mandatory)
- [ ] **No Unapproved FIPS Claims:** This PR does not introduce, upgrade, or suggest "FIPS validated", "CMVP certified", or "FIPS 140-3 compliant" terminology. All language complies with the [FIPS 140 Boundary Guide](doc/FIPS_140_BOUNDARY.md).
- [ ] **KAT Verification:** If cryptographic logic was modified, the change is verified byte-exact against the official test vectors.
- [ ] **Secret Zeroization:** Any new or modified secret buffers (e.g., private keys, ephemeral secrets, derived key material) use `secureZero` or `secureZeroInt32` in `finally` blocks to defend against memory leakage.

## ⚙️ Verification Gates
Please run the following validation gates locally and check them off:

- [ ] **Static Analysis:** `dart analyze` exits with `0` issues.
- [ ] **Full Test Suite:** `dart test` passes cleanly (160+ tests).
- [ ] **Targeted KAT Runs:**
  - `dart test test/kat_evaluator_test.dart` (ML-KEM vectors)
  - `dart test test/mldsa_kat_test.dart` (ML-DSA vectors)
- [ ] **Formatting:** Code format passes `dart format --set-exit-if-changed .`
- [ ] **Web Portability:** Verified web-portable execution with:
  - `dart test -p chrome` (dart2js)
  - `dart test -p chrome --compiler dart2wasm` (dart2wasm)

## 📦 Dependency & Package Hygiene
- [ ] **Zero Runtime Dependencies:** This PR does not introduce any third-party runtime package dependencies in `pubspec.yaml`.
- [ ] **AI Config Integrity:** AI agent configuration files (`AGENTS.md`, `CLAUDE.md`, `.gemini/`, `.claude/`, `.codex/`) have **not** been modified unless explicitly part of tool framework upgrades.
- [ ] **Dry Run Publish:** `dart pub publish --dry-run` completes with `0` warnings.
- [ ] **Exclusions:** Verified that no development tools, local test data, or draft documentation bypasses `.pubignore`.

---
*By submitting this PR, you agree to license your contributions under the MIT license.*

# Contributing to pqcrypto

Thank you for your interest in contributing to `pqcrypto`! This document outlines the process for contributing to the project to ensure a smooth, secure, and collaborative environment.

## 1. Development Setup

The `pqcrypto` package is pure Dart, meaning there are no native bindings or C FFI dependencies to configure.

### Prerequisites

- Dart SDK `^3.10.0` or Flutter SDK containing a compatible Dart version.

### Installation

1. Fork the repository and clone it locally.
2. Run `dart pub get` to install development dependencies.
3. Verify your setup by running the test suite:

   ```bash
   dart test
   ```

## 2. Core Principles

Before writing code, please review these core design constraints:

- **Zero Runtime Dependencies**: The core package must remain pure Dart. We vendor required primitives (like FIPS 202 Keccak/SHA-3 and FIPS 180-4 SHA-2) internally rather than adding external dependencies.
- **Strict Compliance over Innovation**: Cryptographic implementations must adhere strictly to the FIPS standards (FIPS 203 for ML-KEM, FIPS 204 for ML-DSA).
- **KAT Validation**: All cryptographic logic must be validated against the official NIST Known Answer Test (KAT) vectors.
- **Claim Boundaries**: Do not claim CMVP or FIPS 140 module validation. Our evidence is strictly "byte-exact regression and KAT validation." Read `doc/FIPS_140_BOUNDARY.md` for more details.

## 3. Pull Request Checklist

When submitting a PR, ensure you have completed the following steps:

- [ ] **Branching**: Create your feature or bugfix branch from the `develop` branch (e.g., `git checkout -b feat/add-new-hash develop`).
- [ ] **Formatting**: Code must be formatted using `dart format`.
- [ ] **Static Analysis**: `dart analyze` must return **0 issues**. We use strict linting rules (`lints: ^6.0.0`).
- [ ] **Unit Tests**: Add tests for any new behavior or bug fixes.
- [ ] **KAT Tests**: If you modified cryptographic math, serialization, or packing, ensure `dart test test/kat_evaluator_test.dart` and `dart test test/mldsa_kat_test.dart` pass perfectly.
- [ ] **Documentation**: Update `CHANGELOG.md` under the `## Unreleased` section. Update any relevant docs in the `doc/` folder.
- [ ] **Web Compatibility**: Ensure your code doesn't use VM-only APIs (like `dart:io` or `dart:ffi` inside `lib/`). Tests should pass on web compilers:

  ```bash
  dart test -p chrome
  dart test -p chrome --compiler dart2wasm
  ```

## 4. How to Submit a Pull Request

1. Push your branch to your fork.
2. Open a Pull Request targeting the `develop` branch of the main repository.
3. Provide a clear and descriptive PR title (e.g., `feat: implement HashML-DSA`, `fix: correct parameter parsing in ML-KEM`).
4. In the PR description, explain *why* the change is needed and link to any relevant issues.
5. Wait for CI to complete and for a maintainer to review.

## 5. Security Vulnerabilities

If you discover a security vulnerability, **do not** open a public issue. Please follow the instructions in our `SECURITY.md` file for coordinated disclosure.

## 6. Architectural Documentation

For a deeper dive into the project's structure, refer to:

- `doc/ARCHITECTURE.md`
- `doc/ENGINEERING_GUIDE.md`
- `doc/SECURITY_AUDIT.md`

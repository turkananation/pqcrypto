# Contributing

Contributions are welcome. `pqcrypto` is a cryptographic library, so correctness
and evidence are paramount — every change must keep the test gates green and must
not overstate what is claimed.

## Before you start

- Read
  [CONTRIBUTING.md](https://github.com/turkananation/pqcrypto/blob/main/CONTRIBUTING.md)
  and the
  [CODE_OF_CONDUCT.md](https://github.com/turkananation/pqcrypto/blob/main/CODE_OF_CONDUCT.md).
- Read the
  [Engineering Guide](https://github.com/turkananation/pqcrypto/blob/main/doc/ENGINEERING_GUIDE.md)
  for setup, conventions, and security practices.
- Skim [Architecture](Architecture) and [Design Philosophy](Design-Philosophy).

## Local setup and verification

```bash
dart pub get
dart analyze                                   # must exit 0
dart format --set-exit-if-changed .            # formatting gate
dart test                                       # full unit + KAT suite (VM)
dart test -p chrome                             # dart2js web gate
dart test -p chrome --compiler dart2wasm        # dart2wasm web gate
dart test test/kat_evaluator_test.dart          # ML-KEM KAT runner
dart test test/mldsa_kat_test.dart              # ML-DSA KAT runner
npx markdownlint-cli2 "**/*.md"                 # docs lint
```

OpenSSL interop (optional, needs OpenSSL ≥ 3.5) lives in
[`tool/openssl_interop/`](https://github.com/turkananation/pqcrypto/tree/main/tool/openssl_interop).

## Ground rules

- **Keep zero runtime dependencies.** Vendor primitives in pure Dart rather than
  adding packages.
- **No `print()` in `lib/`.**
- **Treat ML-KEM and ML-DSA separately** — evidence for one does not imply the
  other.
- **Prefer repo-local fixtures** under `test/data`; no machine-local KAT paths.
- **Never claim CMVP/FIPS 140 validation.** Keep wording within the
  [evidence boundary](FIPS-Compliance).
- **Update docs** when the public API, validation evidence, or security posture
  changes.

## Where work is tracked

- [ROADMAP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ROADMAP.md)
  — release direction.
- [PROGRESS_TRACKER.md](https://github.com/turkananation/pqcrypto/blob/main/doc/PROGRESS_TRACKER.md)
  — open work and gates.
- [BUGS.md](https://github.com/turkananation/pqcrypto/blob/main/doc/BUGS.md)
  and
  [IMPROVEMENTS.md](https://github.com/turkananation/pqcrypto/blob/main/doc/IMPROVEMENTS.md).

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow the coordinated
disclosure process in
[SECURITY.md](https://github.com/turkananation/pqcrypto/blob/main/SECURITY.md).

## Community

- [Discussions](https://github.com/turkananation/pqcrypto/discussions)
- [Issues](https://github.com/turkananation/pqcrypto/issues)

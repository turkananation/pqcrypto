# ML-KEM Testing and Validation Policy

Last updated: 2026-06-03

This repository uses the checked-in files under `test/data` as its ML-KEM KAT corpus. The test runner must read only this repository-local corpus.

## Scope

The tests in this repository provide implementation evidence. They are not a CMVP/FIPS 140 validation claim. FIPS 203 is the algorithm standard for ML-KEM, and validation of cryptographic modules is a separate process — see [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).

Track the official source and errata before making release claims:

- FIPS 203 landing page: <https://csrc.nist.gov/pubs/fips/203/final>
- FIPS 203 PDF: <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf>

## Corpus

| File                                 | Vectors | SHA-256                                                            |
| ------------------------------------ | ------- | ------------------------------------------------------------------ |
| `test/data/MLKEM/kat_MLKEM_512.rsp`  | 1000    | `783106e35afb1ab9aba557630f5380f3ffa40b83abfbe75a03059b5986702017` |
| `test/data/MLKEM/kat_MLKEM_768.rsp`  | 1000    | `6ecab47c229a80b85afd8e9b1b76e604317b2505ac35382b0e288116e1ba860a` |
| `test/data/MLKEM/kat_MLKEM_1024.rsp` | 1000    | `ed23c551c53761649a2dd9573eda2f49f58285675d639fe8c0d585e21f37896c` |

If a corpus file changes, update the hash table in the same change and run the release-gate commands below.

## KAT Coverage

`test/kat_evaluator_test.dart` parses these fields when present:

- `z`, `d`, `msg`, `seed`
- `pk`, `sk`
- `ct`, `ss`
- `ct_n`, `ss_n`

It verifies:

- key generation from `d || z`
- encapsulation from `msg`
- valid decapsulation from `ct`
- invalid-ciphertext decapsulation from `ct_n`

## Unit Coverage

- `test/pack_test.dart` checks compression/decompression with modular distance over `q`, including wrap-boundary regressions.
- `test/poly_test.dart` checks that `Poly.barrettReduce` returns canonical residues in `[0, q - 1]`.
- `test/kem_validation_test.dart` checks public-key length/modulus validation, secret-key length/hash validation, and ciphertext length validation.
- `test/cbd_test.dart` checks CBD sampling distribution.
- `test/keccak_test.dart` checks the vendored FIPS 202 primitives
  (SHA3-224/256/384/512, SHAKE128/256) against published NIST known-answer
  values, including multi-block messages, parameter-table coverage, and the
  SHAKE stream-prefix property.
- `test/roundtrip_test.dart` checks end-to-end keygen → encaps → decaps shared-secret agreement (and implicit rejection of a tampered ciphertext) for all three parameter sets, with no `dart:io`, so it runs on the web compilers too.

## Platform coverage

The library is pure Dart with **no third-party dependencies** (FIPS 202 is vendored in `lib/src/common/keccak.dart`). Because the web compilers use a different integer backend from the VM (`dart2js`: 53-bit `int`, 32-bit bitwise ops), correctness is verified on **all three backends**:

- VM — the full suite, including the file-based KAT corpus.
- `dart2js` and `dart2wasm` (headless Chrome) — every test except the `@TestOn('vm')` KAT-file reader, which needs `dart:io`.

The file-based KAT test is the strongest conformance check but runs VM-only; `test/roundtrip_test.dart` and `test/keccak_test.dart` are the always-portable gate that catches platform-specific arithmetic defects on the web.

## Release Gate

Run these before merging or making correctness claims:

```bash
dart format lib test
dart analyze
dart test test/kat_evaluator_test.dart
dart test                                    # VM: full suite + KAT corpus
dart test -p chrome                          # web: dart2js
dart test -p chrome --compiler dart2wasm     # web: dart2wasm
```

## Claim Boundary

Acceptable claim:

> The implementation passes the checked-in ML-KEM KAT corpus for the keygen, encapsulation, decapsulation, and invalid decapsulation cases covered by that corpus.

Avoid broader claims such as "fully FIPS validated" unless supported by a separate validation record.

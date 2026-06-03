# ML-KEM Testing and Validation Policy

Last updated: 2026-06-03

This repository uses the checked-in files under `test/data` as its ML-KEM KAT corpus. The test runner must read only this repository-local corpus.

## Scope

The tests in this repository provide implementation evidence. They are not a CMVP/FIPS 140 validation claim. FIPS 203 is the algorithm standard for ML-KEM, and validation of cryptographic modules is a separate process.

Track the official source and errata before making release claims:

- FIPS 203 landing page: <https://csrc.nist.gov/pubs/fips/203/final>
- FIPS 203 PDF: <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf>

## Corpus

| File | Vectors | SHA-256 |
| --- | ---: | --- |
| `test/data/kat_MLKEM_512.rsp` | 1000 | `783106e35afb1ab9aba557630f5380f3ffa40b83abfbe75a03059b5986702017` |
| `test/data/kat_MLKEM_768.rsp` | 1000 | `6ecab47c229a80b85afd8e9b1b76e604317b2505ac35382b0e288116e1ba860a` |
| `test/data/kat_MLKEM_1024.rsp` | 1000 | `ed23c551c53761649a2dd9573eda2f49f58285675d639fe8c0d585e21f37896c` |

If a corpus file changes, update the hash table in the same change and run the release-gate commands below.

## KAT Coverage

`test/kat_evaluator.dart` parses these fields when present:

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

## Release Gate

Run these before merging or making correctness claims:

```bash
dart format lib test
dart analyze
dart test test/kat_evaluator.dart
dart test
```

## Claim Boundary

Acceptable claim:

> The implementation passes the checked-in ML-KEM KAT corpus for the keygen, encapsulation, decapsulation, and invalid decapsulation cases covered by that corpus.

Avoid broader claims such as "fully FIPS validated" unless supported by a separate validation record.

# FIPS Evidence and Claim Boundary

Last updated: 2026-06-13

This document records standards alignment evidence for the current repository.
It is not a CMVP/FIPS 140 validation certificate, and it must not be cited as
one. For the full explanation of why algorithm conformance is not module
validation, see [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).

## Summary

| Standard     | Scope in repo                                            | Current status                                                                                                                                   |
| ------------ | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| FIPS 203     | ML-KEM-512/768/1024                                      | Evidence-backed implementation alignment: checked-in KATs plus OpenSSL interop.                                                                  |
| FIPS 202     | SHA3-224/256/384/512 and SHAKE128/256                    | Partial vendored implementation with selected official byte examples; non-byte and full-corpus completion target 0.7.0/0.8.0.                    |
| SP 800-185   | cSHAKE, KMAC, TupleHash, ParallelHash                    | Not implemented yet. Controlled by the FIPS 202 / SP 800-185 release guide; targets 0.7.0 with disciplined 0.8.0 spillover.                      |
| FIPS 204     | ML-DSA-44/65/87                                          | Evidence-backed implementation alignment: byte-exact on the checked-in KAT corpus (raw/pure/hashed × det/hedged). Not CMVP/FIPS 140 validated.   |
| FIPS 205     | SLH-DSA                                                  | In development: M1 internal scaffolding exists; no signing API or ACVP corpus/claim yet. SHAKE targets v0.4.0, SHA-2 v0.5.0                      |
| FIPS 180-4   | SHA-256/384/512                                          | Vendored for HashML-DSA pre-hash; pinned by direct NIST vectors.                                                                                 |
| FIPS 140     | Cryptographic module validation                          | Not claimed. No CMVP validation record exists in this repo.                                                                                      |

## FIPS 203 - ML-KEM

Current ML-KEM evidence:

- `test/data/MLKEM/kat_MLKEM_512.rsp`, `kat_MLKEM_768.rsp`, and
  `kat_MLKEM_1024.rsp` are checked in (see `test/data/MLKEM/README.md`).
- `test/kat_evaluator_test.dart` verifies key generation, encapsulation,
  decapsulation, and invalid decapsulation fields where present.
- The latest local run used for this documentation pass completed 1000 vectors
  for each ML-KEM parameter set.
- `test/kem_validation_test.dart`, `test/pack_test.dart`, `test/poly_test.dart`,
  `test/keygen_derivation_test.dart`, `test/keccak_test.dart`, and
  `test/roundtrip_test.dart` cover key input-validation and regression risks.
- `tool/openssl_interop/` and `.github/workflows/interop.yml` provide the
  OpenSSL A-G interop proof for all three parameter sets.

See [MLKEM_TESTING.md](MLKEM_TESTING.md) and
[OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) for the detailed evidence.

Acceptable wording:

> `pqcrypto` provides a FIPS 203-aligned ML-KEM implementation that passes the
> checked-in KAT corpus and OpenSSL interoperability checks described in this
> repository.

Avoid wording such as:

- "FIPS validated"
- "CMVP validated"
- "FIPS 140 compliant module"
- "fully certified"

## FIPS 202 - SHA3/SHAKE

The package vendors its FIPS 202 primitives in `lib/src/common/keccak.dart` and
uses wrapper functions in `lib/src/common/shake.dart`.

Evidence:

- `test/keccak_test.dart` pins all four SHA3 functions plus SHAKE128/256,
  including direct Keccak-f[1600] constants/profiles, rate boundaries,
  multi-block absorb, and XOF chunk/prefix behavior.
- `test/data/FIPS202` records selected official NIST empty/1600-bit byte
  examples for all six functions, source URLs, retrieval date, and PDF hashes;
  `test/fips202_examples_test.dart` executes the normalized corpus.
- `pubspec.yaml` has no runtime dependencies; `lints` and `test` are
  dev-only dependencies.

Current limitations:

- Non-byte-aligned FIPS 202 examples are not covered yet.
- The checked-in NIST subset does not yet cover every published example.

Full FIPS 202 completion targets 0.7.0 and is planned in
[FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md). The
vendored implementation is not a FIPS-validated module. It is implementation
evidence for this package's correctness boundary. Any incomplete standards
surface spills into 0.8.0 instead of receiving broad release wording.

## SP 800-185 - SHA-3 Derived Functions

SP 800-185 support is **not implemented yet**. The target release is 0.7.0, with
0.8.0 reserved for any surface that cannot satisfy the complete evidence gate.
The planned surface includes:

- cSHAKE128 and cSHAKE256;
- KMAC128, KMAC256, KMACXOF128, and KMACXOF256;
- TupleHash128, TupleHash256, TupleHashXOF128, and TupleHashXOF256; and
- ParallelHash128, ParallelHash256, ParallelHashXOF128, and
  ParallelHashXOF256.

No README, changelog, package metadata, or release note may claim SP 800-185
support until the relevant issue gates and NIST example-vector tests in
[FIPS202_SP800185_RELEASE_GUIDE.md](FIPS202_SP800185_RELEASE_GUIDE.md) are
complete.

## FIPS 204 - ML-DSA

ML-DSA is present and exported (`MlDsa`, `DilithiumParams`,
`DilithiumParameter`) in `lib/src/algos/dilithium/`.

Current ML-DSA evidence:

- The repo-local corpus `test/data/MLDSA` (18 `.rsp` files, see
  `test/data/MLDSA/README.md`) is the official FIPS 204 KAT corpus.
- `test/mldsa_kat_test.dart` reproduces every vector **byte-for-byte** and
  verifies every signature, across the full matrix:

| Dimension       | Values                                                            |
| --------------- | ----------------------------------------------------------------- |
| Parameter set   | ML-DSA-44, ML-DSA-65, ML-DSA-87                                   |
| Signing mode    | deterministic (`rnd = 0`), hedged (`rnd` from vector)             |
| Flavour         | raw (Alg 6/7/8), pure (Alg 1/2/3 + context), hashed (Alg 1/4/5)   |
| Per file        | 100 vectors → 300 key generations + 1800 signatures total         |

- Algorithm-level regression tests: `dsa_zetas_test.dart` (Appendix B zetas +
  negacyclic NTT), `dsa_rounding_test.dart` (Power2Round/Decompose/MakeHint/
  UseHint boundaries), `dsa_pack_test.dart`/`dsa_symmetric_test.dart` (packing
  and sampling), `dsa_negative_test.dart` (malformed pk/sig/hint/context), and
  `dsa_api_test.dart` (context binding, hedged vs deterministic, domain
  separation). `sha2_test.dart` pins the HashML-DSA pre-hash (SHA-256/384/512).
- All ML-DSA tests run on the Dart VM; the algorithm tests also run on `dart2js`
  and `dart2wasm` (the file-based KAT runner is VM-only and auto-skips on web).

Acceptable wording:

> `pqcrypto` provides a FIPS 204-aligned ML-DSA implementation that passes the
> checked-in ML-DSA KAT corpus and regression suite described in this repository.

The same avoid-list as FIPS 203 applies ("FIPS validated", "CMVP validated",
"FIPS 140 compliant module", "certified"). The canonical implementation and
release record is [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md).

Residual hardening (does not affect KAT conformance): the norm check and
rejection loops are best-effort, not provably constant-time, in pure Dart; and
HashML-DSA exposes only the level-bound SHA-2 pre-hash. See
[SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## FIPS 205 - SLH-DSA (in development)

SLH-DSA is **not yet shipped or exported**. Internal M1 scaffolding now covers
all 12 Table 2 parameter records, Algorithms 1-4 utilities, the 32-byte address
layout, and the six SHAKE hash functions. Focused VM and dart2js tests pass,
including independent OpenSSL SHAKE vectors. This is component regression
evidence only, not SLH-DSA algorithm conformance.

The full A-Z compliance and release plan is in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md). Before
shipping, the evidence model must mirror ML-DSA: byte-exact against the
checked-in NIST ACVP SLH-DSA corpus for each claimed parameter set. The six
SHAKE parameter sets target v0.4.0 and the six SHA-2 sets v0.5.0.

Acceptable wording once a release is complete:

> `pqcrypto` provides a FIPS 205-aligned SLH-DSA implementation for the released
> parameter sets that passes the checked-in SLH-DSA KAT corpus and regression
> suite described in this repository.

The same avoid-list applies ("FIPS validated", "CMVP validated", "FIPS 140
compliant module", "certified"). Two SLH-DSA-specific caveats must be surfaced at
the API level, not buried here: the message-bound (BUFF) property does not hold
except for `*-128f` (FIPS 205 §11), and the `s` parameter sets are unsuitable for
web/interactive use. Both are detailed in the release guide and
[SECURITY_AUDIT.md](SECURITY_AUDIT.md) (SLH-01, SLH-04).

## RNG and Module Validation

The package uses `Random.secure()` for random bytes. That delegates to the
platform CSPRNG and is appropriate for a pure Dart package, but it is not a
repository-level SP 800-90A DRBG validation claim. A formal FIPS 140 module
would need its own validated entropy, DRBG, operational environment, and
security policy.

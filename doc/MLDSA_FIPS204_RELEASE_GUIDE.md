# ML-DSA FIPS 204 Compliance and Release Guide

Last updated: 2026-06-05

This is the engineering guide for completing, validating, and releasing
`pqcrypto`'s ML-DSA implementation. It is based on the official NIST FIPS 204
final publication, the NIST FIPS 204 potential-updates spreadsheet, the NIST
PQC FIPS FAQ, and the current repository state.

This document is not a CMVP/FIPS 140 validation certificate. It is the release
plan for algorithm conformance, security hardening, test evidence, and public
claim discipline.

## Source Corpus

| Source                          | URL                                                                                    | How this guide uses it                                                |
| ------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| FIPS 204 final publication page | <https://csrc.nist.gov/pubs/fips/204/final>                                            | Publication status, date, NIST planning notes, official document set. |
| FIPS 204 final PDF              | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>                             | Normative ML-DSA algorithms, parameters, encodings, and appendices.   |
| FIPS 204 DOI                    | <https://doi.org/10.6028/NIST.FIPS.204>                                                | Stable citation target.                                               |
| FIPS 204 potential updates      | <https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx> | Known errata/potential corrections to track during implementation.    |
| NIST PQC FIPS FAQ               | <https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs#Rdc7>                   | Seed-format and internal-interface validation context.                |
| Current pqcrypto ML-DSA code    | `lib/src/algos/dilithium/`                                                             | Baseline implementation and gap analysis.                             |
| Current pqcrypto ML-DSA tests   | `test/dsa_*_test.dart`, `test/mldsa_*_test.dart`                                       | Current failures and future release gates.                            |

## Executive Decision

ML-DSA cannot be released as a supported signature surface until all of these
conditions are true:

1. The public API implements FIPS 204 external functions with hedged signing as
   the default.
2. Internal deterministic functions match the FIPS 204 algorithms and are
   accessible only for tests/fixtures, not as the normal application API.
3. ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets match FIPS 204 Table 1
   and Table 2.
4. Key, signature, and message formatting follow FIPS 204 Sections 5, 6, and 7.
5. Context strings are supported and limited to 255 bytes.
6. Verification rejects invalid public-key and signature lengths before parsing.
7. Packing and unpacking preserve signed coefficient domains instead of silently
   converting centered values into field residues where FIPS requires signed
   ranges.
8. Rejection sampling and XOF use are correct for unbounded operation or use
   bounds no lower than FIPS 204 Appendix C.
9. The implementation passes repo-local ML-DSA KATs for all three parameter
   sets under `dart test`.
10. Negative tests cover malformed public keys, signatures, hints, contexts,
    and parameter mismatches.
11. Sensitive intermediate values are zeroized or deliberately justified where
    Dart semantics prevent a stronger guarantee.
12. Side-channel-sensitive checks avoid secret-dependent early exits where the
    result could reveal useful information.
13. VM, AOT, dart2js, and dart2wasm validation is green or limitations are
    documented before publication.
14. README, package metadata, docs, and changelog use evidence-scoped wording.

## Claim Boundary

Use precise language:

- Acceptable after this guide is completed: "`pqcrypto` provides a FIPS
  204-aligned ML-DSA implementation that passes the checked-in ML-DSA KAT corpus
  and regression suite described in this repository."
- Not acceptable without a validation certificate: "FIPS validated",
  "CMVP validated", "FIPS 140 compliant module", or "certified".

FIPS 204 algorithm conformance and FIPS 140 module validation are different
claims. This package can provide implementation evidence. It cannot claim FIPS
140 validation unless a cryptographic module is separately validated through
CMVP with an approved operational environment, entropy source, DRBG story,
security policy, and certificate.

## FIPS 204 Standard Shape

FIPS 204 defines two related signature modes:

| Mode       | FIPS functions                                  | Release expectation                                                                   |
| ---------- | ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| ML-DSA     | `ML-DSA.KeyGen`, `ML-DSA.Sign`, `ML-DSA.Verify` | Required for supported release.                                                       |
| HashML-DSA | `HashML-DSA.Sign`, `HashML-DSA.Verify`          | Required before claiming broad FIPS 204 support; may be explicitly deferred at first. |

FIPS 204 separates external and internal functions:

| Layer     | Functions       | Rule for this repo                                                                 |
| --------- | --------------- | ---------------------------------------------------------------------------------- |
| External  | Algorithms 1-5  | Public API surface. Handles randomness, context formatting, and input checks.      |
| Internal  | Algorithms 6-8  | Deterministic implementation core. Expose only through internal/test-only helpers. |
| Auxiliary | Algorithms 9-49 | Shared primitives. Must have focused unit and property tests.                      |

The distinction matters. External functions are what applications should call.
Internal functions are necessary for CAVP-style KATs and deterministic test
fixtures, but they should not become the default application API.

## Parameter Sets

Every value below must be represented in code and covered by a size/parameter
test.

| Parameter        | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | Current repo note                                           |
| ---------------- | --------: | --------: | --------: | ----------------------------------------------------------- |
| `q`              | 8380417   | 8380417   | 8380417   | Present in `params.dart`.                                   |
| `zeta`           | 1753      | 1753      | 1753      | NTT uses Appendix B zetas; keep index semantics documented. |
| `d`              | 13        | 13        | 13        | Present in `params.dart`.                                   |
| `tau`            | 39        | 49        | 60        | Present and fixed in `DilithiumParams`.                     |
| `lambda`         | 128       | 192       | 256       | Model through `cTildeSize = lambda / 4`.                    |
| `gamma1`         | 2^17      | 2^19      | 2^19      | Present in `DilithiumParams`.                               |
| `gamma2`         | (q-1)/88  | (q-1)/32  | (q-1)/32  | Present as 95232 and 261888.                                |
| `(k, l)`         | (4, 4)    | (6, 5)    | (8, 7)    | Present in `DilithiumParams`.                               |
| `eta`            | 2         | 4         | 2         | Present in `DilithiumParams`.                               |
| `beta = tau*eta` | 78        | 196       | 120       | Present in `DilithiumParams`.                               |
| `omega`          | 80        | 55        | 75        | Present in `DilithiumParams`.                               |
| Private key      | 2560      | 4032      | 4896      | Covered by `dsa_test.dart`.                                 |
| Public key       | 1312      | 1952      | 2592      | Covered by `dsa_test.dart`.                                 |
| Signature        | 2420      | 3309      | 4627      | Covered by `dsa_sign_test.dart`.                            |

Code cleanup:

- Replace or remove `crhBytes = 48` in `params.dart`; FIPS 204 uses 64-byte
  `mu`, 64-byte `rhoPrime`, 64-byte `tr`, and per-parameter `cTildeSize`.
- Add computed getters for `publicKeyBytes`, `secretKeyBytes`,
  `signatureBytes`, `w1Bytes`, `zBytes`, and `challengeBytes`.
- Add a single source of truth for parameter-derived sizes and use it in tests,
  packing, public input validation, and docs.

## Current Repository Gap Analysis

| Area                    | Current state                                                                | Required state                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Public key generation   | `MlDsa.generateKeyPair(params, seed)` requires a caller-supplied seed.       | External `generateKeyPair(params)` uses a fresh 32-byte seed from secure randomness by default.      |
| Internal key generation | Current seeded API is useful for tests.                                      | Keep as internal/test API named clearly as `keyGenInternal` or equivalent.                           |
| Signing randomness      | `sign` defaults to all-zero `rnd`, making deterministic signing the default. | Hedged signing is default; deterministic signing is explicit and discouraged for side-channel risks. |
| Context string          | Public API does not expose FIPS 204 `ctx`.                                   | `ctx` is supported, defaults to empty, and rejects length greater than 255 bytes.                    |
| Message formatting      | `mu` is computed from direct `tr` plus message bytes.                        | External ML-DSA formats domain byte, context length, context, and message before internal signing.   |
| HashML-DSA              | Not implemented.                                                             | Add or explicitly defer; broad FIPS 204 support requires HashML-DSA APIs and tests.                  |
| Length checks           | `unpackPK` throws on bad pk; `unpackSig` may sublist before explicit checks. | Verify returns `false` for wrong pk/sig lengths before decoding.                                     |
| Packing signed values   | `bitUnpack` and `bitUnpackZ` normalize negatives into `[0, q-1]`.            | Preserve signed coefficient ranges where FIPS requires centered values.                              |
| Current test failures   | Packing and `ExpandS` tests fail; KAT debug path fails.                      | Full VM suite green before release.                                                                  |
| `ExpandS`/sampling      | Fixed-length SHAKE buffers can exhaust.                                      | Use incremental XOF or Appendix C compliant bounds and uniform failure semantics.                    |
| KAT fixture policy      | `mldsa_debug_test.dart` and `mldsa_kat_test.dart` use a Windows KAT root.    | Use checked-in `test/data/kat_MLDSA_*` corpus or a documented fixture download tool.                 |
| Side-channel checks     | `_checkNorm` exits on first failing coefficient.                             | Accumulate flags over all coefficients for secret-derived checks.                                    |
| Zeroization             | No shared zeroization helper.                                                | Zeroize secret seeds, vectors, masks, and failed signing attempts where Dart permits.                |
| NTT zetas               | `zetas[0]` is `1`, while FIPS Appendix B lists `0` then indexes 1..255.      | Either set `zetas[0] = 0` or document that index 0 is unused; add Appendix B equality test.          |
| CAVP readiness          | No CAVP-style deterministic harness.                                         | Internal algorithms are testable from deterministic seeds and `rnd` inputs.                          |

## NIST Potential Updates to Track

The FIPS 204 potential-updates spreadsheet says these are not official changes
and do not introduce new technical requirements, but they remove ambiguity and
should shape implementation reviews:

| Topic               | Engineering interpretation for this repo                                                      |
| ------------------- | --------------------------------------------------------------------------------------------- |
| NTT explanation     | Treat `zeta_i` as the root value, not as a second evaluation of the polynomial.               |
| `M` vs `M'` text    | Internal signing/verifying consumes formatted `M'`; keep external formatting explicit.        |
| Challenge input     | Hash `mu` followed by `w1Encode(w1)` for the commitment hash.                                 |
| `NULL` notation     | Model randomness failure as a single error path with no partial output.                       |
| `Power2Round` typo  | Use `Power2Round`, not `PowerTwoRound`, in code/docs.                                         |
| `w1Encode` use      | It is used by internal signing and verifying, not by external signing directly.               |
| Montgomery appendix | If Montgomery reduction is adopted, match the reference behavior and signed 32-bit details.   |
| `UseHint` bound     | The real upper bound is one less than `(q-1)/(2*gamma2)`; tests should pin boundary behavior. |

## Implementation Architecture

Target package structure:

```text
lib/src/algos/dilithium/
  params.dart       # parameter sets, sizes, security categories
  dsa.dart          # external ML-DSA and HashML-DSA APIs
  internal.dart     # Algorithms 6-8, not exported publicly
  packing.dart      # Algorithms 9-28
  symmetric.dart    # Algorithms 29-34 and SHAKE wrappers
  rounding.dart     # Algorithms 35-40
  ntt.dart          # Algorithms 41-48 and Appendix B zetas
  poly.dart         # Rq/Tq storage, reductions, vector operations
```

Keep `lib/pqcrypto.dart` exports minimal:

- Export supported external API types.
- Do not export internal seeded/keygen/signing primitives as normal user APIs.
- If internal APIs remain needed for tests, keep them under `src/` and import
  them from tests directly.

## Public API Target

The final release API should make safe use easy and unsafe use explicit:

```dart
final params = DilithiumParams.mlDsa65;
final (pk, sk) = MlDsa.generateKeyPair(params);
final sig = MlDsa.sign(sk, message, params, context: contextBytes);
final ok = MlDsa.verify(pk, message, sig, params, context: contextBytes);
```

Required API behavior:

| Function                | Requirement                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `generateKeyPair`       | External key generation. Creates a fresh 32-byte seed using secure randomness.                          |
| `generateKeyPairSeeded` | Internal/test utility. Takes exactly 32 bytes and maps to FIPS `KeyGen_internal`.                       |
| `sign`                  | Hedged signing by default. Generates `rnd` inside the function.                                         |
| `signDeterministic`     | Optional explicit API if retained. Clearly warns about side-channel/fault risks.                        |
| `signWithRandomness`    | Test/CAVP utility accepting `rnd` for deterministic vectors.                                            |
| `verify`                | Returns `false` for bad pk/sig/context lengths and malformed hints. Does not throw for untrusted input. |
| `hashSign`              | HashML-DSA API if implemented. Includes hash OID domain separation.                                     |
| `hashVerify`            | HashML-DSA verification if implemented.                                                                 |

Byte-string scope:

- FIPS 204 permits bit-string messages. Dart APIs should support byte-string
  messages first and document that non-byte-aligned messages are unsupported
  unless a bit-string wrapper is added.
- The external domain separator still uses `BytesToBits` semantics internally;
  implementation can operate on byte arrays as long as it matches the same bit
  ordering for byte-aligned inputs.

## Algorithm-by-Algorithm Work Plan

| FIPS item        | Implementation work                                                                                     | Tests required                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Algorithm 1      | External keygen: generate fresh 32-byte seed; handle RNG failure with one error path.                   | Key sizes, deterministic seeded equivalence, RNG path smoke tests.                                 |
| Algorithm 2      | External ML-DSA sign: `ctx` length check, hedged `rnd`, `M'` formatting.                                | Context empty/non-empty, context too long, hedged signatures verify.                               |
| Algorithm 3      | External verify: `ctx` length check and `M'` formatting.                                                | Wrong context fails, context too long returns false/error as specified by API.                     |
| Algorithms 4-5   | HashML-DSA sign/verify with SHA-256, SHA-512, SHAKE128 OID encodings or explicit deferral.              | HashML KATs or internal round trips; mismatch hash/OID fails.                                      |
| Algorithm 6      | Internal keygen: hash seed plus single-byte `k` and `l`, then ExpandA, ExpandS, Power2Round, encodings. | ML-DSA KAT keygen for 44/65/87.                                                                    |
| Algorithm 7      | Internal sign: `mu`, `rhoPrime`, rejection loop, challenge, hints, output.                              | ML-DSA KAT sign for 44/65/87 with fixed `rnd`; rejection-path regressions.                         |
| Algorithm 8      | Internal verify: decode, length checks, hint validation, recompute challenge.                           | KAT verify, malformed signature corpus, all wrong lengths return false.                            |
| Algorithms 9-13  | Little-endian integer/bit/byte conversions.                                                             | Exhaustive small values; cross-check pack helpers.                                                 |
| Algorithms 14-15 | Coeff-from-byte helpers.                                                                                | Boundary values around `q`, `eta=2`, `eta=4`, rejection markers.                                   |
| Algorithms 16-19 | `SimpleBitPack`, `BitPack`, and unpacking preserving intended signed ranges.                            | Current failing pack tests plus boundary coefficients for every FIPS range.                        |
| Algorithms 20-21 | Hint encoding/decoding with cumulative indexes and strict malformed checks.                             | Duplicate, decreasing, out-of-range, non-zero padding, overweight hints.                           |
| Algorithms 22-28 | pk/sk/sig/w1 encodings.                                                                                 | Exact size and KAT byte equality tests.                                                            |
| Algorithms 29-34 | SampleInBall, RejNTTPoly, RejBoundedPoly, ExpandA, ExpandS, ExpandMask using correct XOFs and seeds.    | KAT intermediate vectors where available; deterministic fixture tests; no fixed-buffer exhaustion. |
| Algorithms 35-40 | Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint.                                           | Boundary tests at 0, q-1, gamma2 edges, UseHint errata upper bound.                                |
| Algorithms 41-48 | NTT, inverse NTT, BitRev8, NTT-domain vector/matrix arithmetic.                                         | Appendix B zeta test, NTT round trip, matrix-vector known fixture.                                 |
| Algorithm 49     | Optional Montgomery reduction.                                                                          | Only if adopted; otherwise document pure modular arithmetic.                                       |

## Packing and Signed Coefficient Rules

Packing is the first correctness blocker. The release implementation must make
these domains explicit:

| Object | FIPS domain before encoding                                 | Current risk                                             | Required fix                                                    |
| ------ | ----------------------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------- |
| `s1`   | coefficients in `[-eta, eta]`                               | `bitUnpack` maps negative values into field residues.    | Preserve signed `int` values or provide signed-view conversion. |
| `s2`   | coefficients in `[-eta, eta]`                               | Same as `s1`.                                            | Same as `s1`.                                                   |
| `t0`   | coefficients in `[-2^(d-1)+1, 2^(d-1)]`                     | Current code stores negative values as residues.         | Keep representation compatible with norm and pack semantics.    |
| `z`    | coefficients in `[-gamma1+1, gamma1]` before signature pack | Current signing reduces `z` to `[0, q-1]` before pack.   | Do not reduce `z` into residues before `BitPack`.               |
| `h`    | binary vector with at most `omega` non-zero entries         | Decoder mostly checks ordering/padding.                  | Add negative tests for every malformed hint case.               |
| `w1`   | coefficients in `[0, (q-1)/(2*gamma2)-1]`                   | Table alignment only; implementation needs boundary KAT. | Add `w1Encode` tests and use shared size getters.               |

Implementation rule: choose one internal representation policy and make it
consistent.

Preferred policy:

- Store ordinary polynomials in canonical `[0, q-1]` only when doing modular
  arithmetic.
- Store secret/noise/response vectors in centered signed form at API boundaries
  where FIPS packing, norm checks, and tests require signed ranges.
- Provide explicit conversion helpers such as `toCenteredQ`, `toCanonicalQ`,
  `centeredAbsAtLeast`, and `packSignedRange`.

## Sampling and XOF Rules

FIPS 204 uses SHAKE128 for `G` and SHAKE256 for `H`. Sampling functions consume
as much output as needed unless the implementation chooses explicit limits.

| Function         | XOF      | Current repo risk                                            | Required release behavior                                                             |
| ---------------- | -------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `SampleInBall`   | SHAKE256 | Fixed 840 bytes is probably enough but not principled.       | Use incremental squeeze or Appendix C limit at least 221 bytes; uniform failure path. |
| `RejNTTPoly`     | SHAKE128 | Fixed 840 bytes matches Appendix C byte floor less directly. | Incremental squeeze or explicit limit at least 894 bytes.                             |
| `RejBoundedPoly` | SHAKE256 | Current fixed buffer fails tests.                            | Incremental squeeze or explicit limit at least 481 bytes.                             |
| `ExpandA`        | SHAKE128 | Seed order appears correct.                                  | Add KAT/intermediate test for seed order: `rho`, then `s`, then `r`.                  |
| `ExpandS`        | SHAKE256 | Current failure in `dsa_symmetric_test.dart`.                | Fix using correct rejection loop and seed formatting.                                 |
| `ExpandMask`     | SHAKE256 | Direct bit unpack is correct direction.                      | Add KAT/intermediate tests for nonce ordering and gamma1 levels.                      |

If a loop bound is implemented:

- Never use a lower bound than Appendix C.
- On exhaustion, destroy intermediate results.
- Return a constant error signal and no partial output.
- Test the failure path with an injected XOF or artificial bound.

## Context and Domain Separation

Public `sign` and `verify` must format messages through FIPS external
functions:

```text
ML-DSA M' = 0x00 || len(ctx) || ctx || M
```

HashML-DSA uses a different domain separator:

```text
HashML-DSA M' = 0x01 || len(ctx) || ctx || DER(OID(PH)) || PH(M)
```

Rules:

- Context length is a single byte and must be at most 255.
- Empty context is the default.
- Wrong context must fail verification.
- HashML-DSA signature identifiers must indicate pre-hash mode and the hash/XOF
  used.
- Prefer separate APIs over flags that can be confused.

## Randomness Requirements

Key generation:

- External keygen must generate a fresh 32-byte `xi`.
- For ML-DSA-65 and ML-DSA-87, FIPS 204 requires an approved RBG security
  strength of at least 192 and 256 bits respectively in validated modules.
- For ML-DSA-44, at least 128 bits is mandatory; 192 bits is recommended to
  preserve category 2 strength.
- In this pure Dart package, `Random.secure()` can be an implementation source
  of cryptographic randomness, but it is not a repo-level SP 800-90 validation
  claim.

Signing:

- Hedged signing is the default and generates fresh 32-byte `rnd`.
- Deterministic signing sets `rnd` to 32 zero bytes, but must be explicit.
- Documentation must warn that deterministic signing is harder to protect
  against side-channel and fault attacks.

Testing:

- CAVP/KAT tests need deterministic access to `xi` and `rnd`.
- Production APIs should not require users to supply `rnd`.

## Verification and Malformed Input Rules

Verification is exposed to attacker-controlled data. It must be defensive:

| Input      | Required behavior                                                                 |
| ---------- | --------------------------------------------------------------------------------- |
| Public key | If length differs from Table 2, return false before `sublist` or decode.          |
| Signature  | If length differs from Table 2, return false before `sublist` or decode.          |
| Context    | If longer than 255 bytes, return false or throw according to public API contract. |
| Hint       | Reject decreasing indexes, duplicates, indexes past omega, and non-zero padding.  |
| `z`        | Reject when norm bound fails.                                                     |
| Parameter  | Do not verify an ML-DSA-44 signature under ML-DSA-65/87 parameters.               |

Recommended API contract:

- `verify` returns `false` for all untrusted malformed inputs.
- `sign` and `generateKeyPair` throw typed argument errors for caller misuse.
- Internal test helpers may throw, but public verification should not.

## Side-Channel and Fault-Resistance Work

Minimum release hardening:

1. Replace `_checkNorm` with a flag-accumulating implementation over all 256
   coefficients.
2. Avoid secret-dependent early returns in rejection checks where practical;
   compute all relevant flags before deciding to reject.
3. Ensure failed signing attempts do not leave reusable `y`, `z`, `r0`, `ct0`,
   `h`, `c`, `rhoPrime`, or secret-vector copies live longer than necessary.
4. Add `secureZero(Uint8List)`, `secureZeroInt32(Int32List)`, and vector helpers.
5. Use `try/finally` around keygen/signing intermediate buffers.
6. Keep `print()` and debug traces out of `lib/`.
7. Treat deterministic signing as a test or constrained-environment mode, not
   the default.
8. Document Dart limitations: garbage collection and integer immutability mean
   zeroization is best-effort for buffers, not a hard memory-erasure proof.

Fault considerations:

- Hedged signing reduces deterministic-fault exposure but is not a complete
  fault-attack countermeasure.
- Add regression tests ensuring `rnd` changes signatures for the same
  key/message/context while all signatures still verify.
- Consider duplicate verification of generated signatures in high-assurance
  mode before returning them.

## KAT and Test Corpus Plan

ML-DSA release requires a repo-local corpus. Machine-local paths are forbidden.

Target layout:

```text
test/data/
  kat_MLDSA_44_det_raw.rsp
  kat_MLDSA_65_det_raw.rsp
  kat_MLDSA_87_det_raw.rsp
```

Required runners:

| Runner                               | Purpose                                                             |
| ------------------------------------ | ------------------------------------------------------------------- |
| `test/mldsa_kat_test.dart`           | Discovered KAT runner for keygen, sign, and verify across 44/65/87. |
| `test/dsa_pack_test.dart`            | Packing/unpacking boundaries and current regression failures.       |
| `test/dsa_symmetric_test.dart`       | ExpandA, ExpandS, ExpandMask, SampleInBall, rejection loops.        |
| `test/dsa_sign_test.dart`            | Public API round trips, bad messages, bad signatures, contexts.     |
| `test/dsa_negative_test.dart`        | Malformed pk/sig/hint/context/parameter tests.                      |
| `test/dsa_fips204_vectors_test.dart` | Focused intermediate fixtures from FIPS/NIST examples if available. |

KAT runner requirements:

- Must run under plain `dart test`.
- Must not depend on `C:\Dev\...`, `$HOME`, or any external directory.
- Must print no production secrets.
- Must verify exact byte equality for public keys, secret keys, signatures, and
  verification result.
- Must include deterministic signing vectors by passing fixed `rnd`.

## Platform Validation Matrix

Before upgrading ML-DSA from experimental:

| Platform gate   | Command                                                   | Required result                                       |
| --------------- | --------------------------------------------------------- | ----------------------------------------------------- |
| Static analysis | `dart analyze`                                            | Exit 0; no production warnings.                       |
| Full VM suite   | `dart test`                                               | Passes, including ML-DSA KATs.                        |
| Focused ML-DSA  | `dart test test/dsa_*_test.dart test/mldsa_kat_test.dart` | Passes locally and in CI.                             |
| Web JS          | `dart test -p chrome`                                     | Passes or ML-DSA exclusions are explicitly justified. |
| Web Wasm        | `dart test -p chrome --compiler dart2wasm`                | Passes or exclusions are explicitly justified.        |
| Format/lint     | `dart format --output=none --set-exit-if-changed .`       | Passes.                                               |
| Markdown lint   | `npx -y markdownlint-cli2 "**/*.md"`                      | Passes.                                               |

Web-specific risk:

- Dart integers on JavaScript compile to JS numbers for many operations.
- `q*q` is below `2^53`, so simple products are currently safe, but any future
  widened multiplication or Montgomery emulation must be rechecked.
- Add web tests for NTT round trips, signing, verification, and KAT sample
  vectors.

## Release Milestones

### M0 - Freeze the Standard Map

- Add this guide to `doc/INDEX.md`, `FIPS_COMPLIANCE.md`, `SECURITY_AUDIT.md`,
  `ROADMAP.md`, and `PROGRESS_TRACKER.md`.
- Add source links to FIPS 204 final PDF, errata, and FAQ.
- Add issue IDs for every gap in this guide.

Exit gate:

- Markdown lint is green.
- Docs clearly say ML-DSA remains experimental until this guide is complete.

### M1 - Fix Deterministic Core Correctness

- Fix `BitPack`/`BitUnpack` signed-domain handling.
- Fix `z` packing by avoiding field-residue normalization before signature
  encoding.
- Fix `ExpandS` fixed-buffer failure.
- Add boundary tests for Algorithms 9-21 and 35-40.
- Add zetas Appendix B test.

Exit gate:

- `dart test test/dsa_pack_test.dart test/dsa_symmetric_test.dart`
- `dart test test/dsa_math_test.dart test/dsa_ntt_test.dart`

### M2 - Implement FIPS External APIs

- Add external keygen with internal random seed generation.
- Add context support to sign/verify.
- Make hedged signing the default.
- Add explicit deterministic/test signing path.
- Add public input length checks and false-return behavior for verification.

Exit gate:

- Round-trip tests for empty context, non-empty context, wrong context, hedged
  signatures, deterministic signatures, and bad lengths.

### M3 - Vendor ML-DSA KAT Corpus

- Add repo-local ML-DSA KAT files.
- Replace hardcoded Windows KAT roots.
- Make `mldsa_kat_test.dart` discovered and deterministic.
- Remove or quarantine debug-only tests that fail by design.

Exit gate:

- `dart test test/mldsa_kat_test.dart`
- `dart test` no longer fails from missing local KAT paths.

### M4 - Complete HashML-DSA or Scope It Out

Decision:

- If claiming broad FIPS 204 support, implement HashML-DSA Sign/Verify.
- If releasing pure ML-DSA first, state "HashML-DSA not yet implemented" in
  README, FIPS compliance docs, and changelog.

HashML-DSA implementation must include:

- domain separator `0x01`;
- context length byte;
- context bytes;
- DER-encoded hash/XOF OID;
- approved hash/XOF output length checks for the claimed security level.

Exit gate:

- HashML tests pass or public docs explicitly scope the release to pure ML-DSA.

### M5 - Security Hardening

- Add best-effort zeroization helpers and apply in keygen/signing.
- Replace secret-derived early exits with accumulated flags.
- Add malformed input and fault-path tests.
- Review exception paths for partial-output leaks.
- Ensure signing-loop exhaustion, if bounded, has one constant failure mode.

Exit gate:

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) open ML-DSA findings are closed or
  explicitly deferred with severity and rationale.

### M6 - Cross-Platform and Release Evidence

- Run VM, web JS, web Wasm, and package dry-run.
- Update README status table.
- Update changelog with exact evidence.
- Update package metadata only after evidence is green.

Exit gate:

- `dart analyze`
- `dart test`
- `dart test -p chrome`
- `dart test -p chrome --compiler dart2wasm`
- `dart pub publish --dry-run`
- `npx -y markdownlint-cli2 "**/*.md"`

## Documentation Release Rules

Before ML-DSA release:

- [README.md](../README.md) must link this guide and state the exact ML-DSA
  support boundary.
- [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md) must distinguish ML-DSA algorithm
  evidence from FIPS 140 validation.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) must close or defer every ML-DSA high
  finding.
- [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) must show each ML-DSA release gate.
- [ROADMAP.md](ROADMAP.md) must define the release version and criteria.
- [CHANGELOG.md](../CHANGELOG.md) must list KAT corpus, API behavior, and any
  limitations such as HashML-DSA deferral.

## Definition of Done

ML-DSA is releasable when this exact checklist is complete:

- [ ] `DilithiumParams` values and sizes are generated from one source of truth.
- [ ] External keygen uses fresh randomness by default.
- [ ] Internal seeded keygen remains test-only.
- [ ] Hedged signing is default.
- [ ] Deterministic signing is explicit.
- [ ] `context` is implemented and length-limited.
- [ ] `M'` formatting is correct for ML-DSA.
- [ ] HashML-DSA is implemented or explicitly out of scope.
- [ ] Public verify has exact length checks for pk and signature.
- [ ] `BitPack`/`BitUnpack` preserve signed domains.
- [ ] `sigEncode` packs `z` from the centered range, not canonical residues.
- [ ] `HintBitUnpack` malformed cases are fully tested.
- [ ] `ExpandS`, `RejBoundedPoly`, `RejNTTPoly`, and `SampleInBall` cannot fail
      due to an undersized fixed buffer in normal operation.
- [ ] Appendix C loop-bound behavior is implemented or not bounded.
- [ ] NTT zetas match Appendix B and have a regression test.
- [ ] `Power2Round`, `Decompose`, `UseHint`, and edge cases are tested.
- [ ] `_checkNorm` and rejection checks are side-channel reviewed.
- [ ] Secret intermediate buffers are zeroized where possible.
- [ ] Repo-local ML-DSA KAT corpus exists.
- [ ] `dart test` passes.
- [ ] Web JS and Wasm gates pass or limitations are explicit.
- [ ] Markdown lint passes.
- [ ] Docs and changelog are evidence-scoped.

Until then, ML-DSA remains experimental.

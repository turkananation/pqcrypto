# FIPS 202 and SP 800-185 Compliance and Release Guide

Last updated: 2026-06-06

This is the engineering guide for completing, validating, and releasing
`pqcrypto`'s SHA-3 / SHAKE and SHA-3-derived function surface:

- FIPS 202: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, and
  the Keccak-p[1600, 24] permutation used by those functions.
- NIST SP 800-185: cSHAKE, KMAC, KMACXOF, TupleHash, TupleHashXOF,
  ParallelHash, and ParallelHashXOF.

This document is deliberately more comprehensive than the current implementation
state. The package already vendors part of FIPS 202 for ML-KEM, ML-DSA, and
future SLH-DSA work, but it has not yet been treated as a standalone
standards-complete release surface. This guide is the A-to-Z plan for doing
that without overclaiming.

This document is **not** a CMVP/FIPS 140 validation certificate. It is a release
plan for algorithm conformance, corpus provenance, security hardening, API
design, test evidence, issue tracking, and public claim discipline. The exact
acceptable wording lives in [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).

Release train: **0.7.0** is the target for the first complete FIPS 202 /
SP 800-185 release scope. **0.8.0** is reserved for spillover if the full
standards surface or its validation evidence cannot close in 0.7.0 without
weakening the claim boundary.

## Completion Status (2026-06-06)

**Not complete.** The repo contains a strong partial FIPS 202 foundation, but it
does not yet implement or validate the full FIPS 202 family or any SP 800-185
functions.

Current implementation:

- `lib/src/common/keccak.dart` implements Keccak-f[1600] using portable
  32-bit lane halves.
- The exposed one-shot functions are `sha3256`, `sha3512`, `shake128`, and
  `shake256`.
- Incremental SHAKE output is available through `shake128Xof` and
  `shake256Xof`.
- `test/keccak_test.dart` pins SHA3-256, SHA3-512, SHAKE128, and SHAKE256
  against known-answer values, including multi-block input and XOF prefix
  stability.
- The package has zero runtime dependencies.

Missing before any complete FIPS 202 claim:

- SHA3-224 and SHA3-384 one-shot functions.
- A public or test-only bit-string representation for non-byte-aligned NIST
  examples.
- A checked-in FIPS 202 example corpus with provenance.
- Coverage of NIST examples for 0-bit, 5-bit, 30-bit, 1600-bit, 1605-bit, and
  1630-bit messages for all six FIPS 202 functions.
- SHAKE output examples beyond the current short empty-message checks.
- Explicit conformance gates for Keccak-p[1600, 24] constants, rotation
  offsets, padding suffixes, rates, capacities, and HMAC block sizes.

Missing before any SP 800-185 claim:

- `left_encode`, `right_encode`, `encode_string`, `bytepad`, and substring
  helpers.
- cSHAKE128 and cSHAKE256.
- KMAC128, KMAC256, KMACXOF128, and KMACXOF256.
- TupleHash128, TupleHash256, TupleHashXOF128, and TupleHashXOF256.
- ParallelHash128, ParallelHash256, ParallelHashXOF128, and
  ParallelHashXOF256.
- A checked-in SP 800-185 example corpus with provenance.
- API-level validation for length limits, block-size limits, customization
  strings, key length guidance, and unsupported bit-level inputs.
- VM, dart2js, and dart2wasm tests for the implemented byte-oriented surface.

## Release Strategy (Conclave-Reviewed)

Before this guide was written, the release strategy was stress-tested through
the Sovereign Conclave skill. Six blind seats (Feynman, Lee Kuan Yew,
von Neumann, Oppenheimer, Aurelius, and Addington) converged on the same
recommendation: use a standards-first, evidence-gated release program rather
than a narrow patch that only fills SHA3-224/SHA3-384. This guide captures the
durable decision and its implementation consequences; local Conclave scratch
artifacts remain outside the published package and repository history.

Controlling decisions:

1. **Target the current final standards first.** FIPS 202 (August 2015) and
   SP 800-185 (December 2016) remain the current final publications. NIST has
   announced future update/revision work, but those future drafts are not the
   implementation baseline until NIST finalizes replacements.
2. **Split implementation into evidence-backed stages.** Complete FIPS 202
   first, then SP 800-185 encodings and cSHAKE, then KMAC, TupleHash, and
   ParallelHash.
3. **Use 0.7.0 as the release target and 0.8.0 as disciplined spillover.**
   Incomplete surfaces move forward as tracked scope; they do not become
   undocumented partial claims.
4. **Do not imply full support from partial primitives.** Current SHA3-256,
   SHA3-512, SHAKE128, and SHAKE256 support is valuable, but it is not full
   FIPS 202 and not SP 800-185.
5. **Use official NIST example values as the authoritative corpus source.**
   Every checked-in vector file needs provenance, source URL, retrieval date,
   and hash.
6. **Separate byte-oriented public APIs from bit-oriented conformance tests.**
   SP 800-185 permits limited implementations that reject unsupported input
   shapes. A first supported release may expose byte-oriented APIs only, but
   non-byte NIST examples still need a test harness or documented deferral
   before broad conformance wording.
7. **Keep zero runtime dependencies.** The package should continue to vendor
   the required Keccak/SP 800-185 logic in pure Dart.
8. **No CMVP/FIPS 140 language.** The output of this program is algorithm and
   vector evidence, not a validated cryptographic module certificate.

## Source Corpus

| Source                                  | URL / path                                                                                                                             | How this guide uses it                                                                                     |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| FIPS 202 final publication page         | <https://csrc.nist.gov/pubs/fips/202/final>                                                                                            | Publication status, date, planning note, known Appendix B typo, official document links.                   |
| FIPS 202 final PDF                      | <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf>                                                                             | Normative Keccak-p, sponge, SHA3, SHAKE, conformance, security, and appendices.                            |
| FIPS 202 DOI                            | <https://doi.org/10.6028/NIST.FIPS.202>                                                                                                | Stable citation target.                                                                                    |
| SP 800-185 final publication page       | <https://csrc.nist.gov/pubs/sp/800/185/final>                                                                                          | Publication status, date, planning note, official document links.                                          |
| SP 800-185 final PDF                    | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf>                                                            | Normative definitions for cSHAKE, KMAC, TupleHash, ParallelHash, encodings, and security considerations.   |
| SP 800-185 DOI                          | <https://doi.org/10.6028/NIST.SP.800-185>                                                                                              | Stable citation target.                                                                                    |
| NIST March 2025 SHA-3 review decision   | <https://www.nist.gov/news-events/news/2025/03/sha-3-nist-update-fips-202-and-revise-special-publication-800-185>                      | Future-revision watch item and release-claim caution.                                                      |
| NIST example values                     | <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>                                                 | Authoritative source for FIPS 202 and SP 800-185 vectors.                                                  |
| Current Keccak code                     | `lib/src/common/keccak.dart`                                                                                                           | Baseline implementation and portability constraints.                                                       |
| Current Keccak tests                    | `test/keccak_test.dart`                                                                                                                | Existing evidence and gap analysis.                                                                        |
| Existing release-guide precedent        | [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md), [SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md)   | Structure, claim boundary, issue map, release gates.                                                       |

Local source-provenance snapshot taken on 2026-06-06:

| File                    | Pages   | SHA-256                                                              |
| ----------------------- | ------: | -------------------------------------------------------------------- |
| `NIST.FIPS.202.pdf`     | 37      | `1592607831ff0908cc590632ce371c6c95e94025bb1a0c8ae90a4d0ec1ed025e`   |
| `NIST.SP.800-185.pdf`   | 32      | `0ebcdfb5b145bcb6a8a0f49737a201e8fb30dce06951595a07010774d402d7c5`   |

## NIST Revision Watch

NIST added planning notes to both publication pages in March 2025.

The current interpretation for this repo:

- FIPS 202 update: treat as editorial and standards-maintenance watch until a
  new final FIPS is published. The current implementation target remains the
  August 2015 final standard, with the published non-normative Appendix B typo
  tracked in docs/tests.
- SP 800-185 revision: treat streaming SHAKE/cSHAKE behavior as a future
  compatibility requirement, not as a reason to delay current final-standard
  conformance. Any future draft must be evaluated separately before code is
  changed.
- No public claim may say "latest revised SP 800-185" until a final revision is
  published, implemented, and tested.

Add a recurring release checklist item: before any SHA-3-derived function
release, re-check the FIPS 202 and SP 800-185 CSRC pages for new drafts,
errata, planning notes, or final revisions.

## Executive Decision

`pqcrypto` cannot claim full FIPS 202 plus SP 800-185 support until all of the
following are true for the surfaces being claimed:

1. FIPS 202 functions SHA3-224/256/384/512 and SHAKE128/256 are implemented
   with correct rates, capacities, suffixes, output lengths, and padding.
2. Existing SHA3-256/512 and SHAKE128/256 APIs remain byte-for-byte compatible.
3. SHA3-224 and SHA3-384 are added with focused tests before public docs call
   the FIPS 202 family complete.
4. NIST FIPS 202 example vectors are checked in or fetched through a
   reproducible, hash-pinned tool.
5. Byte-oriented NIST examples pass for every implemented public API.
6. Non-byte-oriented NIST examples are either supported in a test-only
   bit-string harness or explicitly documented as unsupported by the byte API.
7. SP 800-185 helper encodings match the Recommendation exactly:
   `left_encode`, `right_encode`, `encode_string`, `bytepad`, and substring.
8. cSHAKE falls back to SHAKE when both function-name string and customization
   string are empty.
9. KMAC and KMACXOF encode output length correctly: fixed-output KMAC uses
   `right_encode(L)`, while XOF mode uses `right_encode(0)`.
10. TupleHash and TupleHashXOF encode every tuple element with `encode_string`
    and include fixed-output vs XOF output-length separation.
11. ParallelHash and ParallelHashXOF honor block-size `B`, inner cSHAKE output
    lengths, block count encoding, and fixed-output vs XOF separation.
12. Unsupported input shapes and sizes signal errors and never produce partial
    output.
13. Security guidance for KMAC key length and output length is surfaced in API
    docs and release notes.
14. All new functions run on Dart VM, dart2js, and dart2wasm with no runtime
    dependencies.
15. README, changelog, pubspec metadata, and docs claim only what the checked-in
    evidence proves.

## Claim Boundary

Acceptable wording after the relevant gates pass:

> `pqcrypto` provides a FIPS 202-aligned SHA-3/SHAKE implementation and
> SP 800-185-aligned SHA-3-derived functions for the surfaces listed in this
> release, with checked-in NIST example-vector evidence and VM/web regression
> tests.

Acceptable staged wording:

> `pqcrypto` currently implements SHA3-256, SHA3-512, SHAKE128, and SHAKE256
> from FIPS 202. Full FIPS 202 and SP 800-185 coverage is tracked in
> `doc/FIPS202_SP800185_RELEASE_GUIDE.md`.

Forbidden without a validation certificate:

- "FIPS validated"
- "CMVP validated"
- "FIPS 140 compliant module"
- "certified"
- "constant-time Dart implementation" as a hard guarantee
- "securely erases memory" as a hard guarantee

FIPS 202/SP 800-185 algorithm conformance and FIPS 140 module validation are
different claims. This package can provide source, vector, and regression
evidence. It cannot claim a validated cryptographic module unless a separate
module is validated through CMVP.

## FIPS 202 Standard Shape

FIPS 202 defines the SHA-3 family over binary data using Keccak-p permutations,
the sponge construction, and the Keccak multi-rate padding rule.

The FIPS 202 implementation target for this repo is byte-oriented public use,
with test-only bit-string support sufficient to evaluate official examples that
are not byte-aligned.

### Keccak-p and Keccak[c]

FIPS 202 defines Keccak-p[b, nr] over seven widths. The SHA-3 family uses
Keccak-p[1600, 24].

Implementation expectations:

| Element           | Requirement                              | Current repo                                                              |
| ----------------- | ---------------------------------------- | ------------------------------------------------------------------------- |
| State width       | 1600 bits, 25 lanes of 64 bits.          | Stored as 50 32-bit halves for web portability.                           |
| Round count       | 24 rounds for Keccak-p[1600, 24].        | Present.                                                                  |
| Step mappings     | theta, rho, pi, chi, iota.               | Present in `_permute`.                                                    |
| Rho offsets       | FIPS 202 Table 2.                        | Present as `_rho`; needs direct table test.                               |
| Round constants   | Iota constants for 24 rounds.            | Present as `_rcLo`/`_rcHi`; needs direct table test.                      |
| Padding           | Keccak `pad10*1` plus domain suffixes.   | Present through domain byte and final `0x80`; needs suffix matrix test.   |

### FIPS 202 functions

| Function   | Capacity   | Rate bytes   | Domain suffix bits   | Digest/output     | Current status   |
| ---------- | ---------: | -----------: | -------------------- | ----------------: | ---------------- |
| SHA3-224   | 448        | 144          | `01`                 | 28 bytes          | Missing          |
| SHA3-256   | 512        | 136          | `01`                 | 32 bytes          | Present          |
| SHA3-384   | 768        | 104          | `01`                 | 48 bytes          | Missing          |
| SHA3-512   | 1024       | 72           | `01`                 | 64 bytes          | Present          |
| SHAKE128   | 256        | 168          | `1111`               | caller-selected   | Present          |
| SHAKE256   | 512        | 136          | `1111`               | caller-selected   | Present          |

For byte-oriented implementation, the existing domain bytes are:

- SHA3: `0x06`
- SHAKE: `0x1f`

The guide requires a test explaining this translation from FIPS bit suffixes to
byte-oriented Keccak padding, because suffix mistakes are catastrophic and hard
to notice from API tests alone.

### RawSHAKE

FIPS 202 defines RawSHAKE128 and RawSHAKE256 as intermediate functions for
alternate SHAKE definitions. They are not ordinary public hash APIs.

Repo rule:

- Do not export RawSHAKE as a top-level user API unless an explicit consumer
  requires it.
- If implemented, keep it internal/test-only and pin its domain suffix
  separately from SHAKE.

### HMAC block sizes

FIPS 202 gives SHA-3 HMAC block sizes:

| Hash       | HMAC block size   |
| ---------- | ----------------: |
| SHA3-224   | 144 bytes         |
| SHA3-256   | 136 bytes         |
| SHA3-384   | 104 bytes         |
| SHA3-512   | 72 bytes          |

These are not needed for SP 800-185 KMAC, but they matter if the package later
adds HMAC-SHA3. Keep them out of KMAC implementation to avoid mixing two
different MAC constructions.

## SP 800-185 Standard Shape

SP 800-185 defines SHA-3-derived functions with two security strengths:

| Security strength   | cSHAKE      | KMAC                 | TupleHash                      | ParallelHash                         | Rate        |
| ------------------: | ----------- | -------------------- | ------------------------------ | ------------------------------------ | ----------: |
| 128 bits            | cSHAKE128   | KMAC128/KMACXOF128   | TupleHash128/TupleHashXOF128   | ParallelHash128/ParallelHashXOF128   | 168 bytes   |
| 256 bits            | cSHAKE256   | KMAC256/KMACXOF256   | TupleHash256/TupleHashXOF256   | ParallelHash256/ParallelHashXOF256   | 136 bytes   |

All SP 800-185 public APIs should accept byte strings first. Test-only bit-string
support may be added for official examples and edge cases.

### Encoding helpers

All SP 800-185 implementations depend on the same encoding primitives.

| Helper                 | Purpose                                                                  | Release rule                                               |
| ---------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------- |
| `left_encode(x)`       | Self-delimiting integer, length byte first.                              | Validate boundary values and examples, including 0.        |
| `right_encode(x)`      | Self-delimiting integer, length byte last.                               | Validate boundary values and examples, including 0.        |
| `encode_string(S)`     | `left_encode(len(S))` followed by `S`.                                   | Length is in bits, not bytes.                              |
| `bytepad(X, w)`        | `left_encode(w)` followed by `X`, then zero-padded to a multiple of `w`. | Reject non-positive `w`; test rates 168 and 136.           |
| `substring(X, a, b)`   | Bit substring helper.                                                    | Needed for bit-level and ParallelHash conformance tests.   |

Implementation detail:

- Use `BigInt` only where needed for the formal `2^2040` validity ceiling.
  Public byte APIs may reasonably reject lengths that exceed Dart memory or
  `int` capabilities before attempting allocation.
- Internal length variables must be named in bits where the standard uses
  bits (`len(S)`, `L`) and bytes where the standard uses bytes (`B`, rates).

### cSHAKE

Definitions:

- `cSHAKE128(X, L, N, S)`
- `cSHAKE256(X, L, N, S)`

Rules:

1. If `N` and `S` are both empty, return SHAKE with the same input and output
   length.
2. Otherwise absorb `bytepad(encode_string(N) || encode_string(S), rate) || X`
   with cSHAKE's domain separation.
3. `N` is a function-name string. Ordinary users should generally leave it
   empty. Standard-derived functions use fixed names such as `KMAC`.
4. `S` is the customization string. API docs must say different customization
   strings produce unrelated outputs for the same input, within the standard's
   security model.

API target:

```dart
final out = CShake128.hash(
  message,
  outputLength: 64,
  functionName: Uint8List(0),
  customization: ascii('tenant-a'),
);
```

### KMAC and KMACXOF

Definitions:

- `KMAC128(K, X, L, S)`
- `KMAC256(K, X, L, S)`
- `KMACXOF128(K, X, L, S)`
- `KMACXOF256(K, X, L, S)`

Rules:

1. `K` is encoded with `bytepad(encode_string(K), rate)`.
2. Fixed-output KMAC appends `right_encode(L)`.
3. KMACXOF appends `right_encode(0)` and then squeezes the requested output.
4. The function-name string is `KMAC`.
5. API docs must warn that applications should not select a key shorter than
   the required security strength.
6. API docs must warn that short MAC tags reduce online forgery resistance.

API target:

```dart
final tag = Kmac256.mac(
  key,
  message,
  outputLength: 32,
  customization: ascii('pqcrypto:v1'),
);
```

Recommended public behavior:

- Throw `ArgumentError` for empty keys only if the chosen API policy forbids
  them. The standard allows arbitrary key lengths, but secure use guidance
  requires sufficient key length. If empty keys are allowed for test vectors,
  the safe API should still offer a checked mode.
- Provide `minimumRecommendedKeyBytes` constants: 16 for 128-bit security and
  32 for 256-bit security.
- Provide `minimumRecommendedTagBytes` guidance, but do not hardcode one tag
  size into the primitive.

### TupleHash and TupleHashXOF

Definitions:

- `TupleHash128(X, L, S)`
- `TupleHash256(X, L, S)`
- `TupleHashXOF128(X, L, S)`
- `TupleHashXOF256(X, L, S)`

Rules:

1. Encode each tuple element with `encode_string`.
2. Preserve empty elements. The tuple `[A, empty, B]` is different from
   `[A, B]`.
3. Fixed-output TupleHash appends `right_encode(L)`.
4. TupleHashXOF appends `right_encode(0)`.
5. The function-name string is `TupleHash`.

API target:

```dart
final digest = TupleHash256.hash(
  [firstField, secondField, Uint8List(0)],
  outputLength: 64,
  customization: ascii('record-hash'),
);
```

Tests must prove that tuple boundary changes alter output:

- `[ab, c]` differs from `[a, bc]`.
- `[a, empty, b]` differs from `[a, b]`.
- fixed-output and XOF mode differ for the same visible output length.

### ParallelHash and ParallelHashXOF

Definitions:

- `ParallelHash128(X, B, L, S)`
- `ParallelHash256(X, B, L, S)`
- `ParallelHashXOF128(X, B, L, S)`
- `ParallelHashXOF256(X, B, L, S)`

Rules:

1. `B` is the block size in bytes and must be greater than 0.
2. Each input block is hashed with cSHAKE using empty `N` and `S`.
3. Inner block digest length is 256 bits for the 128-bit function and 512 bits
   for the 256-bit function.
4. The final input starts with `left_encode(B)`, includes each inner digest,
   then appends `right_encode(n)` and either `right_encode(L)` or
   `right_encode(0)` for XOF mode.
5. The function-name string is `ParallelHash`.

API target:

```dart
final digest = ParallelHash128.hash(
  largeMessage,
  blockSize: 8192,
  outputLength: 32,
);
```

Implementation strategy:

- First release may use sequential processing while preserving the exact
  ParallelHash transcript.
- A later optimization can parallelize block hashing behind the same tests.
- Do not imply the first release is faster than SHAKE for all inputs. Benchmark
  before making performance claims.

## Implementation Architecture

Target package structure:

```text
lib/src/common/
  keccak.dart       # Keccak-f[1600], SHA3-224/256/384/512, SHAKE128/256, XOF
  shake.dart        # Compatibility wrappers for SHAKE users
  sp800_185.dart    # cSHAKE, KMAC, TupleHash, ParallelHash public/internal APIs

test/
  data/
    FIPS202/
      README.md
      manifest.json
      examples/...  # hash-pinned NIST example files or normalized vectors
    SP800185/
      README.md
      manifest.json
      examples/...  # hash-pinned cSHAKE/KMAC/TupleHash/ParallelHash vectors
  keccak_test.dart
  fips202_examples_test.dart
  sp800_185_encoding_test.dart
  sp800_185_cshake_test.dart
  sp800_185_kmac_test.dart
  sp800_185_tuplehash_test.dart
  sp800_185_parallelhash_test.dart
```

Guidance:

- Keep `keccak.dart` as the primitive owner. Avoid duplicating sponge logic in
  `sp800_185.dart`.
- Add a private constructor or internal helper that can initialize Keccak with
  a preabsorbed customization block if profiling proves it matters.
- Keep public APIs byte-oriented unless and until a bit-string abstraction has a
  clear user story.
- Keep test-only bit support small and isolated. Do not contaminate normal APIs
  with bit-level complexity if the package cannot ergonomically support it.
- Continue avoiding runtime dependencies. Dev-only vector tooling is acceptable
  if it is isolated from `lib/` and documented.

## Public API Target

The final public API should make standard use obvious and unsafe ambiguity
harder to express.

```dart
final digest224 = sha3224(message);
final digest384 = sha3384(message);

final xof = Shake256.xof(seed);
final block = xof.squeeze(64);

final customized = CShake256.hash(
  message,
  outputLength: 64,
  customization: Uint8List.fromList('app-domain'.codeUnits),
);

final tag = Kmac256.mac(
  key,
  message,
  outputLength: 32,
  customization: Uint8List.fromList('mac-domain'.codeUnits),
);

final tupleDigest = TupleHash128.hash(
  [header, payload, trailer],
  outputLength: 32,
);

final parallelDigest = ParallelHash256.hash(
  largeMessage,
  blockSize: 8192,
  outputLength: 64,
);
```

Proposed exports:

```dart
export 'src/common/keccak.dart'
    show sha3224, sha3256, sha3384, sha3512, shake128, shake256;
export 'src/common/shake.dart' show Shake128, Shake256;
export 'src/common/sp800_185.dart'
    show
        CShake128,
        CShake256,
        Kmac128,
        Kmac256,
        TupleHash128,
        TupleHash256,
        ParallelHash128,
        ParallelHash256;
```

API design rules:

- All output lengths in public byte APIs are bytes.
- Any lower-level internal helper that takes bits must include `Bits` in the
  name, for example `outputLengthBits`.
- Reject negative output lengths.
- For KMAC, distinguish fixed-output and XOF mode with separate methods or
  classes. Do not use a boolean that silently changes `right_encode(L)` to
  `right_encode(0)`.
- For ParallelHash, reject `blockSize <= 0`.
- For tuple inputs, copy or consume `Uint8List` defensively according to the
  existing repo style. Do not store caller-owned mutable buffers in reusable
  keyed objects unless documented.

## Bit-String and Non-Byte Input Policy

FIPS 202 and SP 800-185 are defined on bit strings, and NIST publishes
non-byte-aligned examples. Dart APIs naturally operate on bytes. This mismatch
must be explicit.

Recommended policy:

1. Public v1 APIs accept only byte strings and output whole bytes.
2. If a caller requests non-byte behavior through a future API, the type must
   represent both bytes and bit length.
3. The test suite includes a small internal `BitString` helper for NIST example
   parsing.
4. The documentation says byte-only public APIs are a deliberate limited
   implementation choice permitted by SP 800-185, not an oversight.
5. Broad "full standard" wording is withheld until non-byte examples are either
   supported in public APIs or the claim is narrowed to byte-oriented inputs.

Internal helper sketch:

```dart
final class BitString {
  const BitString(this.bytes, this.bitLength);

  final Uint8List bytes;
  final int bitLength;
}
```

The helper should be used only in tests unless product requirements justify a
public bit-string API.

## Test Corpus Strategy

The corpus must be reproducible and source-scoped.

### FIPS 202 examples

NIST lists example files for each of:

- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHAKE128
- SHAKE256

The listed input lengths are:

- 0 bits
- 5 bits
- 30 bits
- 1600 bits
- 1605 bits
- 1630 bits

There is also a SHAKE truncation sample for output bit lengths not divisible by
8.

Release expectation:

- Check in normalized `.json` or `.rsp` vectors under `test/data/FIPS202/`, or
  check in a manifest plus a tool that fetches, hashes, and normalizes the NIST
  PDFs.
- Include the original NIST URLs and retrieval date in `test/data/FIPS202/README.md`.
- Include SHA-256 hashes for source files and normalized vectors.
- Run a discovered `test/fips202_examples_test.dart` by default under
  `dart test`.
- VM-only tests are allowed for PDF/file parsing tools, but the normalized vector
  tests should run on web where practical.

### SP 800-185 examples

NIST lists example files for:

- cSHAKE
- KMAC
- KMACXOF
- TupleHash
- TupleHashXOF
- ParallelHash
- ParallelHashXOF

Release expectation:

- Check in normalized vectors under `test/data/SP800185/`.
- Cover both 128-bit and 256-bit security strength variants.
- Cover fixed-output vs XOF mode separation.
- Cover empty customization strings and non-empty customization strings.
- Cover tuple-boundary edge cases beyond official examples.
- Cover ParallelHash with more than one block.

### Negative and misuse tests

Add tests for:

- negative output lengths;
- unsupported non-byte inputs through public byte APIs;
- invalid `bytepad` width;
- invalid ParallelHash block size;
- KMAC keys below recommended length in checked/safe mode;
- fixed-output KMAC vs KMACXOF distinction;
- fixed-output TupleHash/ParallelHash vs XOF distinction;
- cSHAKE fallback to SHAKE when `N` and `S` are empty;
- different cSHAKE customization strings yielding different outputs;
- tuple-boundary ambiguity resistance;
- no accidental mutation of caller inputs.

## Security and Side-Channel Posture

FIPS 202 and SP 800-185 primitives are mostly fixed-control-flow transforms, but
the repo still needs disciplined handling.

Security rules:

- Do not claim hard constant-time behavior for Dart.
- Keep Keccak round control flow independent of secret data.
- Avoid secret-dependent branches in KMAC keyed object reuse paths where
  practical.
- Do not log KMAC keys, intermediate sponge state, customization strings that
  may contain secrets, or derived output.
- If reusable KMAC contexts are added, document whether keys are copied,
  retained, and zeroized.
- Zeroize temporary key-encoding buffers with best-effort `secureZero` where
  possible.
- Treat output length as a security parameter in docs.
- For KMAC, document that applications should choose key length at least equal
  to the required security strength.

Misuse language:

- SHAKE and cSHAKE are XOFs. Short requested output lengths reduce available
  collision and preimage strength.
- KMAC is a MAC/PRF construction, not HMAC-SHA3.
- TupleHash is for unambiguous tuple encoding. Do not replace it with raw
  concatenation.
- ParallelHash is not automatically faster in a sequential implementation.

## Performance and Portability

Portability is release-blocking:

- Dart VM
- dart2js
- dart2wasm

Performance gates:

- Benchmark SHA3-256, SHAKE256, KMAC256, TupleHash256, and ParallelHash256 on
  small, medium, and large inputs.
- Compare ParallelHash sequential implementation against SHAKE/SHA3 for large
  inputs before making performance claims.
- Preserve the current 32-bit lane-half arithmetic unless a replacement is
  proven by the FIPS 202 corpus and web tests.
- Add benchmarks under the existing performance plan rather than mixing them
  into functional KAT tests.

## Milestone Plan

The roadmap target is **0.7.0**. Milestones M0-M6 are ordered so that FIPS 202
can be completed before SP 800-185 derived functions depend on it. Any unfinished
standards surface that misses 0.7.0 moves to **0.8.0** with the same evidence
requirements; no issue may be closed by downgrading public wording to hide a
partial implementation.

### M0 - Guide, issues, and source lock

Status: this guide.

Deliverables:

- Publish this document.
- Add GitHub issues SHA3-00 through SHA3-12.
- Add `sha3` label.
- Sync [INDEX.md](INDEX.md), [ROADMAP.md](ROADMAP.md),
  [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md), [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md),
  and [ARCHITECTURE.md](ARCHITECTURE.md).

### M1 - FIPS 202 completion

Deliverables:

- Add SHA3-224 and SHA3-384.
- Add rate/capacity/suffix table tests.
- Add Keccak round constant and rho-offset tests.
- Normalize and check in FIPS 202 examples.
- Add byte-oriented example tests and test-only bit-string harness.
- Update docs to say "FIPS 202 family complete" only after corpus gates pass.

### M2 - SP 800-185 encoding and cSHAKE

Deliverables:

- Add `sp800_185.dart`.
- Implement and test encodings.
- Implement cSHAKE128/256.
- Add cSHAKE NIST vectors.
- Add cSHAKE fallback and customization tests.

### M3 - KMAC and KMACXOF

Deliverables:

- Implement KMAC128/256 and KMACXOF128/256.
- Add NIST KMAC/KMACXOF vectors.
- Add safe-use key/tag length guidance.
- Add best-effort zeroization around temporary key encodings.

### M4 - TupleHash and TupleHashXOF

Deliverables:

- Implement TupleHash128/256 and TupleHashXOF128/256.
- Add NIST TupleHash vectors.
- Add tuple-boundary and empty-element tests.

### M5 - ParallelHash and ParallelHashXOF

Deliverables:

- Implement sequential ParallelHash128/256 and XOF variants.
- Add NIST ParallelHash vectors.
- Add block-size validation and multi-block tests.
- Add benchmarks before claiming any speed advantage.

### M6 - Release readiness

Deliverables:

- All child issues closed for the surfaces being released.
- `dart format --output=none --set-exit-if-changed .`
- `dart analyze`
- `dart test test/keccak_test.dart test/fips202_examples_test.dart`
- `dart test test/sp800_185_encoding_test.dart test/sp800_185_cshake_test.dart test/sp800_185_kmac_test.dart test/sp800_185_tuplehash_test.dart test/sp800_185_parallelhash_test.dart`
- `dart test`
- `dart test -p chrome`
- `dart test -p chrome --compiler dart2wasm`
- `dart pub publish --dry-run`
- README, changelog, `pubspec.yaml`, docs, and issue tracker agree on the
  exact supported surfaces.

## GitHub Issue Map

| ID        | GitHub   | Title                                                 | Priority   | Gate                                                                     |
| --------- | -------- | ----------------------------------------------------- | ---------- | ------------------------------------------------------------------------ |
| SHA3-00   | #48      | Epic: FIPS 202 and SP 800-185 to release              | P0         | All child issues closed.                                                 |
| SHA3-01   | #36      | Source corpus and NIST example-vector provenance      | P0         | `test/data/FIPS202` and `test/data/SP800185` manifests.                  |
| SHA3-02   | #37      | Complete FIPS 202 SHA3-224/SHA3-384 APIs              | P0         | SHA3-224/384 NIST vectors pass.                                          |
| SHA3-03   | #38      | FIPS 202 conformance harness for bit-level examples   | P0         | 0/5/30/1600/1605/1630-bit examples covered or explicitly scoped.         |
| SHA3-04   | #39      | Keccak constants, suffix, rate, and capacity tests    | P0         | Direct table and suffix tests pass.                                      |
| SHA3-05   | #40      | SP 800-185 encoding helpers                           | P0         | `left_encode`, `right_encode`, `encode_string`, `bytepad` tests pass.    |
| SHA3-06   | #41      | cSHAKE128/cSHAKE256                                   | P0         | NIST cSHAKE vectors and SHAKE fallback pass.                             |
| SHA3-07   | #42      | KMAC128/KMAC256 and KMACXOF                           | P0         | NIST KMAC/KMACXOF vectors plus misuse tests pass.                        |
| SHA3-08   | #43      | TupleHash and TupleHashXOF                            | P1         | NIST vectors plus tuple-boundary tests pass.                             |
| SHA3-09   | #44      | ParallelHash and ParallelHashXOF                      | P1         | NIST vectors plus multi-block tests pass.                                |
| SHA3-10   | #45      | Security, zeroization, and API misuse docs            | P1         | KMAC key/tag guidance and no-overclaim docs complete.                    |
| SHA3-11   | #46      | VM/web portability and performance benchmarks         | P1         | VM, dart2js, dart2wasm gates and benchmark report complete.              |
| SHA3-12   | #47      | Release docs, changelog, and package metadata         | P0         | Release wording matches evidence and `pub publish --dry-run` is clean.   |

## Documentation Sync Requirements

Update these files whenever the implementation state changes:

- `README.md`
- `CHANGELOG.md`
- `pubspec.yaml` description/topics if needed
- [INDEX.md](INDEX.md)
- [ROADMAP.md](ROADMAP.md)
- [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)
- [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md)
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md)
- [PERFORMANCE.md](PERFORMANCE.md)

Documentation must always say which surfaces are implemented and tested. Avoid
"full SHA-3" shorthand unless both FIPS 202 and SP 800-185 context makes the
meaning unambiguous.

## Definition of Done

The complete FIPS 202/SP 800-185 release is done only when:

- all issue-map tasks for the release scope are closed;
- all implemented functions are backed by checked-in NIST examples;
- byte-oriented public APIs are documented precisely;
- any non-byte limitation is explicit;
- VM and web compiler tests pass;
- no runtime dependency is added;
- KMAC security guidance is in API docs and README;
- no public wording exceeds algorithm/vector evidence;
- `dart pub publish --dry-run` has zero warnings; and
- the release tag points to the same commit that was published.

## Appendix A - Current Implementation Gap Table

| Surface          | Current status   | Required next action                                            |
| ---------------- | ---------------- | --------------------------------------------------------------- |
| Keccak-f[1600]   | Present          | Add direct constants/table tests.                               |
| SHA3-224         | Missing          | Implement with rate 144 bytes and 28-byte output.               |
| SHA3-256         | Present          | Expand official vector coverage.                                |
| SHA3-384         | Missing          | Implement with rate 104 bytes and 48-byte output.               |
| SHA3-512         | Present          | Expand official vector coverage.                                |
| SHAKE128         | Present          | Expand official vector coverage and non-byte output handling.   |
| SHAKE256         | Present          | Expand official vector coverage and non-byte output handling.   |
| cSHAKE           | Missing          | Implement after encoding helpers.                               |
| KMAC/KMACXOF     | Missing          | Implement after cSHAKE.                                         |
| TupleHash        | Missing          | Implement after cSHAKE.                                         |
| ParallelHash     | Missing          | Implement after cSHAKE and benchmark sequential baseline.       |

## Appendix B - Release Claim Checklist

Before any release announcement:

- [ ] Which FIPS 202 functions are implemented?
- [ ] Which SP 800-185 functions are implemented?
- [ ] Are all claimed functions covered by checked-in NIST examples?
- [ ] Are byte-only limitations documented?
- [ ] Did `dart test -p chrome` and `dart test -p chrome --compiler dart2wasm`
      pass?
- [ ] Did `dart pub publish --dry-run` report zero warnings?
- [ ] Does README avoid CMVP/FIPS 140 language?
- [ ] Does CHANGELOG list exact surfaces, not broad claims?
- [ ] Does `doc/FIPS_COMPLIANCE.md` distinguish algorithm evidence from module
      validation?
- [ ] Did the release owner re-check NIST FIPS 202 and SP 800-185 pages for
      updated planning notes or final revisions?

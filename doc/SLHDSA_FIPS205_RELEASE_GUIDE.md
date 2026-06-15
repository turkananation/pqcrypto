# SLH-DSA FIPS 205 Compliance and Release Guide

Last updated: 2026-06-15

This is the engineering guide for designing, implementing, validating, and
releasing `pqcrypto`'s SLH-DSA (Stateless Hash-Based Digital Signature
Algorithm) implementation. It is based on the official NIST FIPS 205 final
publication (published 2024-08-13), the NIST ACVP test-vector program, the
SLH-DSA design history (SPHINCS+), the existing
[MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md) precedent, and
the current repository state.

This guide began as a greenfield plan. The repository has now completed M0-M8
engineering work locally: the official ACVP corpus is pinned, FIPS 205
Algorithms 1-25 are implemented for all 12 SHA2/SHAKE parameter sets, all 1,248
ACVP cases are byte-exact, the external API is exported in source, and
hardening, platform, benchmark, and independent-provider interop evidence is
present. The guide continues to control CI confirmation and publication work.

This document is **not** a CMVP/FIPS 140 validation certificate. It is the
release plan for algorithm conformance, security hardening, test evidence, and
public claim discipline. The exact acceptable wording lives in
[FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).

## Completion Status (2026-06-15)

**M0-M8 engineering gates complete locally; remote CI and maintainer release
actions remain.** `lib/src/algos/slhdsa/` contains Algorithms 1-25 for all 12
parameter sets.
`test/data/SLHDSA/` contains the official NIST ACVP
sample corpus at commit
`15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`: 120 groups and 1,248 cases across
all 12 parameter sets, with SHA-256 integrity and schema/coverage tests.

`test/slhdsa_kat_test.dart` executes all 1,248 cases: 120 key generations,
624 signatures, and 504 verification outcomes across internal/external,
pure/pre-hash, deterministic/hedged, and positive/negative coverage. The
external Algorithms 21-25 API is exported for every set, while Algorithms
18-20 remain source-only for ACVP execution. HMAC-SHA-256/512, MGF1-SHA-256/512,
the 22-byte compressed address (`ADRS^c`), and the category 1 versus category
3/5 SHA-2 routing are independently tested before composition.

Verify-after-sign, BUFF/performance documentation, 48 VM JIT/AOT/dart2js/
dart2wasm benchmark measurements, and OpenSSL 4.0.1 plus liboqs 0.15.0
cross-verification are complete locally. The decomposed VM matrix, both web
compiler suites, native-provider suites, and package publish dry-run are green.
The updated CI workflows have not yet run on GitHub. The v0.4.0 version bump,
tag, and publication are not yet done.

What already exists and is reused: the vendored Keccak in
`lib/src/common/keccak.dart` (`KeccakXof`, `shake256`, `sha3256`/`sha3512`), the
vendored FIPS 180-4 one-shot hashes in `lib/src/common/sha2.dart` (`sha224`,
`sha256`, `sha384`, `sha512`, `sha512224`, `sha512256`), and the zeroization
helpers in
`lib/src/common/zeroize.dart` (`secureZero`, `secureZeroInt32`).

## Release Strategy (All 12 Sets in v0.4.0)

The implementation was sequenced by hash family. A SHAKE-first order controlled
the build and isolated the new SHA-2 primitives behind independent tests. After
the SHA-2 work closed and all six SHA-2 sets passed the official ACVP and
provider interop gates, the release scope was set to all 12 sets in v0.4.0. The
original SHAKE-first split remains useful engineering history, but no longer
controls the release boundary.

1. **Sequence implementation by hash family.** Build the six SHAKE sets first
   because they reuse `keccak.dart` and add no new primitive. Add the six SHA-2
   sets only after independently testing the four hand-vendored surfaces
   (HMAC-SHA-256/512, MGF1-SHA-256/512, SHA-512 in a new context, and the
   22-byte `ADRS^c`) that form a shared core beneath all six SHA-2 sets.
2. **Build SHAKE-first as an isolation strategy, not just a schedule.** A clean,
   byte-exact SHAKE release proves the WOTS+/XMSS/hypertree/FORS scaffolding is
   correct. Any later SHA-2 KAT failure is then provably isolated to the new
   SHA-2 primitives.
3. **Gate every vendored primitive on its own KAT first.** HMAC against RFC 4231,
   MGF1 against PKCS#1 (RFC 8017) vectors, _before_ it enters the SLH-DSA
   composition. A primitive with no independent KAT is a single point of failure
   in disguise.
4. **Use NIST ACVP `SLH-DSA` vectors only** for byte-exact evidence. Do **not**
   use SPHINCS+ round-3 reference KATs — the FORS digest bit-extraction changed
   between SPHINCS+ v3 and FIPS 205 (see [Appendix A](#appendix-a---differences-from-the-sphincs-submission)).
   Passing v3 vectors would be a byte-exact validation of the _wrong algorithm_.
5. **Default to `SLH-DSA-SHAKE-128f`.** The `s` variants perform on the order of
   10^5-10^6 hash calls per signature and are not appropriate defaults for web,
   Wasm, or interactive flows. Make this an explicit gate in the API and docs,
   not a footnote.
6. **Surface the message-bound (BUFF) gap and the performance reality loudly.**
   They belong in the public API docstrings and the README's first screen, not
   buried in a compliance document (see
   [BUFF / Message-Bound Risk](#buff--message-bound-signature-risk) and
   [Performance Reality](#performance-reality-and-parameter-guidance)).

The rationale, the opinionated-API note (an even narrower two-set surface), and
the kill criteria are summarized in the [Release Strategy Rationale
appendix](#appendix-c---release-strategy-rationale).

## Source Corpus

| Source                                     | URL / path                                                                             | How this guide uses it                                                            |
| ------------------------------------------ | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| FIPS 205 final publication page            | <https://csrc.nist.gov/pubs/fips/205/final>                                            | Publication status, date, official document set.                                  |
| FIPS 205 final PDF                         | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf>                             | Normative SLH-DSA algorithms (1-25), parameters (Table 2), addressing, hashes.    |
| FIPS 205 DOI                               | <https://doi.org/10.6028/NIST.FIPS.205>                                                | Stable citation target.                                                           |
| FIPS 205 potential updates                 | (none published as of 2026-06-14)                                                      | Watch item. FIPS 204 has an errata sheet; FIPS 205 does not yet. Track the page.  |
| NIST ACVP SLH-DSA vectors                  | <https://github.com/usnistgov/ACVP-Server> (`SLH-DSA-keyGen/sigGen/sigVer`)            | The byte-exact KAT corpus source. ACVP-JSON format. The only approved provenance. |
| NIST example values                        | <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values> | Intermediate/example vectors for component cross-checks.                          |
| SPHINCS+ reference / liboqs / OpenSSL 3.5+ | <https://sphincs.org>, <https://github.com/open-quantum-safe/liboqs>                   | Independent cross-verification implementations (not as a KAT source).             |
| Current pqcrypto primitives                | `lib/src/common/{keccak,sha2,zeroize}.dart`                                            | Reused SHAKE/SHA-2/zeroize building blocks; gap analysis for HMAC/MGF1.           |
| ML-DSA release precedent                   | [MLDSA_FIPS204_RELEASE_GUIDE.md](MLDSA_FIPS204_RELEASE_GUIDE.md)                       | Structure, claim boundary, discovered-runner pattern, DoD discipline.             |

## Executive Decision

SLH-DSA cannot be released as a supported signature surface until all of these
conditions are true for the parameter sets being claimed in that release:

1. The public API implements the FIPS 205 external functions
   (`slh_keygen`, `slh_sign`, `hash_slh_sign`, `slh_verify`, `hash_slh_verify`)
   with hedged signing as the default.
2. Internal functions (`slh_keygen_internal`, `slh_sign_internal`,
   `slh_verify_internal`) match the FIPS 205 algorithms exactly and are
   accessible only for tests/fixtures, not as the normal application API.
3. The component schemes (WOTS+, XMSS, hypertree, FORS) are implemented and
   **not** exposed as standalone public APIs (FIPS 205 §3.2 "Do not support
   component use").
4. Every claimed parameter set matches FIPS 205 Table 2: `n, h, d, h', a, k,
   lg_w, m`, security category, and the derived public-key and signature sizes.
5. Key and signature formatting follow FIPS 205 §9.1 and §9.2 (private key
   `SK.seed || SK.prf || PK.seed || PK.root` = 4n bytes; public key
   `PK.seed || PK.root` = 2n bytes; signature `R || SIG_FORS || SIG_HT`).
6. Pure and pre-hash (HashSLH-DSA) message formatting use the correct domain
   separators and DER OID encodings; context strings are supported and limited
   to 255 bytes.
7. Verification rejects malformed signatures by exact length
   (`|SIG| = (1 + k(1+a) + h + d·len)·n`) before any parsing, and returns a
   boolean (never throws) for untrusted input.
8. The hash-function family for the parameter set is instantiated exactly per
   FIPS 205 §11 (SHAKE) or §11.2 (SHA-2 categories 1 vs 3/5), including the
   SHA-256/SHA-512 split and `ADRS^c` compression for SHA-2 sets.
9. Every hand-vendored primitive (HMAC, MGF1) passes its **own** standalone KAT
   before composition.
10. The implementation is byte-exact against the checked-in NIST ACVP SLH-DSA
    KAT corpus for every claimed parameter set, under plain `dart test`.
11. Negative tests cover malformed signatures, wrong lengths, wrong context,
    cross-parameter verification, and pre-hash/pure domain confusion.
12. Sensitive intermediate values (`SK.seed`, `SK.prf`, WOTS+ and FORS secret
    nodes, the randomizer `R`) are zeroized or deliberately justified where Dart
    semantics prevent a stronger guarantee.
13. The randomizer is hedged by default; the deterministic variant is explicit
    and documented as fault-amplifying.
14. VM, AOT, dart2js, and dart2wasm validation is green or limitations are
    documented before publication, with at least one published benchmark per
    target.
15. README, package metadata, docs, and changelog use evidence-scoped wording,
    and the BUFF and performance caveats are surfaced at the API level.

## Claim Boundary

Use precise language, identical in discipline to the ML-DSA boundary:

- Acceptable after a given release is completed: "`pqcrypto` provides a FIPS
  205-aligned SLH-DSA implementation for `{the released parameter sets}` that
  passes the checked-in SLH-DSA KAT corpus and regression suite described in
  this repository."
- Not acceptable without a validation certificate: "FIPS validated",
  "CMVP validated", "FIPS 140 compliant module", or "certified".

FIPS 205 algorithm conformance and FIPS 140 module validation are different
claims. This package can provide implementation evidence. It cannot claim FIPS
140 validation unless a cryptographic module is separately validated through
CMVP with an approved operational environment, entropy source, and security
policy. The full rationale is in [FIPS_140_BOUNDARY.md](FIPS_140_BOUNDARY.md).

Additional SLH-DSA-specific honesty requirements:

- Never claim a parameter set is "supported" until it is byte-exact against
  authoritative ACVP vectors. Sets not yet proven may ship behind an
  `experimental` flag with a printed warning, or not at all.
- Never imply the message-bound (BUFF) property holds (it does not, except for
  `*-128f`; see below).

## FIPS 205 Standard Shape

SLH-DSA is a hypertree of one-time and few-time hash-based signatures. From the
bottom up:

| Component | Role                                                                 | FIPS 205 section / algorithms |
| --------- | -------------------------------------------------------------------- | ----------------------------- |
| WOTS+     | Winternitz one-time signature. Chains of `F`. Signs an n-byte value. | §5, Algorithms 4-8            |
| XMSS      | Merkle tree of `2^h'` WOTS+ public keys. Signs one n-byte value.     | §6, Algorithms 9-11           |
| Hypertree | `d` layers of XMSS trees (total height `h = d·h'`). Signs FORS keys. | §7, Algorithms 12-13          |
| FORS      | Forest of `k` random-subset Merkle trees. Signs the message digest.  | §8, Algorithms 14-17          |
| SLH-DSA   | Randomized digest -> FORS -> hypertree. Internal + external APIs.    | §9-10, Algorithms 18-25       |

FIPS 205 separates functions into three layers; the repo must respect the
boundary:

| Layer     | Functions                                                                                     | Rule for this repo                                                                      |
| --------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| External  | Algorithms 21-25 (`slh_keygen`, `slh_sign`, `hash_slh_sign`, `slh_verify`, `hash_slh_verify`) | Public API surface. Handles randomness, context formatting, pre-hash, and input checks. |
| Internal  | Algorithms 18-20 (`slh_keygen_internal`, `slh_sign_internal`, `slh_verify_internal`)          | Deterministic core. Expose only through internal/test-only helpers for ACVP KATs.       |
| Component | Algorithms 1-17 (toInt/toByte/base_2b, WOTS+, XMSS, HT, FORS)                                 | Shared primitives. Focused unit/property tests. **Never** a public standalone API.      |

The 25 algorithms, in order, with the file each should live in:

| Alg | Name                  | Purpose                                         | Target file      |
| --- | --------------------- | ----------------------------------------------- | ---------------- |
| 1   | `gen_len2`            | Compute `len2` (it is 3 for all sets here).     | `params.dart`    |
| 2   | `toInt`               | Byte string -> integer (big-endian).            | `util.dart`      |
| 3   | `toByte`              | Integer -> byte string (big-endian).            | `util.dart`      |
| 4   | `base_2b`             | Byte string -> base-2^b integer array.          | `util.dart`      |
| 5   | `chain`               | WOTS+ hash chain (iterate `F`).                 | `wots.dart`      |
| 6   | `wots_pkGen`          | WOTS+ public key.                               | `wots.dart`      |
| 7   | `wots_sign`           | WOTS+ signature (with checksum).                | `wots.dart`      |
| 8   | `wots_pkFromSig`      | Recover WOTS+ public key from signature.        | `wots.dart`      |
| 9   | `xmss_node`           | Compute an XMSS Merkle subtree root.            | `xmss.dart`      |
| 10  | `xmss_sign`           | XMSS signature (WOTS+ sig + auth path).         | `xmss.dart`      |
| 11  | `xmss_pkFromSig`      | Recover XMSS root from signature.               | `xmss.dart`      |
| 12  | `ht_sign`             | Hypertree signature (`d` stacked XMSS sigs).    | `hypertree.dart` |
| 13  | `ht_verify`           | Hypertree verification.                         | `hypertree.dart` |
| 14  | `fors_skGen`          | FORS secret value via PRF.                      | `fors.dart`      |
| 15  | `fors_node`           | FORS Merkle subtree root.                       | `fors.dart`      |
| 16  | `fors_sign`           | FORS signature (k secret values + auth).        | `fors.dart`      |
| 17  | `fors_pkFromSig`      | Recover FORS public key from signature.         | `fors.dart`      |
| 18  | `slh_keygen_internal` | Deterministic keygen from seeds.                | `slhdsa.dart`    |
| 19  | `slh_sign_internal`   | Deterministic sign (digest split, FORS, HT).    | `slhdsa.dart`    |
| 20  | `slh_verify_internal` | Deterministic verify (length check, recompute). | `slhdsa.dart`    |
| 21  | `slh_keygen`          | External keygen (fresh RBG).                    | `slhdsa.dart`    |
| 22  | `slh_sign`            | External pure sign (ctx, hedged default).       | `slhdsa.dart`    |
| 23  | `hash_slh_sign`       | External pre-hash sign (PH + OID).              | `slhdsa.dart`    |
| 24  | `slh_verify`          | External pure verify.                           | `slhdsa.dart`    |
| 25  | `hash_slh_verify`     | External pre-hash verify.                       | `slhdsa.dart`    |

## Parameter Sets

FIPS 205 Table 2 defines 12 parameter sets: `{SHA2, SHAKE} × {128, 192, 256} ×
{s, f}`. The `s`/`f` suffix is small-signature vs fast-signing. **All 12 are
represented in code and covered by a size/parameter test**, and ship together in
v0.4.0.

| Set (SHA2 / SHAKE) | n   | h   | d   | h'  | a   | k   | lg_w | m   | cat | pk bytes | sig bytes | candidate release |
| ------------------ | --- | --- | --- | --- | --- | --- | ---- | --- | --- | -------- | --------- | ----------------- |
| `*-128s`           | 16  | 63  | 7   | 9   | 12  | 14  | 4    | 30  | 1   | 32       | 7 856     | v0.4.0            |
| `*-128f`           | 16  | 66  | 22  | 3   | 6   | 33  | 4    | 34  | 1   | 32       | 17 088    | v0.4.0            |
| `*-192s`           | 24  | 63  | 7   | 9   | 14  | 17  | 4    | 39  | 3   | 48       | 16 224    | v0.4.0            |
| `*-192f`           | 24  | 66  | 22  | 3   | 8   | 33  | 4    | 42  | 3   | 48       | 35 664    | v0.4.0            |
| `*-256s`           | 32  | 64  | 8   | 8   | 14  | 22  | 4    | 47  | 5   | 64       | 29 792    | v0.4.0            |
| `*-256f`           | 32  | 68  | 17  | 4   | 9   | 35  | 4    | 49  | 5   | 64       | 49 856    | v0.4.0            |

Derived values (compute these as getters, single source of truth):

- `w = 2^lg_w = 16` (all sets).
- `len1 = ceil(8n / lg_w) = 2n`; `len2 = 3` (all sets); `len = len1 + len2 = 2n + 3`.
  - n=16 -> `len = 35`; n=24 -> `len = 51`; n=32 -> `len = 67`.
- `t = 2^a` (FORS leaves per tree); FORS has `k` trees.
- Private key = `4n` bytes: 64 / 64 / 96 / 96 / 128 / 128.
- Public key = `2n` bytes: 32 / 32 / 48 / 48 / 64 / 64.
- Signature = `(1 + k(1+a) + h + d·len)·n` bytes (the `R || SIG_FORS || SIG_HT`
  layout). The constant `1` is the randomizer `R` (n bytes); `SIG_FORS` is
  `k(1+a)·n`; `SIG_HT` is `(h + d·len)·n`.
- Message digest `m = ceil((h - h')/8) + ceil(h'/8) + ceil(k·a/8)` bytes
  (matches the Table 2 `m` column; note `h' = h/d`).

Implementation rule: encode the **six** `(n, h, d, h', a, k, lg_w)` rows once and
derive `m`, `len`, `pk`, `sig`, and the FORS/HT sub-sizes. The SHA2 and SHAKE
variants of a given size share all of these; only the hash family differs.

## Cryptographic Primitive Inventory and Gaps

SLH-DSA is built from six "tweakable" hash functions plus the message hash.
Their signatures (all operate on byte strings):

| Function  | Signature                                           | Output  | Used by                                 |
| --------- | --------------------------------------------------- | ------- | --------------------------------------- |
| `H_msg`   | `(R, PK.seed, PK.root, M)`                          | m bytes | Message digest in sign/verify.          |
| `PRF`     | `(PK.seed, SK.seed, ADRS)`                          | n bytes | WOTS+ and FORS secret-value generation. |
| `PRF_msg` | `(SK.prf, opt_rand, M)`                             | n bytes | Randomizer `R` generation.              |
| `F`       | `(PK.seed, ADRS, M1)` (n-byte input)                | n bytes | WOTS+ chains, FORS leaves.              |
| `H`       | `(PK.seed, ADRS, M2)` (2n-byte input)               | n bytes | Merkle tree internal nodes.             |
| `T_len`   | `(PK.seed, ADRS, Ml)` (len·n input; `T_k` for FORS) | n bytes | WOTS+ and FORS root compression.        |

What the repo has versus needs:

| Primitive                | Used by                     | Status and evidence                              |
| ------------------------ | --------------------------- | ------------------------------------------------ |
| `KeccakXof` / `shake256` | SHAKE sets                  | Present; direct and composition tests pass.      |
| `sha256` one-shot        | SHA-2 sets                  | Present; direct FIPS 180-4 tests pass.           |
| `sha512` one-shot        | SHA-2 categories 3 and 5    | Present; direct FIPS 180-4 tests pass.           |
| `Trunc_n`                | SHA-2 sets                  | Present in the SLH-DSA utility layer.            |
| `HMAC-SHA-256/512`       | SHA-2 `PRF_msg`             | Present; RFC 4231 tests pass.                    |
| `MGF1-SHA-256/512`       | SHA-2 `H_msg`               | Present; RFC 8017-derived tests pass.            |
| 32-byte `ADRS`           | SHAKE sets                  | Present; Table 1 member tests pass.              |
| 22-byte `ADRS^c`         | SHA-2 sets                  | Present; compressed-address tests pass.          |

This inventory explains the SHAKE-first implementation order. The independent
primitive gates are now closed, so both families share the same v0.4.0
development release boundary.

## The Two Hash-Function Families

The functions above are instantiated differently per family (FIPS 205 §11). Get
these byte-exact; they are the most error-prone surface after addressing.

### SHAKE instantiation (all six SHAKE sets)

The 32-byte `ADRS` is used directly. `8m` and `8n` are bit lengths.

```text
H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)
PRF(PK.seed, SK.seed, ADRS)   = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
PRF_msg(SK.prf, opt_rand, M)  = SHAKE256(SK.prf || opt_rand || M, 8n)
F(PK.seed, ADRS, M1)          = SHAKE256(PK.seed || ADRS || M1, 8n)
H(PK.seed, ADRS, M2)          = SHAKE256(PK.seed || ADRS || M2, 8n)
T_len(PK.seed, ADRS, Ml)      = SHAKE256(PK.seed || ADRS || Ml, 8n)
```

### SHA-2 instantiation, security category 1 (`*-128s`, `*-128f`, n=16)

Uses the 22-byte `ADRS^c`. `Trunc_n` keeps the leftmost n bytes.
`toByte(0, 64-n)` is `64-n` zero bytes (the SHA-256 block-size pad).

```text
H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
PRF(PK.seed, SK.seed, ADRS)   = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRS^c || SK.seed))
PRF_msg(SK.prf, opt_rand, M)  = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M))
F(PK.seed, ADRS, M1)          = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRS^c || M1))
H(PK.seed, ADRS, M2)          = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRS^c || M2))
T_len(PK.seed, ADRS, Ml)      = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRS^c || Ml))
```

### SHA-2 instantiation, security categories 3 and 5 (`*-192*`, `*-256*`, n=24/32)

`H`, `T_len`, `H_msg`, and `PRF_msg` move to SHA-512 (with a `128-n` pad), but
`PRF` and `F` **stay on SHA-256** with the `64-n` pad. This split is the single
most likely transcription error; pin it with a per-function test.

```text
H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)
PRF(PK.seed, SK.seed, ADRS)   = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n)  || ADRS^c || SK.seed))   # SHA-256
PRF_msg(SK.prf, opt_rand, M)  = Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))
F(PK.seed, ADRS, M1)          = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n)  || ADRS^c || M1))         # SHA-256
H(PK.seed, ADRS, M2)          = Trunc_n(SHA-512(PK.seed || toByte(0, 128-n) || ADRS^c || M2))         # SHA-512
T_len(PK.seed, ADRS, Ml)      = Trunc_n(SHA-512(PK.seed || toByte(0, 128-n) || ADRS^c || Ml))         # SHA-512
```

`MGF1` and `HMAC` definitions to vendor:

- `MGF1-Hash(seed, maskLen)` (RFC 8017 Appendix B.2.1): `T = ""`; for
  `counter = 0 .. ceil(maskLen/hLen)-1`: `T = T || Hash(seed || I2OSP(counter, 4))`;
  return `Trunc_{maskLen}(T)`.
- `HMAC-Hash(key, text)` (FIPS 198-1 / RFC 2104): standard ipad/opad with the
  hash's block size (64 bytes for SHA-256, 128 bytes for SHA-512).

## Addressing (`ADRS` and `ADRS^c`)

`ADRS` is a 32-byte structure conforming to 4-byte words, big-endian:

```text
[ layer address (4) | tree address (12) | type (4) | type-specific (12) ]
```

Seven address types (the `type` word):

| Constant     | Value | Used when                           |
| ------------ | ----- | ----------------------------------- |
| `WOTS_HASH`  | 0     | Hashing within WOTS+ chains.        |
| `WOTS_PK`    | 1     | Compressing a WOTS+ public key.     |
| `TREE`       | 2     | Hashing within an XMSS Merkle tree. |
| `FORS_TREE`  | 3     | Hashing within a FORS tree.         |
| `FORS_ROOTS` | 4     | Compressing the k FORS tree roots.  |
| `WOTS_PRF`   | 5     | Generating WOTS+ secret values.     |
| `FORS_PRF`   | 6     | Generating FORS secret values.      |

Rule: whenever `type` changes, the final 12 bytes are zeroed
(`setTypeAndClear`). Implement the member functions exactly (FIPS 205 Table 1):
`setLayerAddress`, `setTreeAddress`, `setTypeAndClear`, `setKeyPairAddress`,
`setChainAddress`/`setTreeHeight`, `setHashAddress`/`setTreeIndex`,
`getKeyPairAddress`, `getTreeIndex`.

For SHA-2 sets, the functions consume a **22-byte compressed** `ADRS^c`
(FIPS 205 Figure 18, Table 3):

```text
ADRS^c = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
         (layer 1B) (tree 8B)    (type 1B)  (last 12B)      = 22 bytes
```

The compressed member-function byte offsets differ from the 32-byte version and
must follow Table 3 (e.g. `getTreeIndex` reads `ADRS^c[18:22]`, not
`ADRS[28:32]`). Implement both layouts behind one `Adrs` abstraction with a
`compressed` flag, and unit-test the offset math against both tables.

## Message Digest and Index Splitting

`slh_sign_internal` (Algorithm 19) and `slh_verify_internal` (Algorithm 20)
derive the FORS message and the hypertree indices from the `m`-byte digest:

```text
R       = PRF_msg(SK.prf, opt_rand, M)          # opt_rand = addrnd (hedged) or PK.seed (deterministic)
digest  = H_msg(R, PK.seed, PK.root, M)         # m bytes
md          = digest[0 : ceil(k*a/8)]                                  # FORS message
tmp_idxtree = digest[ceil(k*a/8) : ceil(k*a/8) + ceil((h-h')/8)]
tmp_idxleaf = digest[ceil(k*a/8) + ceil((h-h')/8) : ... + ceil(h/(8d))]
idx_tree = toInt(tmp_idxtree, ceil((h-h')/8)) mod 2^(h-h')
idx_leaf = toInt(tmp_idxleaf, ceil(h/(8d)))   mod 2^(h/d)
SIG = R || fors_sign(md, ...) || ht_sign(PK_FORS, ..., idx_tree, idx_leaf)
```

The `base_2b(md, a, k)` extraction of the `k` FORS indices from `md` is exactly
the part that changed between SPHINCS+ v3 and FIPS 205 (Appendix A). Pin it with
an ACVP `sigGen` intermediate test.

## Implementation Architecture

Target package structure:

```text
lib/src/common/
  hmac.dart           # NEW: HMAC-SHA-256/512 (FIPS 198-1) - SHA-2 sets only
  mgf1.dart           # NEW: MGF1-SHA-256/512 (RFC 8017)   - SHA-2 sets only
lib/src/algos/slhdsa/
  params.dart         # 12 parameter sets, derived sizes, security categories, hash family
  util.dart           # toInt, toByte, base_2b, Trunc_n, gen_len2
  address.dart        # ADRS (32B) and ADRS^c (22B), 7 types, member functions
  hashing.dart        # H_msg, PRF, PRF_msg, F, H, T_len for SHAKE and SHA-2 families
  wots.dart           # Algorithms 5-8 (chain, pkGen, sign, pkFromSig)
  xmss.dart           # Algorithms 9-11 (node, sign, pkFromSig)
  hypertree.dart      # Algorithms 12-13 (ht_sign, ht_verify)
  fors.dart           # Algorithms 14-17 (skGen, node, sign, pkFromSig)
  slhdsa.dart         # Algorithms 18-25 (internal + external SLH-DSA / HashSLH-DSA)
```

Keep `lib/pqcrypto.dart` exports minimal:

- Export the supported external API types only (`SlhDsa`, `SlhDsaParams`,
  `SlhDsaParameter`).
- Do **not** export WOTS+, XMSS, hypertree, FORS, the address structure, or the
  internal seeded functions as normal user APIs. Tests import them from `src/`
  directly.

## Public API Target

The release API should make safe use easy and unsafe use explicit, defaulting to
the fast parameter set and a hedged randomizer:

```dart
// Recommended default for interactive / general use.
final params = SlhDsaParams.shake128f;
final (pk, sk) = SlhDsa.generateKeyPair(params);
final sig = SlhDsa.sign(sk, message, params, context: contextBytes); // hedged by default
final ok  = SlhDsa.verify(pk, message, sig, params, context: contextBytes);
```

Required API behavior:

| Function                          | Requirement                                                                                                      |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `generateKeyPair`                 | External keygen (Algorithm 21). Fresh `SK.seed`, `SK.prf`, `PK.seed` from secure randomness; `PK.root` computed. |
| `generateKeyPairSeeded`           | Internal/test utility (Algorithm 18). Takes the three n-byte seeds; deterministic. Not the normal API.           |
| `sign`                            | External pure sign (Algorithm 22). Hedged by default (fresh `addrnd`); `ctx` length-checked (<= 255).            |
| `signDeterministic`               | Explicit deterministic variant (`opt_rand = PK.seed`). Documented as fault-amplifying; not the default.          |
| `verify`                          | External pure verify (Algorithm 24). Returns `false` for wrong length/ctx; never throws for untrusted input.     |
| `hashSign` / `hashVerify`         | HashSLH-DSA (Algorithms 23/25). Pre-hash `M` with an approved PH and prepend its DER OID.                        |
| `signInternal` / `verifyInternal` | Internal core (Algorithms 19/20) for ACVP KATs; take a fixed `addrnd`/pre-formatted `M'`.                        |

Opinionated surface (adopted): expose the parameter sets as a
named enum and steer callers to `shake128f`. Gate the `s` variants behind an
explicit acknowledgement so a developer must opt in to slow signing:

```dart
// 's' variants require explicit acknowledgement of the latency/web caveat.
final sig = SlhDsa.sign(sk, message, SlhDsaParams.shake128s,
    allowSlowSigning: true); // throws UnsupportedError without this flag
```

Context and pre-hash formatting (FIPS 205 §10.2):

```text
pure:     M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
pre-hash: M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)
```

HashSLH-DSA pre-hash OIDs exercised by the ACVP corpus (DER, 11 bytes each):

| PH           | DER OID (hex)            | PH(M) bytes |
| ------------ | ------------------------ | ----------: |
| SHA2-224     | `0609608648016503040204` |          28 |
| SHA2-256     | `0609608648016503040201` |          32 |
| SHA2-384     | `0609608648016503040202` |          48 |
| SHA2-512     | `0609608648016503040203` |          64 |
| SHA2-512/224 | `0609608648016503040205` |          28 |
| SHA2-512/256 | `0609608648016503040206` |          32 |
| SHA3-224     | `0609608648016503040207` |          28 |
| SHA3-256     | `0609608648016503040208` |          32 |
| SHA3-384     | `0609608648016503040209` |          48 |
| SHA3-512     | `060960864801650304020A` |          64 |
| SHAKE-128    | `060960864801650304020B` |          32 |
| SHAKE-256    | `060960864801650304020C` |          64 |

FIPS 205 Section 10.2 requires the selected pre-hash to provide sufficient
collision and second-preimage strength for the selected SLH-DSA parameter set.
The enum exposes the complete ACVP mechanics; application policy must reject
security-inappropriate combinations before public release.

## Algorithm-by-Algorithm Work Plan

| FIPS item     | Implementation work                                                                            | Tests required                                                                |
| ------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Alg 1         | `gen_len2`; assert it returns 3 for all sets; precompute.                                      | Equality test against Table 2 derived `len`.                                  |
| Alg 2-3       | `toInt`, `toByte` big-endian conversions (no floating point).                                  | Exhaustive small values; round-trip.                                          |
| Alg 4         | `base_2b` (used for WOTS+ with `b=lg_w` and FORS with `b=a`).                                  | Vector tests for both `b` values; the FORS index extraction.                  |
| Alg 5-8       | WOTS+ `chain`, `pkGen`, `sign`, `pkFromSig`; the checksum `csum` left-shift per Appendix A.    | Per-set WOTS+ pk and sig vectors; checksum boundary.                          |
| Alg 9-11      | XMSS `node` (recursive), `sign` (auth path), `pkFromSig`.                                      | XMSS root from sig; auth-path index parity (`floor(idx/2^j)`).                |
| Alg 12-13     | Hypertree `ht_sign` (d stacked XMSS), `ht_verify` (return bool).                               | HT round-trip; layer index shifting (`idx_tree >> h'`).                       |
| Alg 14-17     | FORS `skGen`, `node`, `sign`, `pkFromSig`; `FORS_PRF`/`FORS_TREE` addressing.                  | FORS pk from sig; per-tree index `i·2^a + indices[i]`.                        |
| Alg 18        | Internal keygen: `xmss_node` at layer `d-1` for `PK.root`; bundle SK/PK.                       | ACVP `keyGen` byte-exact pk/sk.                                               |
| Alg 19        | Internal sign: `opt_rand` select, `R`, `H_msg`, digest split, FORS sign, HT sign.              | ACVP `sigGen` byte-exact (hedged with given `addrnd`, and deterministic).     |
| Alg 20        | Internal verify: exact length check first, recompute digest/indices, FORS pk, `ht_verify`.     | ACVP `sigVer` accept/reject; malformed length returns false before parse.     |
| Alg 21        | External keygen: fresh RBG for `SK.seed`/`SK.prf`/`PK.seed`; single error path on RBG failure. | Key sizes; deterministic equivalence to seeded; RBG smoke test.               |
| Alg 22        | External pure sign: `ctx<=255`, hedged `addrnd`, `M'` (domain 0x00).                           | Round-trip; ctx empty/nonempty/too-long; hedged sigs differ but verify.       |
| Alg 23        | External pre-hash sign: switch on PH, prepend OID, `M'` (domain 0x01).                         | HashSLH-DSA round-trip per PH; wrong-PH fails; cat-1-only PH enforced.        |
| Alg 24-25     | External pure/pre-hash verify: build `M'`, call internal verify.                               | Wrong context fails; pure vs pre-hash domain separation.                      |
| Hashing       | `H_msg`, `PRF`, `PRF_msg`, `F`, `H`, `T_len` for both families; `Trunc_n`; SHA-256/512 split.  | Per-function intermediate vectors; the cat 3/5 SHA-256-vs-SHA-512 split test. |
| HMAC          | `HMAC-SHA-256/512` standalone.                                                                 | RFC 4231 KATs (independent gate before composition).                          |
| MGF1          | `MGF1-SHA-256/512` standalone.                                                                 | RFC 8017 / known MGF1 vectors (independent gate before composition).          |
| Address       | `ADRS` (32B) and `ADRS^c` (22B), 7 types, member functions for both tables.                    | Offset tests for Table 1 and Table 3; `setTypeAndClear` zeroes tail.          |

## Randomness Requirements

Key generation (Algorithm 21):

- Generate fresh `SK.seed`, `SK.prf`, and `PK.seed`, each n bytes, from an
  approved RBG. FIPS 205 §3.1 requires the RBG security strength to be at least
  `8n` bits (128/192/256 for n = 16/24/32).
- In this pure Dart package, `Random.secure()` is the implementation source of
  randomness, but that is not a repo-level SP 800-90 validation claim.
- On RBG failure, return a single error indication (`null`/throw) with no partial
  key output.

Signing (Algorithm 19/22/23):

- Hedged is the default: `addrnd` is a fresh n-byte random value, and
  `opt_rand = addrnd`. Hedged signing should be used wherever side-channel or
  fault attacks are a concern.
- Deterministic signing sets `opt_rand = PK.seed` (no `addrnd`). It is available
  for platforms without an RBG, but it **amplifies fault attacks** (a repeated
  signature lets an attacker collect faulted variants of the same computation).
  Make it explicit (`signDeterministic`), never the default, and document the
  risk inline.

Testing:

- ACVP/KAT tests need deterministic access to the three keygen seeds and to
  `addrnd`. Production APIs must not require the user to supply `addrnd`.

## Verification and Malformed Input Rules

Verification consumes attacker-controlled data and must be defensive:

| Input      | Required behavior                                                                            |     |                                                                                               |
| ---------- | -------------------------------------------------------------------------------------------- | --- | --------------------------------------------------------------------------------------------- |
| Signature  | If `                                                                                         | SIG | != (1 + k(1+a) + h + d·len)·n`, return false before any`sublist`/parse (Algorithm 20 line 1). |
| Public key | If length != `2n`, return false before decode.                                               |     |                                                                                               |
| Context    | If longer than 255 bytes, return false (verify) or throw (sign) per the public API contract. |     |                                                                                               |
| Pre-hash   | A pure signature must not verify as pre-hash and vice versa (domain byte 0x00 vs 0x01).      |     |                                                                                               |
| Parameter  | Do not verify a signature under a different parameter set than it was produced for.          |     |                                                                                               |

Recommended contract: `verify`/`hashVerify` return `false` for all untrusted
malformed inputs; `sign`/`generateKeyPair` throw typed argument errors for
caller misuse; internal test helpers may throw.

## Side-Channel and Fault Posture

The threat model for a hash-based scheme differs sharply from ML-DSA, and the
guide should say so plainly so effort lands where it matters.

What is largely **theater** here (unlike ML-DSA):

- Constant-time secret-dependent branching. SLH-DSA has no rejection-sampling
  loop whose iteration count depends on secret data. WOTS+ chain lengths and
  FORS leaf selection derive from the **public** message digest, not from
  long-term secret key material. Pure-Dart timing hardening of the hash calls
  themselves buys little; the Keccak/SHA-2 cores are already data-oblivious in
  structure.

What genuinely **matters** (the real tails):

1. **Fault / grafting attacks.** A single faulted hash during WOTS+ chain or
   FORS/Merkle computation can yield a universal forgery (the "grafting trees"
   class). Mitigations: hedged randomizer by default; optionally re-verify a
   freshly generated signature before returning it in a high-assurance mode;
   document the residual risk for embedded/mobile targets.
2. **RBG quality.** A weak or reused randomizer silently destroys security with
   no observable symptom. Enforce fresh `addrnd` per signature in hedged mode;
   never reuse. Treat the RBG strength (>= 8n bits) as a documented assumption.
3. **Secret-material lifetime.** Zeroize `SK.seed`, `SK.prf`, the per-call
   WOTS+/FORS secret nodes, and `R` after use, using `secureZero` in `finally`
   blocks. Dart GC makes this best-effort, not a hard erasure proof; document
   that honestly.

Minimum release hardening checklist:

1. Hedged signing is the default; deterministic is an explicit, documented
   opt-in.
2. Zeroize secret seeds and per-call secret nodes in `finally` blocks.
3. Keep `print()` and debug traces out of `lib/`.
4. Provide an optional verify-after-sign mode for fault resistance.
5. Document the fault-attack residual and the RBG-strength assumption in
   [SECURITY_AUDIT.md](SECURITY_AUDIT.md) with a tracking ID.

## BUFF / Message-Bound Signature Risk

FIPS 205 §11 is explicit: SLH-DSA does **not** provide the message-bound
signature (BUFF) property under EUF-CMA for any parameter set except
`*-128f`. Because `H_msg` output is only `m` bytes, a key-pair **owner** could
find an `H_msg` collision and produce one signature valid for two different
messages — a repudiation/fraud vector in payment, consent, and credential
workflows. The cost of finding such a collision is below the claimed security
category for every set except the `128f` pair.

This is a liability disclosure, not a footnote. It must appear in three places:
the `sign()` Dart docstring, the top-level `SlhDsa` class docstring, and the
first screen of the README. Use this exact wording:

```text
SECURITY NOTICE - SLH-DSA does not provide message binding (the BUFF property,
FIPS 205 §11). A single signature may be mathematically valid for more than one
message in certain adversarial contexts. If your application uses signatures to
authorize actions, transfers, or consents, you MUST include a unique application
context string and a nonce in the signed payload. The library cannot enforce
this - you are responsible for binding signatures to their intended
authorization context.
```

Design implication: the `context` parameter and application-level nonces are the
developer's tool for binding. Encourage non-empty contexts in the examples and
never show a README example that signs a raw, unbound message.

## Performance Reality and Parameter Guidance

SLH-DSA is large and slow by design. The `s` variants perform on the order of
10^5-10^6 tweakable-hash calls per signature; the `f` variants are faster but
emit larger signatures. In pure Dart - especially under dart2js and dart2wasm -
the `s` variants are unlikely to be acceptable for interactive use.

| Concern           | Guidance for the release docs                                                                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Default set       | `SLH-DSA-SHAKE-128f`. Smallest credible category-1 stateless set with tractable signing.                                                                      |
| `s` on web/mobile | Explicitly discouraged. Gate behind `allowSlowSigning: true`; document "may take seconds".                                                                    |
| Signature size    | 7.8 KB - 49.9 KB. These do not fit TLS/JWT/SSH without custom negotiation; say so.                                                                            |
| Benchmarks        | Publish at least one keygen/sign/verify benchmark per parameter set on VM + dart2js + dart2wasm.                                                              |
| Use cases         | Position SLH-DSA as the conservative, hash-only backup signature: firmware/artifact/long-term signing, offline use - not high-throughput interactive signing. |

Publishing real per-target benchmark numbers is a **release gate** for the
SLH-DSA claim, because the performance framing depends on measured, not
estimated, latency.

## KAT Corpus Plan and Provenance

This is the highest-leverage correctness control. "Wrong/old test vectors" are
the single most likely way this ships something subtly wrong.

Rules:

- **Source: NIST ACVP `SLH-DSA` vectors only** (`SLH-DSA-keyGen`,
  `SLH-DSA-sigGen`, `SLH-DSA-sigVer`). These are the authoritative,
  FIPS-205-aligned vectors. Check them into `test/data/SLHDSA/` with a README
  documenting the exact commit/source.
- **Do not** use SPHINCS+ round-3 reference KATs. The FORS bit-extraction and
  the WOTS+ checksum shift changed between SPHINCS+ v3 and FIPS 205; a match
  against v3 vectors would validate the wrong algorithm.
- **Vendored-primitive gates first.** HMAC against RFC 4231 and MGF1 against
  RFC 8017 vectors must be green before the SHA-2 SLH-DSA sets are wired up.
- **Cross-verify** with an independent FIPS 205 implementation (SPHINCS+
  reference once aligned to the standard, liboqs, or OpenSSL 3.5+) where
  feasible, as a second, non-NIST check.

Format note: the NIST ACVP vectors are **ACVP-JSON** (`prompt.json` +
`expectedResults.json` per test group), not the `.rsp` format used by the ML-DSA
corpus. The discovered VM-only runner parses ACVP-JSON directly and pairs
groups/cases by `tgId`/`tcId`, preserving upstream provenance.

Checked-in layout and implementation runner:

```text
test/data/SLHDSA/
  README.md                         # pinned commit, coverage, hashes, NIST notice
  SLH-DSA-keyGen-FIPS205/           # prompt.json + expectedResults.json
  SLH-DSA-sigGen-FIPS205/           # all 12 sets and interface/mode groups
  SLH-DSA-sigVer-FIPS205/           # positive and negative verification cases
```

| Runner                              | Purpose                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------- |
| `test/slhdsa_acvp_corpus_test.dart` | Pinned hashes, ACVP pairing/schema, all-set coverage, and case counts.          |
| `test/slhdsa_kat_test.dart`         | Discovered ACVP-JSON runner: keyGen/sigGen/sigVer byte-exact, per set. VM-only. |
| `test/slhdsa_wots_test.dart`        | WOTS+ chain/pkGen/sign/pkFromSig component vectors.                             |
| `test/slhdsa_xmss_ht_test.dart`     | XMSS node/sign/pkFromSig and hypertree round-trips.                             |
| `test/slhdsa_fors_test.dart`        | FORS skGen/node/sign/pkFromSig and the digest index extraction.                 |
| `test/slhdsa_hashing_test.dart`     | H_msg/PRF/PRF_msg/F/H/T_len per family; the SHA-256/512 split.                  |
| `test/slhdsa_address_test.dart`     | `ADRS` (Table 1) and `ADRS^c` (Table 3) member-function offsets.                |
| `test/slhdsa_api_test.dart`         | External round-trips, ctx, pre-hash, hedged vs deterministic, `s`-gating.       |
| `test/slhdsa_negative_test.dart`    | Malformed length, wrong ctx, pure/pre-hash confusion, cross-parameter verify.   |
| `test/hmac_test.dart`               | HMAC-SHA-256/512 against RFC 4231.                                              |
| `test/mgf1_test.dart`               | MGF1-SHA-256/512 against RFC 8017.                                              |

KAT runner requirements (same discipline as ML-DSA): run under plain `dart
test`; no machine-local paths; print no secrets; assert exact byte equality for
pk/sk/sig and the verify boolean; provide deterministic vectors via fixed
`addrnd`.

> **The `/PQC/KAT` `XMSS/` and `LMS/` folders do not test SLH-DSA.** They are
> NIST ACVP vectors for **SP 800-208 stateful** hash-based signatures (RFC 8391
> XMSS / RFC 8554 LMS). FIPS 205 footnote 2 states the WOTS+/XMSS schemes used
> _inside_ SLH-DSA are **not the same** as RFC 8391/SP 800-208. Those vectors are
> valuable for a separate, future stateful-HBS workstream (see
> [Appendix B](#appendix-b---relationship-to-sp-800-208-lmsxmss)), but they must
> **not** be copied into `test/data` to validate SLH-DSA.

## Platform Validation Matrix

Before upgrading a SLH-DSA parameter set from experimental to supported:

| Platform gate   | Command                                             | Required result                                            |
| --------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| Static analysis | `dart analyze`                                      | Exit 0; no production warnings.                            |
| Full VM suite   | `dart test`                                         | Passes, including the SLH-DSA KAT runner.                  |
| Focused SLH-DSA | `dart test test/slhdsa_*_test.dart`                 | Passes locally and in CI.                                  |
| Web JS          | `dart test -p chrome`                               | Passes (file-based KAT runner is VM-only and auto-skips).  |
| Web Wasm        | `dart test -p chrome --compiler dart2wasm`          | Passes; verify 64-bit-safe integer math in hashing.        |
| Benchmarks      | `dart run tool/bench/slhdsa_bench.dart` (VM + web)  | At least one number per claimed set per target, published. |
| Format/lint     | `dart format --output=none --set-exit-if-changed .` | Passes.                                                    |
| Markdown lint   | `npx -y markdownlint-cli2 "**/*.md"`                | Passes.                                                    |

Web-specific risk: SLH-DSA arithmetic is byte/hash oriented (no field
multiplication), so the ML-DSA `2^53` integer concern is largely absent. The
real web risk is **time**: confirm even `128f` keygen/sign/verify complete within
a tolerable budget under dart2js/dart2wasm, and document the numbers.

## Release Milestones

### M0 - Freeze the standard map (complete)

- Add this guide to [INDEX.md](INDEX.md), [ROADMAP.md](ROADMAP.md),
  [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md), [ARCHITECTURE.md](ARCHITECTURE.md),
  [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md), and [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
- File the GitHub issue set (epic + components; see
  [Appendix D](#appendix-d---github-issue-map)).
- Acquire and check in the NIST ACVP SLH-DSA vectors with provenance README.

Exit gate: markdown lint green; docs say SLH-DSA is in active development and not
yet shipped.

### M1 - Shared scaffolding (params, util, address, hashing-SHAKE) (complete)

- Implement `params.dart` (12 sets, derived sizes), `util.dart`
  (`toInt`/`toByte`/`base_2b`/`Trunc_n`/`gen_len2`), `address.dart` (`ADRS` 32B +
  member functions), and the **SHAKE** instantiation of the six hash functions.

Exit gate: `dart test test/slhdsa_address_test.dart test/slhdsa_hashing_test.dart`
(SHAKE), parameter-size test green.

### M2 - WOTS+, XMSS, hypertree, FORS (SHAKE) (complete)

- Implement Algorithms 5-17 against the SHAKE hashing.

Exit gate: component round-trip tests green
(`slhdsa_wots_test`, `slhdsa_xmss_ht_test`, `slhdsa_fors_test`).

### M3 - SLH-DSA internal + external (SHAKE) and ACVP KAT (complete)

- Implement Algorithms 18-25, the digest/index split, context and HashSLH-DSA
  formatting, hedged default, `s`-gating, and the discovered ACVP-JSON runner.

Exit gate: `dart test test/slhdsa_kat_test.dart` byte-exact for all six SHAKE
sets; negative tests green.

### M4 - SHAKE hardening, perf, cross-platform, and v0.4.0 release

- Completed engineering controls: zeroization, verify-after-sign, minimal
  external export, benchmarks per target, BUFF/performance docs, and
  README/changelog updates.
- Completed release verification: decomposed VM matrix, both web compiler
  suites, formatting, analysis, Markdown lint, and package publication
  preflight.
- Completed release visibility: the canonical manifest, generated site,
  AI-discovery files, and agent rules distinguish the published 0.3.1 surface
  from the six-set SLH-DSA development release candidate.
- Remaining maintainer controls: release metadata/versioning, tag, and actual
  publication.

Exit gate: full platform matrix green; `dart pub publish --dry-run` clean; the
SHAKE sets land in the v0.4.0 candidate (the SHA-2 family is added in M5-M8, also
v0.4.0).

### M5 - Vendor and independently KAT-gate HMAC + MGF1 (complete)

- Implement `lib/src/common/hmac.dart` and `lib/src/common/mgf1.dart`.

Exit gate: `dart test test/hmac_test.dart test/mgf1_test.dart` green against RFC
4231 / RFC 8017 **before** any SHA-2 SLH-DSA wiring.

### M6 - SHA-2 hashing (incl. `ADRS^c` and the SHA-256/512 split) (complete)

- Add the `ADRS^c` (22B) layout and the SHA-2 instantiation of all six hash
  functions for categories 1 and 3/5.

Exit gate: `slhdsa_hashing_test` (SHA-2) and `slhdsa_address_test` (`ADRS^c`)
green; the cat 3/5 SHA-256-vs-SHA-512 split is pinned by test.

### M7 - SHA-2 SLH-DSA and ACVP KAT (all 12), v0.4.0 (complete)

- Wire the six SHA-2 sets through the existing component/SLH-DSA code via the
  hash-family abstraction; extend the ACVP runner.

Exit gate: `dart test test/slhdsa_kat_test.dart` byte-exact for all 12 sets; full
platform matrix green; the SHA-2 sets ship in v0.4.0 alongside the SHAKE sets.

### M8 - Cross-verification and consolidation (complete)

- Cross-verify against liboqs/OpenSSL 3.5+ where feasible; finalize
  SECURITY_AUDIT entries; reconcile ROADMAP/PROGRESS_TRACKER.

Exit gate: cross-impl agreement documented or explicitly deferred with rationale.

## Documentation Release Rules

Before the SLH-DSA v0.4.0 release (all 12 sets):

- [README.md](../README.md) links this guide, states the exact SLH-DSA support
  boundary, and carries the BUFF + performance notices on the first screen.
- [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md) distinguishes SLH-DSA algorithm
  evidence from FIPS 140 validation, and lists which parameter sets are claimed.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) closes or defers every SLH-DSA finding
  (fault residual, RBG assumption, zeroization best-effort) with a tracking ID.
- [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) shows each SLH-DSA gate.
- [ROADMAP.md](ROADMAP.md) reflects the all-12 v0.4.0 boundary (SHAKE-first
  sequencing recorded as history).
- [CHANGELOG.md](../CHANGELOG.md) lists the KAT corpus provenance, the claimed
  parameter sets, API behavior, and the BUFF/performance limitations.

## Definition of Done

SLH-DSA is releasable for v0.4.0 when this checklist is complete for all 12
parameter sets.

v0.4.0 release (all 12 sets):

- [x] `SlhDsaParams` encodes all 12 sets with derived sizes from one source of
      truth; size tests pass.
- [x] `toInt`/`toByte`/`base_2b`/`Trunc_n`/`gen_len2` implemented and tested.
- [x] `ADRS` (32-byte) and the seven types with member functions match Table 1.
- [x] SHAKE instantiation of `H_msg`/`PRF`/`PRF_msg`/`F`/`H`/`T_len` is
      implemented and pinned by independent SHAKE vectors; ACVP composition
      evidence remains part of the release gate below.
- [x] Official NIST ACVP corpus pinned with provenance, SHA-256 integrity,
      ACVP schema/coverage checks, and all 1,248 sample cases.
- [x] WOTS+, XMSS, hypertree, FORS (Algorithms 5-17) implemented; component
      round-trips green; components are not public APIs.
- [x] SLH-DSA internal + external (Algorithms 18-25); hedged default;
      deterministic explicit; `s` variants gated by `allowSlowSigning`.
- [x] Context (<= 255) and HashSLH-DSA formatting cover all 12 ACVP PH/OID
      choices; security-appropriate PH selection remains a public-policy gate.
- [x] Verify does the exact `|SIG|` length check before parsing and returns a
      boolean for untrusted input.
- [x] Byte-exact against the checked-in NIST ACVP SLH-DSA vectors for all 12
      sets (keyGen/sigGen/sigVer) under `dart test`.
- [x] Negative tests: malformed length, wrong ctx, pure/pre-hash confusion.
- [x] Secret material zeroized in `finally` blocks (best-effort, documented).
- [x] BUFF notice and performance guidance in `sign()` docstring, class
      docstring, and README first screen; default is `shake128f`.
- [x] At least one keygen/sign/verify benchmark per set per target published.
- [x] `dart analyze` exits 0; the decomposed VM matrix and dart2js/dart2wasm
      gates are green; `dart format` and changed-file markdownlint are clean.
- [x] Docs and changelog evidence-scoped; no CMVP/FIPS 140 claim.
- [x] Generated visibility and agent-discovery surfaces identify all 12 sets as
      an unpublished development release candidate.

SHA-2 family (also required for v0.4.0):

- [x] `HMAC-SHA-256/512` vendored and byte-exact against RFC 4231 (independent
      gate).
- [x] `MGF1-SHA-256/512` vendored and byte-exact against RFC 8017 (independent
      gate).
- [x] `ADRS^c` (22-byte) member functions match Table 3.
- [x] SHA-2 instantiation exact, including the cat 3/5 SHA-256 (`PRF`, `F`) vs
      SHA-512 (`H`, `T_len`, `H_msg`, `PRF_msg`) split, pinned by test.
- [x] Byte-exact against ACVP vectors for all six SHA-2 sets.
- [x] All 12 sets pass the full platform matrix.

Residual / deferred (do not block KAT conformance; track in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md)):

- Fault/grafting resistance is best-effort; verify-after-sign is optional, not a
  proof. Hardware fault attacks on mobile/embedded remain out of scope.
- Constant-time guarantees are not provided in pure Dart; the scheme's
  secret-dependent timing surface is small, but not formally zero.
- Zeroization is best-effort under Dart GC, not hard memory erasure.
- A CMVP/FIPS 140 module validation is out of scope and not claimed.
- The release version tag and `dart pub publish` are not yet done.

## Appendix A - Differences From the SPHINCS+ Submission

FIPS 205 §A documents the changes from the SPHINCS+ v3.1 submission. These are
exactly the places where reasoning from SPHINCS+ reference code produces
plausible-but-wrong output, so they are correctness traps:

- Two new address types, `WOTS_PRF` (5) and `FORS_PRF` (6), for secret-value
  generation.
- `PK.seed` was added as an input to `PRF` (multi-key attack mitigation).
- For category 3 and 5 SHA-2 sets, SHA-256 was **replaced by SHA-512** in
  `H_msg`, `PRF_msg`, `H`, and `T_len` (but **not** `PRF` or `F`).
- `R` and `PK.seed` were added as inputs to MGF1 inside `H_msg` for the SHA-2
  sets (multi-target long-message second-preimage mitigation).
- The method for **extracting FORS indices from the message digest** changed
  (to align with the reference implementation). Using SPHINCS+ v3 vectors will
  not match.
- Line 6 of `wots_sign` and `wots_pkFromSig` (the `csum` left-shift) was changed
  to match the reference; the original pseudocode shifted by the wrong amount
  when `lg_w != 4` (not an issue here since `lg_w = 4`, but encode it correctly).
- Only the 12 "simple" instances are approved (no "robust" variants).

## Appendix B - Relationship to SP 800-208 LMS/XMSS

The `/PQC/KAT` workspace contains NIST ACVP vectors for **LMS** (RFC 8554) and
**XMSS** (RFC 8391), which are **stateful** hash-based signatures standardized
by NIST SP 800-208 - a different standard and a different algorithm family from
FIPS 205 SLH-DSA.

Key distinctions:

- LMS/XMSS are **stateful**: each signature consumes a one-time key and the
  signer must persist state; reusing state breaks security. SLH-DSA is
  **stateless** by construction (the hypertree + FORS + randomized index
  selection remove the state requirement).
- The XMSS in SP 800-208 is **RFC 8391 XMSS**, whose WOTS+/addressing/tweakable
  hashes differ from the XMSS _component_ inside SLH-DSA (FIPS 205 footnote 2).
  The SP 800-208 vectors cannot validate SLH-DSA's internal XMSS.

Therefore: the LMS/XMSS vectors are **not** part of the SLH-DSA KAT corpus and
must not be copied into `test/data` for SLH-DSA testing. They are, however, a
strong asset for a **separate future workstream** - SP 800-208 stateful HBS
(LMS/HSS and XMSS/XMSS^MT) - which would reuse the same vendored SHA-2/SHAKE
primitives and the same discovered-runner discipline. If pursued, it belongs in
its own guide and its own `lib/src/algos/{lms,xmss}/` modules, tracked under the
"Extended Algorithms" section of [ROADMAP.md](ROADMAP.md), after SLH-DSA ships.

## Appendix C - Release Strategy Rationale

The release was sequenced SHAKE-first and then opened to all 12 sets in v0.4.0.
The rationale below records why.

Core principles:

- Sequence by hash family. The SHA-2 primitives form a shared core whose single
  transcription error would contaminate six sets and turn a KAT failure into a
  multi-dimensional search, so the SHAKE sets (no new primitive) were proven
  first and the SHA-2 sets followed once their primitives were independently
  KAT-green.
- Gate vendored primitives (HMAC, MGF1) on their own KATs before composition.
- NIST ACVP `SLH-DSA` vectors only; SPHINCS+ v3 vectors validate the wrong
  algorithm (FORS extraction changed).
- Default to `shake128f`; the `s` variants are not for web/interactive; gate and
  document them.
- BUFF and performance caveats belong at the API/README level, not in a footnote.
- Timing side-channels are largely theater for a hash-based scheme; fault/
  grafting, RBG quality, and zeroization are the real tails.

API surface (adopted): prefer an opinionated, recommended-default enum over
twelve flat choices — implemented as the `allowSlowSigning` gate plus a default
of `shake128f`; all 12 sets remain documented and implemented.

Kill criteria: if `shake128f` signing exceeds ~1 s on a mid-tier mobile/VM
target, revisit defaults before release; if authoritative ACVP SLH-DSA vectors
cannot be obtained in a checkable form, the byte-exact claim is blocked (fall
back to reference cross-verification and say so); if any vendored primitive
cannot be made independently KAT-green, the dependent SHA-2 sets slip, not the
SHAKE ones.

## Appendix D - GitHub Issue Map

This guide is decomposed into the GitHub issues below. They are **live** on the
repository (label `slh-dsa`), with epic SLHDSA-00 (#34) linking every child.
Issue tracking lives on GitHub, not in
the repository tree; the table below is the durable key -> issue map. Performance
(`PERF-*`) and stable-API (`STABLE-*`) work tracks under the v0.5.0 and v1.0.0
milestones; see [ROADMAP.md](ROADMAP.md).

| ID        | Issue | Title                                                                  | Milestone | Priority |
| --------- | ----- | ---------------------------------------------------------------------- | --------- | -------- |
| SLHDSA-00 | #34   | Epic: FIPS 205 SLH-DSA to release (tracking issue)                     | v0.4.0    | P0       |
| SLHDSA-01 | #8    | Acquire + check in NIST ACVP SLH-DSA vectors with provenance README    | v0.4.0    | P0       |
| SLHDSA-02 | #4    | `params.dart`: 12 sets + derived sizes (single source of truth)        | v0.4.0    | P0       |
| SLHDSA-03 | #15   | `util.dart`: toInt/toByte/base_2b/Trunc_n/gen_len2                     | v0.4.0    | P0       |
| SLHDSA-04 | #16   | `address.dart`: `ADRS` (32B), 7 types, Table 1 member functions        | v0.4.0    | P0       |
| SLHDSA-05 | #9    | `hashing.dart`: SHAKE instantiation of the six hash functions          | v0.4.0    | P0       |
| SLHDSA-06 | #5    | `wots.dart`: Algorithms 5-8 (+ component tests)                        | v0.4.0    | P0       |
| SLHDSA-07 | #17   | `xmss.dart`: Algorithms 9-11 (+ component tests)                       | v0.4.0    | P0       |
| SLHDSA-08 | #18   | `hypertree.dart`: Algorithms 12-13 (+ round-trip tests)                | v0.4.0    | P0       |
| SLHDSA-09 | #6    | `fors.dart`: Algorithms 14-17 (+ digest-index extraction test)         | v0.4.0    | P0       |
| SLHDSA-10 | #19   | `slhdsa.dart`: internal Algorithms 18-20 + ACVP KAT runner             | v0.4.0    | P0       |
| SLHDSA-11 | #20   | `slhdsa.dart`: external Algorithms 21-25 (ctx, pre-hash, hedged, gate) | v0.4.0    | P0       |
| SLHDSA-12 | #21   | Negative/malformed-input tests + verify length-check                   | v0.4.0    | P1       |
| SLHDSA-13 | #22   | Zeroization + optional verify-after-sign + SECURITY_AUDIT entries      | v0.4.0    | P1       |
| SLHDSA-14 | #23   | BUFF + performance docs (API docstrings, README, FIPS_COMPLIANCE)      | v0.4.0    | P0       |
| SLHDSA-15 | #24   | Benchmarks (VM + dart2js + dart2wasm) + PERFORMANCE.md numbers         | v0.4.0    | P1       |
| SLHDSA-16 | #10   | Cross-platform gates + v0.4.0 release (all 12 sets)                    | v0.4.0    | P0       |
| SLHDSA-17 | #25   | `hmac.dart`: HMAC-SHA-256/512 + RFC 4231 KAT gate                      | v0.4.0    | P0       |
| SLHDSA-18 | #26   | `mgf1.dart`: MGF1-SHA-256/512 + RFC 8017 KAT gate                      | v0.4.0    | P0       |
| SLHDSA-19 | #27   | `ADRS^c` (22B) + Table 3 member functions                              | v0.4.0    | P0       |
| SLHDSA-20 | #28   | SHA-2 hashing (cat 1 and cat 3/5 split) + per-function tests           | v0.4.0    | P0       |
| SLHDSA-21 | #29   | Wire 6 SHA-2 sets + extend ACVP KAT to all 12                          | v0.4.0    | P0       |
| SLHDSA-22 | #30   | SHA-2 family (6 sets) + cross-impl verification                        | v0.4.0    | P1       |

See also [ROADMAP.md](ROADMAP.md) and [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md)
for the milestone view.

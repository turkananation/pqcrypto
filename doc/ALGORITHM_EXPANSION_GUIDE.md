# Algorithm Expansion Guide

Last updated: 2026-06-16

This guide describes how to expand `pqcrypto` beyond ML-KEM without weakening
the existing assurance boundary.

## Current Algorithm State

| Algorithm | Standard/status           | Repository state                                             |
| --------- | ------------------------- | ------------------------------------------------------------ |
| ML-KEM    | FIPS 203                  | Supported with checked-in KAT and native interop evidence.   |
| ML-DSA    | FIPS 204                  | Supported; byte-exact on the checked-in KAT corpus.          |
| SLH-DSA   | FIPS 205                  | Shipped in 0.4.0; all 12 SHA2/SHAKE sets byte-exact on ACVP. |
| HQC       | NIST additional KEM track | Not started; wait for final implementation guidance.         |
| FN-DSA    | FALCON/FIPS 206 direction | Not started; high sampler and side-channel risk.             |

## Priority Recommendation

1. Cut the SLH-DSA 0.4.0 release: release branch, tag, and pub.dev publication.
2. Keep SLH-DSA artifact/archival guidance separate from interactive handshake
   defaults because of signature size, slow `s` sets, and the BUFF caveat.
3. Maintain ML-KEM, ML-DSA, and SLH-DSA KAT/ACVP, interop, and security
   regressions.
4. Consider HQC for KEM diversity after spec stability.
5. Defer FN-DSA until the sampler/precision/side-channel strategy is credible.

## Shared Infrastructure Needed

| Component             | Needed by              | Priority | Notes                                            |
| --------------------- | ---------------------- | -------- | ------------------------------------------------ |
| `secureZero` helpers  | All algorithms         | P0       | Use for `Uint8List` and `Int32List` temporaries. |
| Constant-time helpers | ML-KEM, ML-DSA, future | P0       | Comparisons, select, norm checks.                |
| KAT fixture policy    | All algorithms         | P0       | Use repo-local corpus under `test/data`.         |
| Benchmark suite       | All algorithms         | P2       | Required before speed claims.                    |
| HMAC/MGF1 + `ADRS^c`  | SLH-DSA SHA2 variants  | P2       | Done; keep KAT-gated for all SHA-2 set changes.  |
| GF(2^m) library       | HQC                    | P3       | Keep separate from lattice arithmetic.           |
| FFT/complex support   | FN-DSA                 | P4       | High implementation risk in pure Dart.           |

## SLH-DSA Direction

SLH-DSA is hash-based and avoids lattice arithmetic, but signatures are large.

Current internal structure:

```text
lib/src/algos/slhdsa/
  address.dart
  hashing.dart
  params.dart
  util.dart
  fors.dart
  wots.dart
  xmss.dart
  hypertree.dart
  slhdsa.dart # Algorithms 18-25 and internal/external composition
```

Completed foundation:

- all 12 parameter sets, Algorithms 1-25, SHAKE + SHA-2 hashing, and the 32-byte
  `ADRS` / 22-byte `ADRS^c`;
- official NIST ACVP sample corpus with integrity/schema gate;
- all 1,248 ACVP cases byte-exact, plus focused component/API tests.

Remaining release action work is tracked in
[SLHDSA_FIPS205_RELEASE_GUIDE.md](SLHDSA_FIPS205_RELEASE_GUIDE.md).

## HQC Direction

HQC provides code-based KEM diversity. Do not begin it as a side quest during
ML-DSA validation.

Suggested structure:

```text
lib/src/algos/hqc/
  kem.dart
  gf.dart
  reed_solomon.dart
  reed_muller.dart
  parsing.dart
  params.dart
```

Key risks are GF arithmetic correctness, code decoding behavior, and large key
and ciphertext sizes.

## FN-DSA Direction

FN-DSA has small signatures but the hardest implementation profile:

- discrete Gaussian sampling;
- FFT/complex arithmetic;
- precision discipline;
- side-channel resistance.

In pure Dart, this should be deferred until the final standard and a defensible
sampler strategy exist. A separate helper package or FFI boundary may be safer
than putting high-risk native assumptions into the core runtime package.

## Expansion Checklist

For every new algorithm:

- [ ] parameters for every supported security level;
- [ ] serialization and round-trip tests;
- [ ] negative tests for malformed public inputs;
- [ ] deterministic KAT runner discovered by `dart test`;
- [ ] repo-local KAT corpus or documented reason for absence;
- [ ] side-channel review for comparisons, rejection loops, and secret branches;
- [ ] zeroization strategy;
- [ ] package exports and readiness language updated together;
- [ ] [INDEX.md](INDEX.md), [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md),
      [SECURITY_AUDIT.md](SECURITY_AUDIT.md), and
      [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) updated.

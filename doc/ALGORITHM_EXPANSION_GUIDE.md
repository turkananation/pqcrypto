# Algorithm Expansion Guide

Last updated: 2026-06-05

This guide describes how to expand `pqcrypto` beyond ML-KEM without weakening
the existing assurance boundary.

## Current Algorithm State

| Algorithm | Standard/status           | Repository state                                            |
| --------- | ------------------------- | ----------------------------------------------------------- |
| ML-KEM    | FIPS 203                  | Supported with checked-in KAT and OpenSSL interop evidence. |
| ML-DSA    | FIPS 204                  | Exported but experimental; current full suite fails.        |
| SLH-DSA   | FIPS 205                  | Not started.                                                |
| HQC       | NIST additional KEM track | Not started; wait for final implementation guidance.        |
| FN-DSA    | FALCON/FIPS 206 direction | Not started; high sampler and side-channel risk.            |

## Priority Recommendation

1. Finish ML-DSA correctness and repo-local KAT validation.
2. Harden shared security utilities: zeroization, constant-time helpers, and
   negative tests.
3. Add SLH-DSA if a new signature family is needed.
4. Consider HQC for KEM diversity after spec stability.
5. Defer FN-DSA until the sampler/precision/side-channel strategy is credible.

## Shared Infrastructure Needed

| Component             | Needed by              | Priority | Notes                                            |
| --------------------- | ---------------------- | -------- | ------------------------------------------------ |
| `secureZero` helpers  | All algorithms         | P0       | Use for `Uint8List` and `Int32List` temporaries. |
| Constant-time helpers | ML-KEM, ML-DSA, future | P0       | Comparisons, select, norm checks.                |
| KAT fixture policy    | All algorithms         | P0       | Use repo-local corpus under `test/data`.         |
| Benchmark suite       | All algorithms         | P2       | Required before speed claims.                    |
| SHA-256 wrapper       | SLH-DSA SHA2 variants  | P2       | Current package vendors SHA3/SHAKE only.         |
| GF(2^m) library       | HQC                    | P3       | Keep separate from lattice arithmetic.           |
| FFT/complex support   | FN-DSA                 | P4       | High implementation risk in pure Dart.           |

## SLH-DSA Direction

SLH-DSA is hash-based and avoids lattice arithmetic, but signatures are large.

Suggested structure:

```text
lib/src/algos/slh_dsa/
  slh_dsa.dart
  address.dart
  fors.dart
  wots.dart
  xmss.dart
  hypertree.dart
  params.dart
  hash.dart
```

Minimum work:

- ADRS structure;
- WOTS+ chain/keygen/sign/verify;
- XMSS tree construction;
- FORS sign/verify;
- hypertree orchestration;
- parameter sets;
- KAT corpus and tests;
- README/doc status update.

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

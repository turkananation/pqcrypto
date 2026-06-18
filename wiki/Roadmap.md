# Roadmap

A summary of where `pqcrypto` is going. The authoritative, detailed plan is
[ROADMAP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ROADMAP.md);
shipped changes are in
[CHANGELOG.md](https://github.com/turkananation/pqcrypto/blob/main/CHANGELOG.md).

## Shipped

| Version | Highlights                                                                                                          |
| ------- | ------------------------------------------------------------------------------------------------------------------- |
| 0.1.0   | Initial ML-KEM (512/768/1024) with KAT evidence.                                                                    |
| 0.2.x   | ML-KEM input validation, OpenSSL interop, vendored FIPS 202, web tests, zero deps.                                  |
| 0.3.0   | Byte-exact FIPS 204 ML-DSA (44/65/87), HashML-DSA, vendored SHA-2, KEM constant-time output selection, zeroization. |
| 0.3.1   | Package metadata alignment (zero deps; ML-KEM + ML-DSA evidence).                                                   |
| 0.4.0   | All 12 SLH-DSA sets (SHAKE + SHA-2), byte-exact on 1,248 ACVP cases; OpenSSL/liboqs interop. **Current release.**   |

## Planned

| Version | Theme                          | Notes                                                                                       |
| ------- | ------------------------------ | ------------------------------------------------------------------------------------------- |
| 0.5.0   | **Performance & platform**     | Automated benchmark suite across AOT/dart2js/dart2wasm.                                     |
| 0.6.0   | **Full FIPS 202 + SP 800-185** | SHA-3 corpus completion, cSHAKE, KMAC, TupleHash, ParallelHash (0.7.0 spillover if needed). |
| 1.0.0   | **Stable API**                 | Frozen public API; evidence and docs aligned.                                               |

## Under consideration

- **LMS / XMSS** — stateful hash-based signatures (SP 800-208).
- **HQC** — code-based KEM, a different hardness assumption for crypto-agility.
- **FN-DSA (Falcon)** — compact signatures, deferred pending a credible Dart
  sampler/side-channel approach.

What new algorithms unlock for builders is sketched in
[Future Releases](https://github.com/turkananation/pqcrypto/blob/main/doc/cookbook/FUTURE_RELEASES.md).

## Principles that won't change

- **Zero runtime dependencies** unless a deliberate, separate package boundary
  is introduced.
- **Evidence-scoped claims** — no CMVP/FIPS 140 overclaim; conformance is shown
  by KATs, tests, and interop.
- **Cross-platform parity** — VM, `dart2js`, and `dart2wasm` gates stay green.

See the full plan, release criteria, and trackers:
[ROADMAP.md](https://github.com/turkananation/pqcrypto/blob/main/doc/ROADMAP.md)
·
[PROGRESS_TRACKER.md](https://github.com/turkananation/pqcrypto/blob/main/doc/PROGRESS_TRACKER.md).

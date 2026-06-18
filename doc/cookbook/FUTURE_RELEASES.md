# Project Ideas Unlocked by Future Releases

Last updated: 2026-06-16

Everything in [PROJECT_CATALOG.md](PROJECT_CATALOG.md) works with the current
`pqcrypto` **0.4.0** release today. This page looks at what each release adds —
starting with SLH-DSA in 0.4.0 — and the forward [roadmap](../ROADMAP.md) beyond
it. Later milestones may land in the source tree before they are published to
pub.dev; check the roadmap and changelog before building against them.

Status legend: **Planned** = on the roadmap with a target version; **Exploratory**
= a candidate direction, not committed.

## 0.4.0 — SLH-DSA (FIPS 205), hash-based signatures

**Shipped in 0.4.0.** Stateless hash-based signatures: all 12 FIPS
205 parameter sets (both the SHAKE and SHA-2 hash families) are implemented and
byte-exact on the checked-in 1,248-case official ACVP sample corpus. All 12 ship
together in 0.4.0.
SLH-DSA uses only hash functions — no lattice arithmetic — so it is a strong
*diversification* against any future lattice cryptanalysis. The trade-offs are
large signatures and slower signing; verification stays reasonable.

What it unlocks:

- **Belt-and-suspenders dual signatures (post-quantum × post-quantum).** Extend
  building block [BB9](BUILDING_BLOCKS.md#bb9-hybrid-and-dual-signatures) to
  ML-DSA **+** SLH-DSA so a forgery requires breaking two *different* families of
  hardness assumption — not lattice twice.
- **Long-term / archival document signing.** For signatures that must remain
  trustworthy for decades, a conservative hash-based scheme is attractive
  precisely because its security rests on well-understood hash assumptions.
- **High-assurance firmware/code signing.** Pair with
  [BB7](BUILDING_BLOCKS.md#bb7-signed-software-and-firmware-updates) where the
  verifier is constrained but the threat horizon is long.

Plan around: much larger signatures than ML-DSA, and slower signing — favor it
for low-frequency, high-value signatures, not per-request tokens.

## 0.5.0 — Performance and platform work

**Planned.** Benchmark suite and platform measurement (AOT, dart2js, dart2wasm),
plus candidate arithmetic optimizations. This does not add algorithms, but it
makes the **web** and **embedded-Linux** ideas in the catalog easier to size and
justify with real numbers on your target. If your project's viability depends on
throughput, this milestone is the one to watch.

## 0.6.0 — Full FIPS 202 and SP 800-185 (SHA-3 family + KMAC)

**Planned** (with 0.7.0 spillover if the evidence gate cannot close). Completes
the public FIPS 202 / SP 800-185 utility surface. The source tree already has
byte-oriented SHA3-224/256/384/512, SHAKE128/256, and incremental SHAKE XOFs for
internal use; this milestone adds the remaining evidence boundary and the SP
800-185 derived functions: cSHAKE, KMAC, TupleHash, ParallelHash. This is the
milestone that **shrinks the "you supply" column** for several building blocks,
because today the package exports no public hash or MAC.

What it could unlock (subject to the final exported API):

- **Native keyed MAC for transcripts and integrity (KMAC).** Today
  [BB3](BUILDING_BLOCKS.md#bb3-hybrid-authenticated-handshake) and
  [BB6](BUILDING_BLOCKS.md#bb6-tamper-evident-signed-log) need a hash/MAC from
  your stack. KMAC would let more of the pipeline live in one zero-dependency
  package.
- **Unambiguous multi-field hashing (TupleHash).** A natural fit for transcript
  and record framing — TupleHash removes field-boundary ambiguity by
  construction, complementing the length-prefix helper in
  [BB6](BUILDING_BLOCKS.md#bb6-tamper-evident-signed-log).
- **Domain-separated XOF (cSHAKE).** Clean per-purpose separation for derived
  values without bolting on an external library.
- **A standalone SHA-3 utility surface** for apps that just want vetted
  SHA3/SHAKE in pure Dart.

Plan around: until this ships, keep using a public hash/MAC from your application
stack for KDFs, transcripts, and logs.

## Extended algorithms (exploratory)

From the [roadmap](../ROADMAP.md)'s extended-algorithms direction:

- **LMS / XMSS (stateful hash-based signatures, SP 800-208).** **Exploratory.**
  High-assurance firmware signing where strict one-time-key state management is
  acceptable. *Caveat carried forward:* state reuse in stateful HBS is
  catastrophic; only pursue with rigorous state custody.
- **HQC (code-based KEM).** **Exploratory.** A KEM built on a different hardness
  assumption than ML-KEM — useful for crypto-agility and KEM diversification in
  [BB2](BUILDING_BLOCKS.md#bb2-encrypt-to-a-public-key) /
  [BB3](BUILDING_BLOCKS.md#bb3-hybrid-authenticated-handshake).
- **FN-DSA (Falcon).** **Exploratory.** Compact signatures for bandwidth- or
  storage-constrained signing, where ML-DSA's signature size is the binding
  constraint. Deferred until a credible Dart sampler and side-channel approach
  exist.

## How to track this

- [../ROADMAP.md](../ROADMAP.md) — the authoritative release direction.
- [../PROGRESS_TRACKER.md](../PROGRESS_TRACKER.md) — open work and gates.
- The package `CHANGELOG.md` — what actually shipped.

When one of these lands in a published package, the corresponding idea graduates
into [PROJECT_CATALOG.md](PROJECT_CATALOG.md) and
[project-ideas.yaml](project-ideas.yaml) with its `status` flipped to
`available`. Until then, the honest answer to "can I build X with the published
package?" is **not yet**.

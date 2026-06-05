# OpenSSL ↔ pqcrypto ML-KEM Interoperability

**Status:** ✅ Verified. The full suite (tests A–G) passes for **all three**
parameter sets — ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
**Last verified:** 2026-06-03 (Linux) against **OpenSSL 3.5.4 and 3.5.6**; CI
also runs it against **OpenSSL 4.0.0** — see [Results](#5-results).

This document explains how the `pqcrypto` package's ML-KEM implementation
interoperates with [OpenSSL](https://www.openssl.org/)'s native ML-KEM, how that
interoperability is tested on **Linux** and **macOS**, the exact versions and
results, and the use cases it unlocks.

> **Why this matters.** NIST Known-Answer Tests (KATs) prove that `pqcrypto`
> reproduces the standard's reference byte outputs. Interoperability with OpenSSL
> proves the complementary, real-world property: that a key or ciphertext
> produced by one independent FIPS 203 implementation is accepted by the other,
> and both derive the **same shared secret**. This is the property that actually
> matters when a Dart client talks to an OpenSSL-based server (or vice versa).
>
> **Purity note.** All FFI lives in the **separate** `openssl_pqcrypto_interop`
> dev-tool package under [`tool/openssl_interop/`](../tool/openssl_interop/)
> (`publish_to: none`), which depends on `pqcrypto` by path. The published
> `pqcrypto` package's `lib/` contains **no** `dart:ffi` and stays pure Dart /
> Flutter / Web compatible; pub.dev platform support is derived only from `lib/`.

---

## 1. What "interoperability" means here

ML-KEM (FIPS 203) is fully specified down to the byte. Two conformant
implementations must agree on the wire formats and the derived secret. All
sizes are in bytes:

| Artifact                            | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| :---------------------------------- | :--------: | :--------: | :---------: |
| Encapsulation key (public key) `ek` | **800**    | **1184**   | **1568**    |
| Ciphertext `c`                      | **768**    | **1088**   | **1568**    |
| Decapsulation key (secret key) `dk` | **1632**   | **2400**   | **3168**    |
| Shared secret `K`                   | **32**     | **32**     | **32**      |

These follow directly from the parameter sets (`k` = 2 / 3 / 4):

- `publicKeyBytes  = 384·k + 32`
- `ciphertextBytes = 32·(k·du + dv)` (512/1024 use `du,dv = 10,4` / `11,5`)
- `secretKeyBytes  = 768·k + 96` = `ByteEncode₁₂(ŝ) ‖ ek ‖ H(ek) ‖ z`

`pqcrypto`'s sizes (see [`params.dart`](../lib/src/algos/kyber/params.dart))
match OpenSSL's **exactly** at every level. Because the public-key and
ciphertext encodings are identical raw byte strings, **no format conversion is
needed** to pass them between the two implementations.

Interoperability therefore reduces to observable checks: *does the shared secret
derived by implementation X equal the shared secret derived by implementation
Y?* — plus the stronger byte-level checks the deterministic-seed path unlocks
(Section 2).

---

## 2. The test suite

The harness ([`tool/openssl_interop/`](../tool/openssl_interop/)) runs the
following for **each** of ML-KEM-512, ML-KEM-768, and ML-KEM-1024. Tests A and B
are self-consistency sanity checks; C–G are cross-implementation proofs.

| Test           | KeyGen                               | Encaps          | Decaps          | What it proves                                                                   |
| :------------: | :----------------------------------- | :-------------- | :-------------- | :------------------------------------------------------------------------------- |
| **sizes**      | —                                    | —               | —               | OpenSSL & `pqcrypto` outputs match the FIPS 203 size constants                   |
| **A**          | OpenSSL                              | OpenSSL         | OpenSSL         | Sanity: OpenSSL is internally consistent                                         |
| **B**          | pqcrypto                             | pqcrypto        | pqcrypto        | Sanity: `pqcrypto` is internally consistent                                      |
| **C**          | **OpenSSL**                          | **pqcrypto**    | **OpenSSL**     | OpenSSL can decapsulate a **pqcrypto** ciphertext (×fuzz)                        |
| **D**          | **pqcrypto**                         | **OpenSSL**     | **pqcrypto**    | `pqcrypto` can decapsulate an **OpenSSL** ciphertext (×fuzz)                     |
| **E**          | both, from a **shared seed** `(d‖z)` | —               | —               | Same seed ⇒ **byte-identical public keys**                                       |
| **E-exchange** | both, from a shared seed             | both directions | both directions | The seed-derived keypair interoperates both ways                                 |
| **F**          | pqcrypto                             | —               | —               | **Public-key wire round-trip**: pqcrypto → OpenSSL → re-export is byte-identical |
| **G**          | both, from a shared seed             | —               | both            | **Implicit-rejection** secret `Kbar = J(z‖c)` agrees on an invalid ciphertext    |
| **negative**   | OpenSSL                              | —               | —               | `pqcrypto` rejects a truncated OpenSSL public key                                |

A round-trip test **passes** when `encapsulate`'s shared secret equals
`decapsulate`'s shared secret (byte-for-byte). C and D are run over many random
keypairs (`fuzz`, 16–24 iterations per direction per level) to catch any
1-in-N divergence.

### Why E, F, and G matter (beyond A–D)

A–D only ever exercise *valid* ciphertexts and never compare raw key bytes
directly. The seed-based tests close those gaps:

- **E / E-exchange** — OpenSSL exposes deterministic ML-KEM keygen from the
  64-byte FIPS 203 seed `(d‖z)` (the `"seed"` `OSSL_PARAM`). Feeding the *same*
  seed to both implementations must yield the *same* public key, bit for bit —
  a far stronger statement than "the round-trip works."
- **F** — proves the raw public-key encoding is identical on the wire: a
  `pqcrypto` key imported into OpenSSL and re-exported reproduces the exact input
  bytes.
- **G** — exercises the FIPS 203 **implicit-rejection** branch that A–D never
  reach. A correctly-sized but invalid ciphertext never makes decapsulation
  fail; instead both sides return `K̄ = J(z‖c)`. With a shared seed (hence shared
  `z`) and the same ciphertext `c`, the two implementations must produce the
  **same** rejection secret. This proves the `J`/domain-separation path is
  byte-conformant too.

### Why only public keys (and seeds) cross the boundary

The harness exchanges only **public keys**, **ciphertexts**, and (for the
deterministic tests) **seeds** — never expanded private keys. Each side keeps
its own KeyGen → Decaps internal. This is intentional:

- The **public key**, **ciphertext**, and the 64-byte **seed** are standardized
  raw encodings and are byte-identical across implementations, so they transfer
  with no conversion.
- The **expanded private (decapsulation) key** is *not* exchanged because the two
  projects serialize it differently. OpenSSL can represent a decapsulation key
  as the 64-byte seed `(d‖z)` or the expanded key; `pqcrypto` uses the expanded
  FIPS 203 form `dk = ByteEncode₁₂(ŝ) ‖ ek ‖ H(ek) ‖ z`. Sharing the *seed*
  (test E/G) gives the same effect — both sides derive the identical expanded
  key — without inventing a non-standard private-key wire format.

This mirrors how ML-KEM is actually deployed: each party generates its own
keypair, publishes its public key, and the only things that travel over the wire
are the public key and the ciphertext.

---

## 3. How it works

### 3.1 Shared, testable structure

The reusable FFI and scaffolding live in
[`tool/openssl_interop/lib/openssl_ml_kem.dart`](../tool/openssl_interop/lib/openssl_ml_kem.dart),
imported by both the runnable harness
([`bin/openssl_pqcrypto_interop.dart`](../tool/openssl_interop/bin/openssl_pqcrypto_interop.dart))
and the test suite
([`test/interop_test.dart`](../tool/openssl_interop/test/interop_test.dart)).
The EVP API is algorithm-agnostic, so a single loaded library serves all three
parameter sets — the level is just the algorithm-name argument
(`"ML-KEM-512" / "ML-KEM-768" / "ML-KEM-1024"`).

### 3.2 pqcrypto side (pure Dart)

Uses the package's public API, no native code:

```dart
final pq = PqcKem.kyber1024;               // or .kyber512 / .kyber768
final (pk, sk) = pq.generateKeyPair();      // standardized pk, expanded sk
final (ct, ss) = pq.encapsulate(pk);        // ct, 32-byte ss
final ssRecovered = pq.decapsulate(sk, ct);
final (pk2, _) = pq.generateKeyPair(seed64); // deterministic from a 64-byte d‖z
```

### 3.3 OpenSSL side (Dart FFI → `libcrypto`)

The harness binds directly to `libcrypto` using `dart:ffi` and the OpenSSL
high-level **EVP** API. No `openssl` CLI and no build step at runtime — it
`dlopen`s the shared library and calls:

| EVP function                                                                      | Purpose                                                                |
| :-------------------------------------------------------------------------------- | :--------------------------------------------------------------------- |
| `EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-<lvl>", NULL)`                          | Create a context for the chosen level                                  |
| `EVP_PKEY_keygen_init` / `EVP_PKEY_keygen`                                        | Generate a keypair                                                     |
| `EVP_PKEY_get1_encoded_public_key`                                                | Export the raw public key                                              |
| `EVP_PKEY_fromdata_init` / `EVP_PKEY_fromdata` (param `"pub"`, sel. `PUBLIC_KEY`) | Import a raw public key (for encaps)                                   |
| `EVP_PKEY_fromdata_init` / `EVP_PKEY_fromdata` (param `"seed"`, sel. `KEYPAIR`)   | **Deterministically derive a keypair from a 64-byte seed** (tests E/G) |
| `EVP_PKEY_encapsulate_init` / `EVP_PKEY_encapsulate`                              | Encapsulate                                                            |
| `EVP_PKEY_decapsulate_init` / `EVP_PKEY_decapsulate`                              | Decapsulate                                                            |
| `OSSL_PARAM_BLD_*`                                                                | Build the `OSSL_PARAM` carrying the imported octet string              |
| `OpenSSL_version(0)`                                                              | Report the loaded library version (for the banner)                     |

ML-KEM ships in OpenSSL's **default provider** (built into `libcrypto`) since
OpenSSL 3.5, so no provider configuration or `openssl.cnf` is required — opening
`libcrypto` is sufficient.

### 3.4 Library resolution

`resolveLibcryptoPath()` (in
[`lib/openssl_ml_kem.dart`](../tool/openssl_interop/lib/openssl_ml_kem.dart))
resolves `libcrypto` in this order:

1. The `LIBCRYPTO_PATH` environment variable, if set (the reliable, explicit
   path — always used on Linux when the system OpenSSL is < 3.5).
2. Platform defaults:
   - **macOS:** Homebrew locations, e.g. `/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib`.
   - **Linux:** `/usr/local/lib64/libcrypto.so`, `/usr/local/lib/libcrypto.so`
     (the default install prefix for a from-source build).

If none is found, the harness exits `2` with the probed paths and the
`OpenSSL ≥ 3.5` requirement; the test suite reports a **skip** (so a bare
`dart test` on a machine without ML-KEM stays green).

> **Tip.** Any OpenSSL ≥ 3.5 `libcrypto.so.3` works — including ones already
> shipped by recent application runtimes (e.g. a current `org.gnome.Platform` or
> `org.freedesktop.Platform` flatpak runtime bundles OpenSSL 3.5.x). Point
> `LIBCRYPTO_PATH` at it and the harness runs with no extra build.

---

## 4. The FIPS 203 fixes that made interop possible

Interoperability is unforgiving: a single byte of divergence in the public key
or ciphertext breaks tests C–G. Reaching all-green required correcting specific
FIPS 203 conformance defects, tracked here by stable Evidence-Ledger ID
(E-numbers) and the fix commit:

| Defect                                                                | Ledger | Effect if wrong                                                         | Fix commit   |
| :-------------------------------------------------------------------- | :----: | :---------------------------------------------------------------------- | :----------- |
| `Compress` must wrap to `[0, 2^d−1]` (mod 2^d), not clamp             | E2     | Ciphertext bytes diverge → C/D fail                                     | `aeae275`    |
| KeyGen seed expansion must be `G(d ‖ k)` (domain-separation byte `k`) | E7     | Different `ρ`/keys → public keys never match                            | `fb2e8cc`    |
| Matrix `Â[i][j] = SampleNTT(XOF(ρ, j, i))` — correct `i/j` order      | E8     | Generates `Aᵀ` → ciphertext diverges → C/D fail                         | `4572b3b`    |
| `barrettReduce` must return canonical `[0, q−1]`                      | E5/E6  | Contract/edge-case hardening (KATs already passed; removes latent risk) | this session |

The upstream interop demo pins commit **`4572b3b`** — the point at which the
public-key and ciphertext encodings became byte-compatible with OpenSSL. The
current working tree is ahead of that commit (Barrett canonicalization, full
512/768/1024 interop coverage, the seed-based E/G tests, input validation, CI),
and **the entire suite still passes** (see below), confirming none of the later
changes regressed interop.

---

## 5. Results

### 5.1 Linux (verified in this repository)

| Component | Version / detail                                                                                                  |
| :-------- | :---------------------------------------------------------------------------------------------------------------- |
| OS        | Linux x86_64                                                                                                      |
| OpenSSL   | **3.5.4** (30 Sep 2025) and **3.5.6** (7 Apr 2026), default provider (`libcrypto.so.3`); CI also builds **4.0.0** |
| Dart SDK  | **3.12.0** (stable)                                                                                               |
| pqcrypto  | working tree (path override), ahead of `4572b3b`                                                                  |
| Date      | 2026-06-03                                                                                                        |

Harness output (`dart run bin/openssl_pqcrypto_interop.dart`, truncated paths;
all 24 checks across the three levels passed):

```text
=== OpenSSL ↔ pqcrypto ML-KEM Interoperability ===
    OpenSSL 3.5.6 7 Apr 2026 (via FFI → libcrypto) vs pqcrypto package
    libcrypto: …/org.gnome.Platform/.../libcrypto.so.3
    levels: ML-KEM-512, ML-KEM-768, ML-KEM-1024   |   fuzz: 16 iterations/direction

--- ML-KEM-512 ---
  sizes pk/ct/sk/ss — OpenSSL 800/768/—/— · pqcrypto 800/768/1632/32 · FIPS 800/768/1632/32
[PASS] ML-KEM-512 sizes: OpenSSL & pqcrypto match FIPS 203 pk/ct/sk/ss
[PASS] ML-KEM-512 A: OpenSSL→OpenSSL self-consistent
[PASS] ML-KEM-512 B: pqcrypto→pqcrypto self-consistent
[PASS] ML-KEM-512 C: OpenSSL keygen + pqcrypto encaps + OpenSSL decaps
[PASS] ML-KEM-512 D: pqcrypto keygen + OpenSSL encaps + pqcrypto decaps
[PASS] ML-KEM-512 F: public-key wire round-trip (pqcrypto→OpenSSL→bytes identical)
[PASS] ML-KEM-512 E: same seed ⇒ identical public keys (OpenSSL == pqcrypto)
[PASS] ML-KEM-512 G: implicit-rejection secret J(z‖c) agrees on invalid ciphertext

--- ML-KEM-768 ---   (8 × [PASS], sizes 1184/1088/2400/32)
--- ML-KEM-1024 ---  (8 × [PASS], sizes 1568/1568/3168/32)

=== Summary ===
passed: 24   skipped: 0   failed: 0
[PASS] All executed interop checks passed.
```

Test-suite output (`dart test`, the more exhaustive `package:test` version —
24 fuzz iterations/direction plus the E-exchange and negative tests):

```text
00:00 +30: All tests passed!
```

> Note: `pqcrypto` interoperates with **two independent OpenSSL 3.5.x builds**
> (3.5.4 and 3.5.6) and, in CI, with **4.0.0** — evidence the conformance is to
> the standard, not to a specific OpenSSL build.

### 5.2 macOS (upstream-validated procedure)

The original interoperability demo
([JeremyTubongbanua/snippets `pqc/openssl_pqcrypto_interop`](https://github.com/JeremyTubongbanua/snippets/tree/main/pqc/openssl_pqcrypto_interop))
was authored and validated on macOS. The vendored harness here runs there
unchanged (it auto-detects the Homebrew `libcrypto`).

| Component | Version / detail                                                           |
| :-------- | :------------------------------------------------------------------------- |
| OS        | macOS (Apple Silicon)                                                      |
| OpenSSL   | **3.5+** via Homebrew (e.g. `brew install openssl@3.5`), `libcrypto.dylib` |
| Dart SDK  | **≥ 3.11**                                                                 |
| pqcrypto  | this working tree                                                          |

Expected output is the same all-`[PASS]` summary as Linux. The harness banner
prints the actual loaded version and the `libcrypto` path it resolved.

---

## 6. Reproducing it

The harness lives at [`tool/openssl_interop/`](../tool/openssl_interop/) — a
self-contained Dart project that depends on this package by path
(`pqcrypto: { path: ../.. }`), so it always tests the current working tree. It
exposes two entry points:

- `dart run bin/openssl_pqcrypto_interop.dart` — the human-readable harness
  (exit `0` all-pass, `1` on failure, `2` if no ML-KEM `libcrypto` is found).
- `dart test` — the rigorous `package:test` suite (skips cleanly if no
  ML-KEM `libcrypto` is available).

### 6.1 macOS

```sh
brew install openssl@3.5                 # provides ML-KEM-capable libcrypto
cd tool/openssl_interop
dart pub get
dart run bin/openssl_pqcrypto_interop.dart   # auto-detects Homebrew libcrypto
dart test                                    # auto-detects Homebrew libcrypto
```

### 6.2 Linux

The system `libcrypto` on most distros today is OpenSSL 3.0.x, which **does not**
include ML-KEM (added in 3.5). Use any OpenSSL ≥ 3.5 `libcrypto` and point the
harness at it via `LIBCRYPTO_PATH` (see the tip in Section 3.4 — a recent flatpak
runtime's bundled `libcrypto.so.3` already qualifies).

Or build from source (≈5–10 min):

```sh
# Download the latest release (4.x or 3.5+), then:
./Configure no-docs no-tests shared --prefix="$HOME/openssl" --libdir=lib
make -j"$(nproc)"
make install_sw

cd tool/openssl_interop
dart pub get
LIBCRYPTO_PATH="$HOME/openssl/lib/libcrypto.so" \
  dart run bin/openssl_pqcrypto_interop.dart
LIBCRYPTO_PATH="$HOME/openssl/lib/libcrypto.so" dart test
```

---

## 7. Continuous integration

[`.github/workflows/interop.yml`](../.github/workflows/interop.yml) runs the
interop proof on every push/PR:

1. Cache (or build) an OpenSSL ≥ 3.5 `libcrypto` for `ubuntu-latest`
   (GitHub's runner images ship OpenSSL 3.0.x, which lacks ML-KEM, so the
   workflow provisions a newer one — pinned to **4.0.0** — and caches it by
   version).
2. Set up the Dart SDK.
3. `dart pub get` in `tool/openssl_interop`.
4. Run **both** entry points with `LIBCRYPTO_PATH` pointing at the provisioned
   library: the `dart test` suite (tests A–G × three levels) and the
   `bin/openssl_pqcrypto_interop.dart` harness.

This is a **separate workflow** from the main [`ci.yml`](../.github/workflows/ci.yml)
(analyze + unit suite + KAT corpus) because it has a heavier, platform-specific
dependency (OpenSSL). The two layers are complementary:

- **`ci.yml` (fast, every change):** the 3000-vector KAT suite — the always-on
  proxy for conformance, hence for interop.
- **`interop.yml` (heavier):** the direct OpenSSL round-trip proof across all
  three parameter sets.

---

## 8. Use cases

- **Hybrid TLS / key exchange.** TLS 1.3 hybrid groups such as
  `X25519MLKEM768` combine X25519 with ML-KEM-768. A Dart service using
  `pqcrypto` for the ML-KEM half can interoperate with OpenSSL-based peers
  because the ML-KEM encodings and shared secret match. The 512 and 1024 levels
  are likewise proven for deployments that select those.
- **Dart client ↔ OpenSSL/C server (and vice versa).** A Flutter/Dart app can
  encapsulate to a public key generated by an OpenSSL backend, and the backend
  recovers the identical shared secret (Test C). The reverse also holds
  (Test D).
- **Cross-language / polyglot systems.** Any stack that already uses OpenSSL
  (Python `cryptography`, Node, Go via cgo, native C/C++) can exchange ML-KEM
  material with `pqcrypto` peers.
- **Migration & dual-stack validation.** Teams migrating to or from `pqcrypto`
  can prove byte-level equivalence with their existing OpenSSL stack before
  cutover.
- **Regression guard.** Run as CI (Section 7) so a future change that silently
  breaks wire compatibility is caught immediately.

---

## 9. Caveats & limitations

- **All three parameter sets are under direct interop test.** ML-KEM-512,
  ML-KEM-768, and ML-KEM-1024 each run the full A–G suite against OpenSSL, in
  addition to the KAT corpus (3000 vectors total).
- **Tests E and G need seed-based keygen.** They use OpenSSL's deterministic
  ML-KEM keygen from a seed (`EVP_PKEY_fromdata` with the `"seed"` param),
  available from OpenSSL 3.5. If a given `libcrypto` lacks it, the harness/suite
  reports those two as **skipped** rather than failing; A–D and F still run.
- **OpenSSL ≥ 3.5 required.** ML-KEM was added in OpenSSL 3.5; earlier releases
  (including the system 3.0.x on current Ubuntu/macOS-without-Homebrew) lack it.
- **Public keys, ciphertexts, and seeds cross the boundary** (Section 2) — never
  expanded private keys. This is by design and reflects how ML-KEM is deployed.
- **Not a security/side-channel claim.** This proves *functional* wire
  compatibility and shared-secret agreement. It is not a constant-time, CMVP, or
  FIPS 140 validation. See [MLKEM_TESTING.md](MLKEM_TESTING.md) for the claim
  boundary.
- **Banner version is read live.** The harness prints `OpenSSL_version(0)` from
  the actually-loaded `libcrypto`, so the reported version reflects reality (not
  a hardcoded string).

---

## 10. References

- FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
- OpenSSL ML-KEM (EVP_PKEY-ML-KEM): <https://docs.openssl.org/master/man7/EVP_PKEY-ML-KEM/>
- Upstream interop demo: <https://github.com/JeremyTubongbanua/snippets/tree/main/pqc/openssl_pqcrypto_interop>
- This repository and [ML-KEM Testing Policy](MLKEM_TESTING.md)

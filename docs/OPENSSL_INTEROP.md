# OpenSSL ↔ pqcrypto ML-KEM Interoperability

**Status:** ✅ Verified. All four cross-implementation tests pass.
**Last verified:** 2026-06-03 (Linux, OpenSSL 4.0.0) — see [Results](#5-results).

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

---

## 1. What "interoperability" means here

ML-KEM (FIPS 203) is fully specified down to the byte. Two conformant
implementations must agree on the wire formats and the derived secret:

| Artifact (ML-KEM-768) | Size | Notes |
| :--- | :---: | :--- |
| Encapsulation key (public key) | **1184 bytes** | `ByteEncode₁₂(t̂)` (3 × 384 = 1152) ‖ `ρ` (32) |
| Ciphertext | **1088 bytes** | `c₁` = Compress/Encode₁₀(u) (3 × 320 = 960) ‖ `c₂` = Compress/Encode₄(v) (128) |
| Shared secret | **32 bytes** | The KEM output `K` |

`pqcrypto`'s sizes match OpenSSL's **exactly** (see
[`params.dart`](../lib/src/algos/kyber/params.dart): `publicKeyBytes = 384·k + 32`,
`ciphertextBytes = 960 + 128` for ML-KEM-768). Because the public key and
ciphertext encodings are identical raw byte strings, **no format conversion is
needed** to pass them between the two implementations.

Interoperability therefore reduces to a single observable check: *does the
shared secret derived by implementation X equal the shared secret derived by
implementation Y?*

---

## 2. The four-test matrix

The harness ([`tool/openssl_interop/`](../tool/openssl_interop/)) runs four
tests. Two are sanity checks (each side agrees with itself); two are the actual
cross-implementation proofs.

| Test | KeyGen | Encaps | Decaps | What it proves |
| :--: | :--- | :--- | :--- | :--- |
| **A** | OpenSSL | OpenSSL | OpenSSL | Sanity: OpenSSL is internally consistent |
| **B** | pqcrypto | pqcrypto | pqcrypto | Sanity: pqcrypto is internally consistent |
| **C** | **OpenSSL** | **pqcrypto** | **OpenSSL** | OpenSSL can decapsulate a **pqcrypto** ciphertext |
| **D** | **pqcrypto** | **OpenSSL** | **pqcrypto** | pqcrypto can decapsulate an **OpenSSL** ciphertext |

A test **passes** when `encapsulate`'s shared secret equals `decapsulate`'s
shared secret (byte-for-byte). Tests C and D exercise both directions of the
exchange, so together they prove full bidirectional interoperability.

### Why only public keys cross the boundary

The harness deliberately exchanges only **public keys** (and ciphertexts)
between implementations — never private keys. Each side keeps its own
KeyGen → Decaps internal. This is intentional:

- The **public key** and **ciphertext** are standardized raw encodings and are
  byte-identical across implementations, so they transfer with no conversion.
- The **private (decapsulation) key** is *not* exchanged because the two
  projects serialize it differently. OpenSSL can represent a decapsulation key
  as the 64-byte seed `(d‖z)` or the expanded key; `pqcrypto` uses the expanded
  FIPS 203 form `dk = ByteEncode₁₂(ŝ) ‖ ek ‖ H(ek) ‖ z`. Converting private-key
  formats is unnecessary for an interop proof and would only add a translation
  layer that isn't part of the standard's wire contract.

This mirrors how ML-KEM is actually deployed: each party generates its own
keypair, publishes its public key, and the only things that travel over the wire
are the public key and the ciphertext.

---

## 3. How it works

### 3.1 pqcrypto side (pure Dart)

Uses the package's public API, no native code:

```dart
final pq = PqcKem.kyber768;
final (pk, sk) = pq.generateKeyPair();   // 1184-byte pk, expanded sk
final (ct, ss) = pq.encapsulate(pk);      // 1088-byte ct, 32-byte ss
final ssRecovered = pq.decapsulate(sk, ct);
```

### 3.2 OpenSSL side (Dart FFI → `libcrypto`)

The harness binds directly to `libcrypto` using `dart:ffi` and the OpenSSL
high-level **EVP** API. No `openssl` CLI and no build step at runtime — it
`dlopen`s the shared library and calls:

| EVP function | Purpose |
| :--- | :--- |
| `EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL)` | Create an ML-KEM-768 context |
| `EVP_PKEY_keygen_init` / `EVP_PKEY_keygen` | Generate a keypair |
| `EVP_PKEY_get1_encoded_public_key` | Export the raw 1184-byte public key |
| `EVP_PKEY_fromdata_init` / `EVP_PKEY_fromdata` | Import a raw public key (for encaps) |
| `EVP_PKEY_encapsulate_init` / `EVP_PKEY_encapsulate` | Encapsulate |
| `EVP_PKEY_decapsulate_init` / `EVP_PKEY_decapsulate` | Decapsulate |
| `OSSL_PARAM_BLD_*` | Build the `OSSL_PARAM` carrying the imported `pub` octet string |
| `OpenSSL_version(0)` | Report the loaded library version (for the banner) |

ML-KEM ships in OpenSSL's **default provider** (built into `libcrypto`) since
OpenSSL 3.5, so no provider configuration or `openssl.cnf` is required — opening
`libcrypto` is sufficient.

### 3.3 Library resolution

`tool/openssl_interop/bin/openssl_pqcrypto_interop.dart` resolves `libcrypto` in
this order:

1. The `LIBCRYPTO_PATH` environment variable, if set (the reliable, explicit
   path — always used on Linux when the system OpenSSL is < 3.5).
2. Platform defaults:
   - **macOS:** Homebrew locations, e.g. `/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib`.
   - **Linux:** `/usr/local/lib64/libcrypto.so`, `/usr/local/lib/libcrypto.so`
     (the default install prefix for a from-source build).

If none is found it throws with the list of probed paths and the
`OpenSSL ≥ 3.5` requirement.

---

## 4. The FIPS 203 fixes that made interop possible

Interoperability is unforgiving: a single byte of divergence in the public key
or ciphertext breaks tests C and D. Reaching all-green required correcting
specific FIPS 203 conformance defects. These are tracked in this repository's
[Evidence Ledger](EVIDENCE_LEDGER.md):

| Defect | Ledger | Effect if wrong | Fix commit |
| :--- | :---: | :--- | :--- |
| `Compress` must wrap to `[0, 2^d−1]` (mod 2^d), not clamp | E2 | Ciphertext bytes diverge → C/D fail | `aeae275` |
| KeyGen seed expansion must be `G(d ‖ k)` (domain-separation byte `k`) | E7 | Different `ρ`/keys → public keys never match | `fb2e8cc` |
| Matrix `Â[i][j] = SampleNTT(XOF(ρ, j, i))` — correct `i/j` order | E8 | Generates `Aᵀ` → ciphertext diverges → C/D fail | `4572b3b` |
| `barrettReduce` must return canonical `[0, q−1]` | E5/E6 | Contract/edge-case hardening (KATs already passed; removes latent risk) | this session |

The upstream interop demo pins commit **`4572b3b`** — the point at which the
public-key and ciphertext encodings became byte-compatible with OpenSSL. The
current working tree is ahead of that commit (Barrett canonicalization, expanded
tests, input validation, CI), and **all four interop tests still pass** (see
below), confirming none of the later changes regressed interop.

---

## 5. Results

### 5.1 Linux (verified in this repository)

| Component | Version / detail |
| :--- | :--- |
| OS | Linux x86_64 (Ubuntu 24.04 toolchain, gcc 13.3.0) |
| OpenSSL | **4.0.0** (14 Apr 2026), built from source, default provider (`libcrypto.so.4`) |
| Dart SDK | **3.12.0** (stable) |
| pqcrypto | working tree (path override), ahead of `4572b3b` |
| Date | 2026-06-03 |

Output (truncated hex; full secrets are 32 bytes and matched byte-for-byte):

```text
=== ML-KEM-768 Cross-Implementation Comparison ===
    OpenSSL 4.0.0 14 Apr 2026 (via FFI → libcrypto) vs pqcrypto package
    libcrypto: /tmp/osslinst/lib/libcrypto.so

[PASS] OpenSSL encaps/decaps shared secrets match
[PASS] pqcrypto encaps/decaps shared secrets match
[PASS] OpenSSL keygen + pqcrypto encaps + OpenSSL decaps: shared secrets match
[PASS] pqcrypto keygen + OpenSSL encaps + pqcrypto decaps: shared secrets match

=== Summary ===
[PASS] All tests passed.
```

> Note: `pqcrypto` interoperates with OpenSSL **4.0.0**, a release *newer* than
> the 3.6 used in the original validation — evidence the conformance is to the
> standard, not to a specific OpenSSL build.

### 5.2 macOS (upstream-validated procedure)

The original interoperability demo
([JeremyTubongbanua/snippets `pqc/openssl_pqcrypto_interop`](https://github.com/JeremyTubongbanua/snippets/tree/main/pqc/openssl_pqcrypto_interop))
was authored and validated on macOS. The vendored harness here runs there
unchanged (it auto-detects the Homebrew `libcrypto`).

| Component | Version / detail |
| :--- | :--- |
| OS | macOS (Apple Silicon) |
| OpenSSL | **3.6** via Homebrew (`brew install openssl@3.6`), `libcrypto.dylib` |
| Dart SDK | **≥ 3.11** |
| pqcrypto | fork pinned at `4572b3b` (upstream) / this working tree |

Expected output is the same four `[PASS]` lines as Linux. The harness banner
prints the actual loaded version (e.g. `OpenSSL 3.6.x`), and the `libcrypto`
path it resolved.

---

## 6. Reproducing it

The harness lives at [`tool/openssl_interop/`](../tool/openssl_interop/) — a
self-contained Dart project that depends on this package by path
(`pqcrypto: { path: ../.. }`), so it always tests the current working tree.

### 6.1 macOS

```sh
brew install openssl@3.6                 # provides ML-KEM-capable libcrypto
cd tool/openssl_interop
dart pub get
dart run bin/openssl_pqcrypto_interop.dart   # auto-detects Homebrew libcrypto
```

### 6.2 Linux

The system `libcrypto` on most distros today is OpenSSL 3.0.x, which **does not**
include ML-KEM (added in 3.5). Either install an OpenSSL ≥ 3.5 package or build
one, then point the harness at it via `LIBCRYPTO_PATH`.

Build from source (≈5–10 min):

```sh
# Download the latest release (4.x or 3.5+), then:
./Configure no-docs no-tests shared --prefix="$HOME/openssl" --libdir=lib
make -j"$(nproc)"
make install_sw

cd tool/openssl_interop
dart pub get
LIBCRYPTO_PATH="$HOME/openssl/lib/libcrypto.so" \
  dart run bin/openssl_pqcrypto_interop.dart
```

The program exits `0` if all four tests pass and `1` if any fail.

---

## 7. Continuous integration

[`.github/workflows/interop.yml`](../.github/workflows/interop.yml) runs the
four tests on every push/PR:

1. Cache (or build) an OpenSSL ≥ 3.5 `libcrypto` for `ubuntu-latest`
   (GitHub's runner images ship OpenSSL 3.0.x, which lacks ML-KEM, so the
   workflow provisions a newer one and caches it by version).
2. Set up the Dart SDK.
3. `dart pub get` in `tool/openssl_interop`.
4. Run the harness with `LIBCRYPTO_PATH` pointing at the provisioned library.

This is a **separate workflow** from the main [`ci.yml`](../.github/workflows/ci.yml)
(analyze + unit suite + KAT corpus) because it has a heavier, platform-specific
dependency (OpenSSL). The two layers are complementary:

- **`ci.yml` (fast, every change):** the 3000-vector KAT suite — the always-on
  proxy for conformance, hence for interop.
- **`interop.yml` (heavier):** the direct OpenSSL round-trip proof.

---

## 8. Use cases

- **Hybrid TLS / key exchange.** TLS 1.3 hybrid groups such as
  `X25519MLKEM768` combine X25519 with ML-KEM-768. A Dart service using
  `pqcrypto` for the ML-KEM half can interoperate with OpenSSL-based peers
  because the ML-KEM encodings and shared secret match.
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

- **Parameter set under direct interop test:** the harness covers **ML-KEM-768**
  (the most widely deployed level, e.g. `X25519MLKEM768`). ML-KEM-512 and
  ML-KEM-1024 are covered by the KAT corpus (3000 vectors total) but not by this
  live OpenSSL harness. Extending the harness to 512/1024 is a matter of adding
  the corresponding `EVP_PKEY_CTX_new_from_name` names.
- **OpenSSL ≥ 3.5 required.** ML-KEM was added in OpenSSL 3.5; earlier releases
  (including the system 3.0.x on current Ubuntu/macOS-without-Homebrew) lack it.
- **Public keys only cross the boundary** (Section 2) — this is by design and
  reflects how ML-KEM is deployed.
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

# Security Policy

`pqcrypto` is a pure Dart post-quantum cryptography library (ML-KEM / FIPS 203
and ML-DSA / FIPS 204). Because it implements cryptographic primitives, we take
correctness and disclosure seriously and welcome reports.

## Supported Versions

| Version | Supported            |
| ------- | -------------------- |
| 0.3.x   | Yes — security fixes |
| < 0.3.0 | No — please upgrade  |

Only the latest published `0.3.x` line receives security fixes. The `main`
branch is where fixes land first.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for an unfixed security bug.

1. Preferred: open a private [GitHub Security Advisory](https://github.com/turkananation/pqcrypto/security/advisories/new)
   on the repository.
2. Alternative: email **<turkananation@gmail.com>** with the subject line
   `pqcrypto security report`.

Please include, where possible:

- the affected version(s) and platform (VM, dart2js, dart2wasm, Flutter target);
- a description of the issue and its impact;
- a minimal reproduction (test vector, seed, or code snippet);
- whether the issue is already public.

### What to expect

- Acknowledgement of your report within **5 business days**.
- A triage assessment (severity, affected versions) and a remediation plan.
- Coordinated disclosure: we will agree on a timeline before any public
  advisory, and we are happy to credit reporters who wish to be named.

## Scope and Cryptographic Caveats

`pqcrypto` provides **implementation evidence** (checked-in KAT corpora, focused
unit tests, OpenSSL interop for ML-KEM), **not** a validated cryptographic
module. See [doc/FIPS_140_BOUNDARY.md](doc/FIPS_140_BOUNDARY.md) for the precise
claim boundary. In particular:

- **No CMVP/FIPS 140 validation.** Do not deploy this library where a validated
  module is contractually or legally required without your own validation.
- **Best-effort side-channel resistance.** Keccak is structurally constant-time;
  the ML-DSA norm check and rejection loops evaluate all coefficients with no
  early exit; ML-KEM decapsulation uses constant-time output selection. However,
  pure Dart compiled to the VM, dart2js, and dart2wasm cannot *guarantee*
  constant-time execution (JIT, GC, and per-iteration branch directions are out
  of our control). Treat timing/cache side-channel resistance as best-effort.
- **Best-effort zeroization.** `secureZero`/`secureZeroInt32` overwrite secret
  buffers in `finally` blocks, but Dart's garbage collector may have already
  copied or retained values; this is defense-in-depth, not a guarantee.
- **Randomness.** Key generation and hedged signing draw from
  `Random.secure()` (the platform CSPRNG). This is not an SP 800-90A/B
  validation claim.

These are documented design boundaries, not vulnerabilities. Reports that
*demonstrate* a concrete, exploitable weakening of the above (for example, an
input that makes verification accept a forged signature, a KAT mismatch, or a
practical key-recovery side channel) are in scope and very welcome.

## Out of Scope

- Requests for CMVP/FIPS 140 certification (a separate, formal process).
- Theoretical side-channel concerns already documented in
  [doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md) without a concrete exploit.
- Vulnerabilities in the developer-only OpenSSL interop tool under
  `tool/openssl_interop/`, which is never shipped to consumers.

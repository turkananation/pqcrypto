# Security Posture, Compliance & Threat Model

This document strictly defines the cryptographic boundaries, side-channel mitigations, and compliance postures of the `pqcrypto` library. It is written for security architects and auditors.

## 🏛️ 1. The FIPS 140 Boundary & Claim Limits

In enterprise software, the distinction between mathematical correctness and formal compliance is critical.

* **What we guarantee:** `pqcrypto` is a byte-for-byte exact, mathematically pure translation of the NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) specifications. If an algorithm generates a ciphertext or a signature, it will perfectly match the expected output defined in the official NIST Known Answer Test (KAT) corpus.
* **What we DO NOT guarantee:** This package is **NOT** a CMVP (Cryptographic Module Validation Program) certified module. CMVP validates specific, compiled hardware or software boundaries operating under strict OS configurations. Because Dart compiles to multiple disparate architectures (AOT ARM64, dart2js, dart2wasm), claiming "FIPS 140-3 Validation" at the source-code library level is legally and technically inaccurate.

If your industry requires a formal CMVP certificate, you must use a certified hardware module or OS-level library via FFI (e.g., AWS LC, BoringSSL), not a pure Dart package.

## 🛡️ 2. Threat Model: Side-Channel Attacks

A side-channel attack attempts to extract secret keys by observing physical characteristics of the execution (timing, power consumption, memory access patterns).

Because the Dart VM uses Just-In-Time (JIT) compilation and modern Ahead-Of-Time (AOT) compilers perform aggressive optimization, guaranteeing "constant-time execution" in Dart is practically impossible. Compilers will often optimize away branchless boolean logic into conditional jumps.

### Best-Effort Mitigations

Despite the platform limitations, we implement a defensive, best-effort side-channel posture:

1. **Implicit Rejection (ML-KEM):** In FIPS 203 decapsulation, if the ciphertext is tampered with, the algorithm must not reveal whether the failure occurred during the ciphertext check or the re-encryption check. We utilize bitwise masking (`mask = 0 - (isValid ? 1 : 0)`) to merge the correct shared secret and the implicit rejection secret without using `if/else` control flow.
2. **Polynomial Norm Checking (ML-DSA):** During the signature generation rejection loop, we evaluate the infinite norm of all 256 coefficients of the polynomial vectors. The `_normExceeds` function does not "early return" upon finding the first out-of-bounds coefficient; it evaluates the entire polynomial to prevent leaking the location of the failure via execution timing.
3. **Hedged Signatures:** ML-DSA is deterministic by default. This makes it highly vulnerable to physical fault injection (DPA). We strictly enforce **Hedged Signing** as the default mechanism. Fresh entropy is injected from `Random.secure()` alongside the message, masking the exact deterministic generation.

## 🧹 3. Memory Security & Zeroization

Languages with Garbage Collection (GC), like Dart, abstract away memory management. A `Uint8List` containing a secret key may be copied by the GC during memory compaction or left in RAM long after it is no longer referenced.

To minimize the window of exposure to memory-dump attacks (like Heartbleed or cold-boot attacks), `pqcrypto` implements explicit zeroization on sensitive intermediate buffers using `secureZero()`:

```dart
final z = Uint8List(32);
try {
  // ... perform decapsulation math ...
} finally {
  // The Dart compiler cannot reliably optimize away this loop
  // because the List is mutable.
  for (int i = 0; i < z.length; i++) {
    z[i] = 0;
  }
}
```

*Note: This only zeroes the primary allocated buffer. If the Dart VM copied the buffer internally, we cannot control the copy.*

## 🚨 4. Vulnerability Disclosure Policy

We treat all cryptographic defects as **P0 Critical**. 

If you discover a timing leak, a deviation from a KAT vector, or an RNG failure, **DO NOT** open a public issue or discuss it in the GitHub Discussions board.

Please refer to `SECURITY.md` in the root repository to obtain the PGP keys of the core maintainers and send an encrypted disclosure. We will coordinate a patch, request a CVE, and publish a security advisory.

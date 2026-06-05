# Welcome to the pqcrypto Wiki 🛡️

**`pqcrypto`** is a pure Dart, zero-dependency library implementing the next generation of cryptographic algorithms standardized by NIST for the post-quantum era.

As quantum computing matures, traditional asymmetric cryptography (like RSA and ECDSA) will become vulnerable to Shor's algorithm. `pqcrypto` provides drop-in, highly optimized, and mathematically proven algorithms to protect Dart and Flutter applications against these future threats.

## 🌟 The pqcrypto Mission

Our goal is to provide the Dart ecosystem with a **distinguished, enterprise-grade cryptographic boundary** that prioritizes correctness over convenience. 

We do not invent cryptography; we meticulously translate formal standards into safe, highly tested code. Every mathematical operation in this library is strictly validated against the official NIST Known Answer Tests (KATs) ensuring absolute byte-for-byte exactness.

---

## 🧭 Navigating the Wiki

If you are new to post-quantum cryptography or this library, we recommend reading through the wiki in this order:

1. **[Quickstart](Quickstart)**: How to install and immediately use ML-KEM and ML-DSA in your project.
2. **[Design Philosophy](Design-Philosophy)**: Why we enforce zero dependencies and how we structure our pure Dart approach.
3. **[Cryptographic Algorithms](Cryptographic-Algorithms)**: Deep technical dives into our FIPS 203 and FIPS 204 implementations.
4. **[Security Posture](Security-Posture)**: Our claims, boundaries, side-channel protections, and zeroization strategies.

## 📖 Deep Dives (Internal Documentation)

For maintainers and cryptography engineers wanting to look under the hood, the repository contains extensive architecture documents located in the `doc/` directory:

- [Engineering Guide](../blob/main/doc/ENGINEERING_GUIDE.md) - Internal implementation details.
- [Architecture](../blob/main/doc/ARCHITECTURE.md) - System design and polynomial arithmetic structures.
- [OpenSSL Interop](../blob/main/doc/OPENSSL_INTEROP.md) - How we validate our ML-KEM implementation against C/C++ OpenSSL via FFI.
- [FIPS 140 Boundary](../blob/main/doc/FIPS_140_BOUNDARY.md) - Explicit definitions of what compliance means for this library.

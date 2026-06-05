# Welcome to the pqcrypto Engineering Wiki 🛡️

**`pqcrypto`** is a pure Dart, zero-dependency cryptographic module implementing the next generation of algorithms standardized by NIST for the post-quantum era.

As quantum computing architectures scale, asymmetric algorithms relying on integer factorization (RSA) and discrete logarithms (ECDH, ECDSA) will become mathematically trivial to break using Shor's algorithm. `pqcrypto` provides drop-in, highly optimized, and mathematically proven algorithms to protect Dart backends and Flutter clients against these future threats today.

## 🌟 The Distinguished Mission

In cryptography, complexity is the enemy of security. Our engineering mandate is to provide the Dart ecosystem with an **enterprise-grade cryptographic boundary** that prioritizes mathematical correctness and auditability above all else. 

We do not invent cryptographic concepts; we meticulously translate formal standards into safe, highly tested Dart code. Every core operation in this library is strictly validated against the official NIST Known Answer Tests (KATs), ensuring absolute byte-for-byte exactness. We eschew external dependencies to completely eliminate supply-chain poisoning vectors.

---

## 🧭 Navigating the Documentation

We have organized the wiki to serve developers, security architects, and infrastructure engineers based on their deployment needs:

1. **[Quickstart](Quickstart)**: The immediate API surface. How to generate keys, encapsulate shared secrets, and sign payloads in a few lines of code.
2. **[Design Philosophy](Design-Philosophy)**: Our architectural tenets. Why we enforce zero dependencies, our stance on pure Dart portability, and our defensive "footgun-free" API defaults.
3. **[Cryptographic Algorithms](Cryptographic-Algorithms)**: Deep technical overviews of our FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) implementations, including parameter tables, NTT polynomial arithmetic, and HashML-DSA specifications.
4. **[Security Posture & Compliance](Security-Posture)**: The explicit boundary of our claims. Details on KAT testing, best-effort side-channel mitigation within the Dart VM, memory zeroization, and FIPS 140 limits.
5. **[Serverpod & Flutter Integration](Serverpod-Integration)**: A production-ready blueprint for hybrid handshakes, `.spy.yaml` serialization, replay defenses, and Flutter isolate offloading.
6. **[Multi-Agent PQC Framework](Multi-Agent-Framework)**: Our structured coordinate system for utilizing LLMs (like Antigravity and Codex) to build `pqcrypto` integrations safely.

## 📖 Deep Dives (Internal Documentation)

For core maintainers and cryptography engineers wanting to look at the math beneath the API, the repository contains extensive architecture documents located in the `doc/` directory:

- [Engineering Guide](../blob/main/doc/ENGINEERING_GUIDE.md) - Internal implementation details, BigInt constraints, and endianness handling.
- [Architecture](../blob/main/doc/ARCHITECTURE.md) - System design and low-level polynomial arithmetic structures.
- [OpenSSL Interop](../blob/main/doc/OPENSSL_INTEROP.md) - How we validate our ML-KEM implementation against C/C++ OpenSSL via Foreign Function Interfaces (FFI).
- [FIPS 140 Boundary](../blob/main/doc/FIPS_140_BOUNDARY.md) - Explicit definitions of compliance verbiage for this library.

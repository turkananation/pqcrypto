# pqcrypto Project Overview for AI Assistants

## Project Summary

pqcrypto is a pure Dart library implementing NIST-standardized post-quantum cryptographic algorithms:

- **ML-KEM (FIPS 203)**: Kyber-based key encapsulation mechanism - **PRODUCTION READY** with full NIST KAT compliance (3000/3000 vectors passing)
- **ML-DSA (FIPS 204)**: Dilithium-based digital signature algorithm - **IN DEVELOPMENT** with all critical issues recently resolved, awaiting NIST KAT validation
- **Version**: 0.1.0
- **Platforms**: Dart VM, Flutter, Web (dart2js/dart2wasm)
- **Dependencies**: Single dependency on pointycastle for SHA3/SHAKE primitives

## Architecture Overview

```text
lib/src/
├── algos/
│   ├── kyber/              # ML-KEM implementation (3 security levels: 512/768/1024)
│   │   ├── kem.dart        # Public API: generateKeyPair(), encapsulate(), decapsulate()
│   │   ├── indcpa.dart     # IND-CPA encryption (K-PKE)
│   │   ├── pack.dart       # FIPS 203 compression serialization (d ∈ {1,4,5,10,11,12})
│   │   └── params.dart     # Parameter sets (k, eta1, eta2, du, dv)
│   │
│   └── dilithium/          # ML-DSA implementation (3 security levels: 44/65/87)
│       ├── dsa.dart        # Public API: generateKeyPair(), sign(), verify()
│       ├── ntt.dart        # Complete NTT transform with 256 zetas
│       ├── poly.dart       # Polynomial arithmetic (Int32List, q=8380417)
│       ├── symmetric.dart  # Sampling functions (ExpandA/S, SampleInBall, rejection)
│       ├── packing.dart    # BitPack/SimpleBitPack serialization
│       ├── rounding.dart   # Power2Round, Decompose, Hints operations
│       └── params.dart     # Parameter sets with per-level tau (39/49/60)
│
└── common/
    ├── poly.dart           # Kyber polynomial (List<int>, q=3329, incomplete NTT)
    └── shake.dart          # SHAKE128/256 wrappers around pointycastle
```

### Design Principles

1. **Separate Polynomial Types**: Kyber uses `Poly` (ℤ₃₃₂₉[X]/(X²⁵⁶+1), incomplete NTT), Dilithium uses `DilithiumPoly` (ℤ₈₃₈₀₄₁₇[X]/(X²⁵⁶+1), complete NTT)
2. **Pure Modular Arithmetic**: No Montgomery reduction for simplicity (q² fits in 53 bits, ~2x performance trade-off acceptable)
3. **Static-Method Operations**: Crypto operations as static methods taking `Params` objects
4. **pointycastle Dependency**: Delegates complex Keccak-1600 to avoid reimplementation

## Key Components

### ML-KEM (Production Ready)

- **Matrix Generation**: SHAKE128-based SampleNTT with rejection
- **NTT Transforms**: Cooley-Tukey butterflies (128 degree-2 modules)
- **Polynomial Multiplication**: BaseMul with gamma-twisted coefficients
- **Security Features**: IND-CCA2 via implicit rejection, constant-time comparisons, domain separation

### ML-DSA (Near Production)

- **Complete FIPS 204 Coverage**: All algorithms implemented with per-level parameters
- **Recent Fixes**: Resolved 4 critical issues (tau constants, ExpandMask truncation, SampleInBall stream length, debug prints)
- **Remaining Issues**: Secret zeroization needed, constant-time `_checkNorm()`, verify RejNTTPoly encoding

## Development Guidelines

### Code Patterns

```dart
// High-level APIs
class KyberKem { ... }  // Instance-based
class MlDsa { ... }     // Static methods (to be refactored to instance-based)

// Factory shortcuts
final kem = PqcKem.kyber768;  // Returns KyberKem instance
final dsa = MlDsa(DilithiumParameter.mlDsa44);

// Parameter objects
class KyberParams { int k, eta1, eta2, du, dv; }
class DilithiumParams { int k, l, eta, tau, beta, omega, gamma1, gamma2; }
```

### Testing Standards

- Round-trip serialization tests (pack → unpack)
- Negative test cases (bad inputs, corrupted data)
- Integration tests (full sign/verify, encap/decap)
- Deterministic seeded tests for reproducibility
- Size validation for all key/ciphertext types

### Security Requirements

- Implement secret zeroization in `finally` blocks: `secret.fillRange(0, secret.length, 0)`
- Ensure constant-time operations (no early returns on validation)
- Use domain separation for all hash operations
- Validate against NIST KAT vectors before production release

## Performance Characteristics

### Benchmarks (Dart VM JIT)

| Operation   | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| ----------- |------------|------------|-------------|
| KeyGen      | ~0.7 ms    | ~1.3 ms    | ~1.8 ms     |
| Encapsulate |  ~0.7 ms   | ~1.4 ms    | ~1.8 ms     |
| Decapsulate | ~0.6 ms    | ~1.0 ms    | ~1.7 ms     |

**Hotspots**: NTT (35%), SHAKE matrix gen (25%), pointwise mul (20%)
**Optimizations**: Switch Kyber to Int32List, in-place NTT, batch Barrett reduction

## Security Considerations

- **HIGH**: No zeroization of secret key material (s1, s2, s2Hat in ML-DSA)
- **HIGH**: `_checkNorm()` has early-return timing side-channel
- **MEDIUM**: Incremental XOF not implemented (fixed-length SHAKE)
- **LOW**: RNG source is `Random.secure()` (platform CSPRNG, not formal DRBG)

## Roadmap & Priorities

- **v0.2.0**: ML-DSA KAT validation, zeroization, API consistency, constant-time operations
- **v0.3.0**: Performance optimizations, additional algorithms
- See `docs/ROADMAP.md` for detailed schedule
- See `docs/SECURITY_AUDIT.md` for complete findings
- See `docs/IMPROVEMENTS.md` for 8 specific recommendations

## Quick Reference

```bash
# Test commands
dart test                              # All tests
dart test test/pack_test.dart         # ML-KEM serialization
dart test test/dsa_sign_test.dart     # ML-DSA round-trip

# Run example
dart run example/main.dart            # Benchmarks

# Analyze
dart analyze                          # Lint checks
```

For detailed documentation, see `docs/` directory. This overview provides AI assistants with sufficient context to contribute effectively without duplicating comprehensive human-readable guides.

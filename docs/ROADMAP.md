# pqcrypto Release Roadmap

**Date**: 2026-03-13
**Current Version**: 0.1.0

---

## Version History

| Version | Date | Milestone |
|---------|------|-----------|
| 0.1.0 | Dec 2024 | Initial release: ML-KEM (FIPS 203) with 3000/3000 KAT |

---

## Planned Releases

### v0.2.0 - ML-DSA Production Release

**Target**: Q2 2026
**Theme**: Complete ML-DSA (FIPS 204) to production quality

| Task | Priority | Status |
|------|----------|--------|
| Fix `tau` parameter per security level | P0 | Open |
| Fix `ExpandMask` rho' truncation (64 bytes) | P0 | Open |
| Fix `SampleInBall` stream length | P0 | Open |
| Remove all debug `print()` statements | P0 | Open |
| Verify `RejNTTPoly` input encoding vs FIPS 204 | P0 | Open |
| Add input validation on all public APIs | P1 | Open |
| Implement instance-based `MlDsa` API (like `KyberKem`) | P1 | Open |
| Export ML-DSA through `pqcrypto.dart` | P1 | Open |
| Run NIST KAT vectors for ML-DSA-44/65/87 | P1 | Open |
| Update README with ML-DSA usage and compliance table | P2 | Open |
| Add comprehensive negative tests | P2 | Open |

**Release Criteria**:
- All three ML-DSA parameter sets pass NIST KAT vectors
- Sign/Verify round-trip for all levels
- Negative test coverage (bad sig, bad msg, bad pk)
- No `print()` in `lib/` directory
- API documentation for all public types

---

### v0.3.0 - Security Hardening

**Target**: Q3 2026
**Theme**: Production-grade security for both ML-KEM and ML-DSA

| Task | Priority | Status |
|------|----------|--------|
| Implement secret material zeroization | P1 | Open |
| Make ML-DSA `_checkNorm` constant-time | P1 | Open |
| Constant-time conditional select for ML-KEM decapsulation | P1 | Open |
| Add constant-time `decompose` for ML-DSA | P1 | Open |
| Cache `Random.secure()` instance | P2 | Open |
| Remove duplicate `KyberLevel` enum | P2 | Open |
| Add `@visibleForTesting` annotations | P2 | Open |
| Enable `avoid_print` lint rule | P2 | Open |
| Use `Int32List` for Kyber polynomials | P2 | Open |
| In-place Kyber NTT operations | P2 | Open |
| Comprehensive Dartdoc for public API | P2 | Open |
| Cross-platform CI (VM, dart2js, dart2wasm) | P2 | Open |

**Release Criteria**:
- All public APIs have Dartdoc
- No timing-dependent branches in cryptographic code
- All secret buffers zeroized after use
- CI green on all target platforms

---

### v0.4.0 - SLH-DSA (SPHINCS+)

**Target**: Q4 2026
**Theme**: Add hash-based signatures (FIPS 205)

| Task | Priority | Status |
|------|----------|--------|
| Implement WOTS+ chain function | P1 | Open |
| Implement XMSS tree | P1 | Open |
| Implement FORS | P1 | Open |
| Implement Hypertree | P1 | Open |
| Implement SLH-DSA KeyGen/Sign/Verify | P1 | Open |
| Support SLH-DSA-128s/128f parameter sets | P1 | Open |
| Support SLH-DSA-192s/256f parameter sets | P2 | Open |
| NIST KAT validation | P1 | Open |
| Export through `pqcrypto.dart` | P1 | Open |

**Release Criteria**:
- At least SLH-DSA-128s and SLH-DSA-128f pass NIST KAT
- Performance benchmarks documented
- API follows established patterns

---

### v0.5.0 - Performance Optimization

**Target**: Q1 2027
**Theme**: Significant performance improvements

| Task | Priority | Status |
|------|----------|--------|
| Native SHAKE via `dart:ffi` (mobile/desktop) | P1 | Open |
| WebAssembly NTT kernel for web targets | P2 | Open |
| Lazy Barrett reduction in NTT | P2 | Open |
| Pre-computed matrix caching API | P2 | Open |
| Object pooling for polynomial buffers | P3 | Open |
| Benchmark suite with regression tracking | P2 | Open |
| AOT compilation testing and optimization | P2 | Open |

**Release Criteria**:
- 2x improvement on native platforms (via FFI SHAKE)
- 1.5x improvement on web (via Wasm NTT)
- Automated benchmark tracking in CI

---

### v1.0.0 - Production Stable

**Target**: Q2 2027
**Theme**: Stable API, full NIST suite, production-ready

| Task | Priority | Status |
|------|----------|--------|
| Stable API (no breaking changes after 1.0) | P0 | Open |
| Complete NIST KAT for all algorithms and levels | P0 | Open |
| Security audit by external reviewer | P0 | Open |
| HQC KEM implementation (if NIST finalizes) | P1 | Open |
| CONTRIBUTING.md and governance | P2 | Open |
| pub.dev publishing | P1 | Open |
| Semantic versioning compliance | P1 | Open |

---

### v1.1.0+ - Extended Algorithms

**Target**: 2027+
**Theme**: Complete PQC algorithm suite

| Task | Target |
|------|--------|
| FN-DSA (FALCON) when FIPS 206 is finalized | v1.1.0 |
| Hybrid KEM (ML-KEM + X25519) | v1.2.0 |
| Hybrid DSA (ML-DSA + Ed25519) | v1.2.0 |
| BIKE (Round 4 candidate) if selected | v1.3.0 |
| Classic McEliece (if practical) | Evaluate |

---

## Long-Term Vision

```
2024    2025    2026         2027        2028+
  |-------|-------|------------|-----------|--------->
  v0.1    |      v0.2        v1.0       v1.x
  ML-KEM  |      ML-DSA      Stable     Hybrid
          |      SLH-DSA     HQC        FN-DSA
          |      Security    Perf       FIPS 140-3
          |                  Audit
          |
    Community growth
    Serverpod integration
    Flutter ecosystem
```

---

## Resource Requirements

| Phase | Engineering Effort | Skills Needed |
|-------|-------------------|---------------|
| v0.2 (ML-DSA fix) | 1-2 weeks | Dart, FIPS 204 spec knowledge |
| v0.3 (Security) | 2-3 weeks | Side-channel analysis, Dart FFI |
| v0.4 (SLH-DSA) | 3-4 weeks | Hash-based crypto, Merkle trees |
| v0.5 (Performance) | 3-4 weeks | C/Rust FFI, WASM, SIMD |
| v1.0 (Stable) | 2-3 weeks | Testing, documentation |
| External audit | 4-8 weeks | Contracted security firm |

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| NIST revises FIPS 204 before v0.2 | Low | High | Monitor NIST announcements |
| `pointycastle` SHA-3 bug found | Low | Critical | Fork or replace with own impl |
| Dart `Int32List` JS semantics change | Very Low | High | Pin Dart SDK version |
| FN-DSA spec delayed beyond 2027 | Medium | Low | Deprioritize, focus on SLH-DSA |
| Side-channel in pure Dart deemed unfixable | Medium | Medium | Document limitations, offer FFI path |
| HQC spec changes significantly | Low | Medium | Wait for final before implementing |

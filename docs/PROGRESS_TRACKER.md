# pqcrypto Master Progress Tracker

**Last Updated**: 2026-03-13
**Version**: 0.1.0

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| :x: | Not started |
| :hourglass: | In progress |
| :white_check_mark: | Complete |
| :warning: | Blocked / Needs decision |

---

## PHASE 0: Critical Fixes (Quick Wins - ~37 min total)

*Eliminates all 4 Critical findings. Do these first.*

| # | Task | File(s) | Time | Severity | Source | Status |
|---|------|---------|------|----------|--------|--------|
| QW-01 | Add `tau` field to `DilithiumParams` (39/49/60) | params.dart, dsa.dart | 5 min | CRITICAL | SECURITY_AUDIT CRIT-01, BUG-001 | :x: |
| QW-02 | Delete all `print()` from dsa.dart + packing.dart | dsa.dart, packing.dart | 10 min | CRITICAL | SECURITY_AUDIT CRIT-02, BUG-006 | :x: |
| QW-03 | Increase `SampleInBall` stream from 256 to 840 bytes | symmetric.dart:357 | 2 min | HIGH | SECURITY_AUDIT CRIT-03, BUG-003 | :x: |
| QW-04 | Fix `_rejGamma1` input buffer from 32+2 to 64+2 | symmetric.dart:220-223 | 3 min | CRITICAL | SECURITY_AUDIT CRIT-04, BUG-002 | :x: |
| QW-05 | Export ML-DSA types in `pqcrypto.dart` | pqcrypto.dart | 1 min | MEDIUM | BUG-012, IMP-04 | :x: |
| QW-06 | Remove dead 34-byte input buffer in `_rejNttPoly` | symmetric.dart:59-63 | 2 min | LOW | BUG-004, IMP-10 | :x: |
| QW-07 | Remove duplicate `KyberLevel` enum from params.dart | kyber/params.dart:27 | 1 min | LOW | BUG-007, IMP-10 | :x: |
| QW-08 | Replace placeholder library docstring | pqcrypto.dart:1-4 | 1 min | LOW | BUG-011, IMP-18 | :x: |
| QW-09 | Add `avoid_print` lint rule | analysis_options.yaml | 2 min | MEDIUM | IMP-13 | :x: |
| QW-10 | Add input size validation to KEM public API | kem.dart | 10 min | HIGH | SECURITY_AUDIT HIGH-02 | :x: |

**Phase 0 Total**: ~37 minutes | Resolves: 4 Critical, 2 High, 2 Medium, 3 Low findings

---

## PHASE 1: ML-DSA Correctness (Target: v0.2.0)

*Goal: All 3 ML-DSA levels pass NIST KAT vectors.*

| # | Task | File(s) | Effort | Source | Status |
|---|------|---------|--------|--------|--------|
| 1.1 | Verify `_rejNttPoly` input encoding (1-byte vs 2-byte indices) against FIPS 204 final | symmetric.dart:53-111 | 2 hrs | BUG-004, COMPLIANCE | :x: |
| 1.2 | Verify `t0` pack/unpack round-trip through full KeyGen->Sign->Verify | packing.dart:219-293 | 2 hrs | BUG-005 | :x: |
| 1.3 | Verify `decompose` edge cases (r - r0 == q-1) | rounding.dart:40-119 | 1 hr | COMPLIANCE Alg 4 | :x: |
| 1.4 | Refactor `MlDsa` to instance-based API (match `KyberKem` pattern) | dsa.dart | 3 hrs | IMP-06 | :x: |
| 1.5 | Add `tau`, `signatureBytes`, `publicKeyBytes`, `secretKeyBytes` to `DilithiumParams` | params.dart | 1 hr | IMP-01 | :x: |
| 1.6 | Implement ML-DSA NIST KAT evaluator | test/dsa_kat_evaluator.dart (new) | 4 hrs | IMP-14, COMPLIANCE | :x: |
| 1.7 | Download and run NIST KAT vectors for ML-DSA-44 | test/data/ | 2 hrs | COMPLIANCE | :x: |
| 1.8 | Run NIST KAT vectors for ML-DSA-65 | test/data/ | 1 hr | COMPLIANCE | :x: |
| 1.9 | Run NIST KAT vectors for ML-DSA-87 | test/data/ | 1 hr | COMPLIANCE | :x: |
| 1.10 | Update README with ML-DSA status table and usage examples | README.md | 1 hr | IMP-19 | :x: |
| 1.11 | Add negative tests (bad sig, bad msg, wrong pk, truncated inputs) | test/dsa_sign_test.dart | 2 hrs | IMP-16 | :x: |
| 1.12 | Remove unused import in indcpa.dart | indcpa.dart:7 | 1 min | BUG-013 | :x: |

**Phase 1 Total**: ~20 hours

---

## PHASE 2: Security Hardening (Target: v0.3.0)

*Goal: Constant-time operations, secret zeroization, hardened public API.*

| # | Task | File(s) | Effort | Source | Status |
|---|------|---------|--------|--------|--------|
| 2.1 | Implement `secureZero()` / `secureZeroInt32()` utilities | common/utils.dart (new) | 30 min | IMP-07, HIGH-01 | :x: |
| 2.2 | Add zeroization to ML-KEM KeyGen (rhoSigma, sigma) | indcpa.dart, kem.dart | 1 hr | IMP-07 | :x: |
| 2.3 | Add zeroization to ML-KEM Decaps (mPrime, kPrime, rPrime) | kem.dart | 1 hr | IMP-07 | :x: |
| 2.4 | Add zeroization to ML-DSA KeyGen (rhoPrime, kKey) | dsa.dart | 1 hr | IMP-07 | :x: |
| 2.5 | Add zeroization to ML-DSA Sign (all intermediates) | dsa.dart | 1 hr | IMP-07 | :x: |
| 2.6 | Make `_checkNorm` constant-time (accumulate flag, no early return) | dsa.dart:463-480 | 30 min | IMP-08, HIGH-03 | :x: |
| 2.7 | Make `decompose` constant-time (eliminate branch on q-1) | rounding.dart:40-119 | 1 hr | SECURITY_AUDIT | :x: |
| 2.8 | Add constant-time conditional select to ML-KEM decaps | kem.dart | 30 min | IMP-09 | :x: |
| 2.9 | Cache `Random.secure()` instance (avoid per-call allocation) | kem.dart:148 | 15 min | MED-01 | :x: |
| 2.10 | Add input validation to ML-DSA public API | dsa.dart | 1 hr | IMP-03 | :x: |
| 2.11 | Switch Kyber `List<int>` to `Int32List` for polynomials | common/poly.dart | 3 hrs | OPT-01 | :x: |
| 2.12 | Make Kyber NTT in-place (eliminate copy allocation) | common/poly.dart | 2 hrs | OPT-02 | :x: |
| 2.13 | Implement incremental SHAKE squeezing for `_sampleNTT` fallback | indcpa.dart:207-235 | 4 hrs | MED-02 | :x: |

**Phase 2 Total**: ~17 hours

---

## PHASE 3: Code Quality & Testing (Target: v0.3.0)

| # | Task | File(s) | Effort | Source | Status |
|---|------|---------|--------|--------|--------|
| 3.1 | Add `@visibleForTesting` annotations | indcpa.dart, symmetric.dart | 30 min | IMP-12 | :x: |
| 3.2 | Add comprehensive Dartdoc to all public classes/methods | All public API files | 4 hrs | IMP-11 | :x: |
| 3.3 | Enable strict linter rules (`prefer_final_locals`, etc.) | analysis_options.yaml | 30 min | IMP-13 | :x: |
| 3.4 | Add cross-platform CI (Linux, macOS, Windows, Chrome) | .github/workflows/ (new) | 2 hrs | IMP-15, ENGINEERING | :x: |
| 3.5 | Add performance regression benchmarks | test/ or benchmark/ (new) | 2 hrs | IMP-17 | :x: |
| 3.6 | Fix example shared secret comparison (use proper comparison) | example/main.dart:31 | 5 min | BUG-008 | :x: |
| 3.7 | Create CONTRIBUTING.md | CONTRIBUTING.md (new) | 1 hr | IMP-20 | :x: |

**Phase 3 Total**: ~10.5 hours

---

## PHASE 4: SLH-DSA Implementation (Target: v0.4.0)

| # | Task | File(s) | Effort | Source | Status |
|---|------|---------|--------|--------|--------|
| 4.1 | Design SLH-DSA module structure and params | lib/src/algos/sphincs/ (new) | 4 hrs | ALGO_EXPANSION | :x: |
| 4.2 | Implement ADRS (address) structure | sphincs/address.dart | 2 hrs | ALGO_EXPANSION | :x: |
| 4.3 | Implement WOTS+ chain function and keygen | sphincs/wots.dart | 8 hrs | ALGO_EXPANSION | :x: |
| 4.4 | Implement XMSS tree construction | sphincs/xmss.dart | 8 hrs | ALGO_EXPANSION | :x: |
| 4.5 | Implement FORS signing and verification | sphincs/fors.dart | 8 hrs | ALGO_EXPANSION | :x: |
| 4.6 | Implement Hypertree multi-layer structure | sphincs/hypertree.dart | 8 hrs | ALGO_EXPANSION | :x: |
| 4.7 | Build SLH-DSA.KeyGen / Sign / Verify | sphincs/slh_dsa.dart | 8 hrs | ALGO_EXPANSION | :x: |
| 4.8 | Implement SLH-DSA-128s and SLH-DSA-128f parameter sets | sphincs/params.dart | 2 hrs | ALGO_EXPANSION | :x: |
| 4.9 | Run NIST KAT for SLH-DSA | test/slh_dsa_kat.dart (new) | 4 hrs | ALGO_EXPANSION | :x: |
| 4.10 | Export SLH-DSA through pqcrypto.dart | pqcrypto.dart | 15 min | ALGO_EXPANSION | :x: |

**Phase 4 Total**: ~52 hours

---

## PHASE 5: Performance Optimization (Target: v0.5.0)

| # | Task | File(s) | Effort | Source | Status |
|---|------|---------|--------|--------|--------|
| 5.1 | Native SHAKE-128/256 via `dart:ffi` (OpenSSL/XKCP) | common/shake_native.dart (new) | 16 hrs | OPT-05 | :x: |
| 5.2 | Conditional import: native SHAKE on VM, pure Dart on web | common/shake.dart | 2 hrs | OPT-05 | :x: |
| 5.3 | Lazy Barrett reduction (defer to every other NTT layer) | common/poly.dart | 4 hrs | OPT-04 | :x: |
| 5.4 | Pre-computed matrix caching API for repeated encapsulations | kyber/kem.dart | 4 hrs | OPT-03 | :x: |
| 5.5 | Wasm NTT kernel for web deployment | tool/ntt_kernel/ (new) | 16 hrs | OPT-06 | :x: |
| 5.6 | Object pooling for polynomial buffers | common/pool.dart (new) | 4 hrs | OPT-09 | :x: |
| 5.7 | Automated benchmark suite with regression tracking | benchmark/ (new) | 4 hrs | PERFORMANCE | :x: |
| 5.8 | AOT compilation testing and optimization | CI/CD | 2 hrs | PERFORMANCE | :x: |

**Phase 5 Total**: ~52 hours

---

## PHASE 6: Stable Release & Beyond (Target: v1.0.0+)

| # | Task | Effort | Source | Status |
|---|------|--------|--------|--------|
| 6.1 | Freeze public API (no breaking changes after 1.0) | 2 hrs | ROADMAP | :x: |
| 6.2 | Complete NIST KAT for ALL algorithms and ALL levels | 8 hrs | ROADMAP | :x: |
| 6.3 | External security audit engagement | 4-8 wks | ROADMAP | :x: |
| 6.4 | HQC KEM implementation (code-based) | ~60 hrs | ALGO_EXPANSION | :x: |
| 6.5 | FN-DSA (FALCON) implementation (after FIPS 206 final) | ~80 hrs | ALGO_EXPANSION | :x: |
| 6.6 | Hybrid KEM (ML-KEM + X25519) | ~20 hrs | ROADMAP | :x: |
| 6.7 | Hybrid DSA (ML-DSA + Ed25519) | ~20 hrs | ROADMAP | :x: |
| 6.8 | Publish to pub.dev | 2 hrs | ROADMAP | :x: |

---

## Cross-Reference: All Items by Source Document

### From SECURITY_AUDIT.md (14 findings)

| Finding | Severity | Tracker Item | Status |
|---------|----------|-------------|--------|
| CRIT-01: tau global constant | CRITICAL | QW-01 | :x: |
| CRIT-02: Debug print() leaks | CRITICAL | QW-02 | :x: |
| CRIT-03: SampleInBall stream short | CRITICAL | QW-03 | :x: |
| CRIT-04: ExpandMask rho' truncated | CRITICAL | QW-04 | :x: |
| HIGH-01: No secret zeroization | HIGH | 2.1-2.5 | :x: |
| HIGH-02: No input size validation | HIGH | QW-10, 2.10 | :x: |
| HIGH-03: _checkNorm non-constant-time | HIGH | 2.6 | :x: |
| MED-01: Random.secure() per-call | MEDIUM | 2.9 | :x: |
| MED-02: Fixed stream length in _sampleNTT | MEDIUM | 2.13 | :x: |
| MED-03: KyberLevel duplicate enum | MEDIUM | QW-07 | :x: |
| MED-04: _rejNttPoly double input buffer | MEDIUM | QW-06 | :x: |
| LOW-01: Barrett may exceed q | LOW | 2.12 | :x: |
| LOW-02: _listEquals non-CT (test only) | LOW | N/A | :x: |
| LOW-03: _polySub single reduction | LOW | 2.12 | :x: |

### From BUGS.md (13 bugs)

| Bug | Severity | Tracker Item | Status |
|-----|----------|-------------|--------|
| BUG-001: tau global | CRITICAL | QW-01 | :x: |
| BUG-002: ExpandMask rho' | CRITICAL | QW-04 | :x: |
| BUG-003: SampleInBall stream | HIGH | QW-03 | :x: |
| BUG-004: _rejNttPoly encoding | MEDIUM | QW-06, 1.1 | :x: |
| BUG-005: t0 packing sign | HIGH | 1.2 | :x: |
| BUG-006: Debug prints | CRITICAL | QW-02 | :x: |
| BUG-007: KyberLevel duplicate | LOW | QW-07 | :x: |
| BUG-008: toString() comparison | LOW | 3.6 | :x: |
| BUG-009: hashVec k vs l | LOW | QW-02 (removed with prints) | :x: |
| BUG-010: Unused debug vars | LOW | QW-02 (removed with prints) | :x: |
| BUG-011: Placeholder docstring | LOW | QW-08 | :x: |
| BUG-012: ML-DSA not exported | MEDIUM | QW-05 | :x: |
| BUG-013: Unused import | LOW | 1.12 | :x: |

### From IMPROVEMENTS.md (20 improvements + 10 quick wins)

| ID | Category | Tracker Item | Status |
|----|----------|-------------|--------|
| IMP-01 | Correctness | 1.5 | :x: |
| IMP-02 | Correctness | QW-02 | :x: |
| IMP-03 | Correctness | QW-10, 2.10 | :x: |
| IMP-04 | API | QW-05 | :x: |
| IMP-05 | API | 1.4 | :x: |
| IMP-06 | API | 1.4 | :x: |
| IMP-07 | Security | 2.1-2.5 | :x: |
| IMP-08 | Security | 2.6 | :x: |
| IMP-09 | Security | 2.8 | :x: |
| IMP-10 | Quality | QW-06, QW-07 | :x: |
| IMP-11 | Quality | 3.2 | :x: |
| IMP-12 | Quality | 3.1 | :x: |
| IMP-13 | Quality | QW-09, 3.3 | :x: |
| IMP-14 | Testing | 1.6 | :x: |
| IMP-15 | Testing | 3.4 | :x: |
| IMP-16 | Testing | 1.11 | :x: |
| IMP-17 | Testing | 3.5 | :x: |
| IMP-18 | Docs | QW-08 | :x: |
| IMP-19 | Docs | 1.10 | :x: |
| IMP-20 | Docs | 3.7 | :x: |

---

## Metrics

| Metric | Current | After Phase 0 | After Phase 1 | After Phase 2 | v1.0 Target |
|--------|---------|--------------|--------------|--------------|-------------|
| Critical findings | 4 | **0** | 0 | 0 | 0 |
| High findings | 3 | 1 | 0 | 0 | 0 |
| Medium findings | 4 | 1 | 0 | 0 | 0 |
| Low findings | 3 | 0 | 0 | 0 | 0 |
| ML-KEM KAT pass | 3000/3000 | 3000/3000 | 3000/3000 | 3000/3000 | 3000/3000 |
| ML-DSA KAT pass | 0/? | 0/? | ?/? (target all) | All | All |
| SLH-DSA KAT pass | - | - | - | - | All |
| Algorithms exported | 1 (ML-KEM) | 2 (+ML-DSA) | 2 | 2 | 3+ |
| Test files | 8 | 8 | 10+ | 12+ | 15+ |
| print() in lib/ | ~23 | **0** | 0 | 0 | 0 |
| Public API Dartdoc | ~10% | ~10% | ~30% | ~90% | 100% |

---

## Time Investment Summary

| Phase | Effort | Cumulative | Target Release |
|-------|--------|-----------|----------------|
| Phase 0 (Quick Wins) | **37 min** | 37 min | Immediate |
| Phase 1 (ML-DSA Fix) | ~20 hrs | ~21 hrs | v0.2.0 |
| Phase 2 (Security) | ~17 hrs | ~38 hrs | v0.3.0 |
| Phase 3 (Quality) | ~10.5 hrs | ~49 hrs | v0.3.0 |
| Phase 4 (SLH-DSA) | ~52 hrs | ~101 hrs | v0.4.0 |
| Phase 5 (Performance) | ~52 hrs | ~153 hrs | v0.5.0 |
| Phase 6 (Stable+) | ~190+ hrs | ~343+ hrs | v1.0.0+ |

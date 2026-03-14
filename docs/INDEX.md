# pqcrypto Documentation Index

**Pure Dart Post-Quantum Cryptography Library**
**Version**: 0.1.0 | **Date**: 2026-03-14

---

## Documents

| Document | Description | Audience |
| -------- | ----------- | -------- |
| [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) | **Master tracker**: every task, bug, and improvement across all phases | Everyone |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | Full security audit: 4 Critical, 3 High, 4 Medium, 3 Low findings | Security engineers, maintainers |
| [BUGS.md](BUGS.md) | All known bugs with reproduction steps and fix guidance | Developers |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, module dependencies, data flow diagrams | Contributors, architects |
| [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md) | Algorithm-by-algorithm FIPS 203/204 compliance status | Compliance officers, auditors |
| [PERFORMANCE.md](PERFORMANCE.md) | Benchmarks, bottleneck analysis, optimization roadmap | Performance engineers |
| [IMPROVEMENTS.md](IMPROVEMENTS.md) | Recommendations + 10 Quick Wins (37 min to eliminate all Critical findings) | All developers |
| [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md) | How to implement SLH-DSA, FN-DSA, HQC, and other PQC algorithms | Crypto implementers |
| [ROADMAP.md](ROADMAP.md) | Release schedule from v0.2.0 through v1.0.0+ | Project managers, stakeholders |
| [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md) | Development setup, conventions, math reference, CI/CD | New contributors |

---

## Quick Links

### For Security Reviewers

Start with [SECURITY_AUDIT.md](SECURITY_AUDIT.md), then [FIPS_COMPLIANCE.md](FIPS_COMPLIANCE.md).

### For New Contributors

Start with [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md), then [ARCHITECTURE.md](ARCHITECTURE.md).

### For Project Planning

Start with [ROADMAP.md](ROADMAP.md), then [ALGORITHM_EXPANSION_GUIDE.md](ALGORITHM_EXPANSION_GUIDE.md).

### For Bug Fixes

Start with [BUGS.md](BUGS.md), then [IMPROVEMENTS.md](IMPROVEMENTS.md).

---

## Summary of Findings

### ML-KEM (FIPS 203): Production Quality

- 3000/3000 NIST KAT vectors passing
- Correct IND-CCA2 security with implicit rejection
- Constant-time ciphertext comparison
- Minor issues: input validation, memory zeroization

### ML-DSA (FIPS 204): In Development - 4 Critical Issues

1. `tau` hardcoded as global constant (wrong for ML-DSA-65/87)
2. Debug `print()` statements leak cryptographic intermediates
3. `SampleInBall` stream too short for ML-DSA-87
4. `ExpandMask` truncates 64-byte `rho'` to 32 bytes

### Next Milestone: v0.2.0

Fix all ML-DSA critical issues and validate against NIST KAT vectors.

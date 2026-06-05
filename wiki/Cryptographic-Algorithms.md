# Cryptographic Algorithms

This page details the specific cryptographic implementations within `pqcrypto` and their adherence to NIST standards.

## ML-KEM (FIPS 203)
**Module-Lattice-Based Key-Encapsulation Mechanism** (formerly Kyber).

### Purpose
Used for securely exchanging symmetric keys (shared secrets) over untrusted networks. It replaces ECDH (Elliptic Curve Diffie-Hellman) and RSA Key Exchange.

### Supported Parameter Sets
- **ML-KEM-512**: Equivalent to AES-128 security.
- **ML-KEM-768**: Equivalent to AES-192 security. (Recommended default)
- **ML-KEM-1024**: Equivalent to AES-256 security.

### Implementation Details
- Uses Barrett reduction for modular arithmetic ensuring canonical residues.
- Implements the FIPS 203 `ByteEncode₁₂` and `ByteDecode₁₂` for strict validation.
- Employs a constant-time, branchless mask during decapsulation to prevent side-channel timing leaks between success and implicit rejection paths.

---

## ML-DSA (FIPS 204)
**Module-Lattice-Based Digital Signature Standard** (formerly CRYSTALS-Dilithium).

### Purpose
Used to authenticate digital documents, binaries, and network payloads. It replaces ECDSA and RSA signatures.

### Supported Parameter Sets
- **ML-DSA-44**: Equivalent to SHA3-256 security.
- **ML-DSA-65**: Equivalent to AES-192 security. (Recommended default)
- **ML-DSA-87**: Equivalent to AES-256 security.

### Implementation Details
- **Hedged Signing**: By default, `sign()` introduces fresh entropy (`Random.secure()`) alongside the message, mitigating physical fault attacks while maintaining deterministic fallback logic.
- **Context Strings**: Supports FIPS 204 domain separation via context strings (up to 255 bytes).
- **HashML-DSA**: Fully implements the §5.4 pre-hash variant for extremely large payloads, natively supporting SHA-256, SHA-384, and SHA-512 OIDs.
- Rejection samplers use incremental SHAKE XOF streams, preventing buffer exhaustion on rare polynomial edge cases.

---

## SLH-DSA (FIPS 205) - *Coming Soon in v0.4.0*
**Stateless Hash-Based Digital Signature Algorithm** (formerly SPHINCS+).

Unlike ML-DSA which relies on Lattice-based math, SLH-DSA relies entirely on the security of cryptographic hash functions (SHA-2 and SHAKE). It serves as a conservative fallback standard in the unlikely event that lattice cryptography is mathematically compromised.

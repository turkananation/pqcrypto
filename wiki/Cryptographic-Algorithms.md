# Cryptographic Algorithms

The `pqcrypto` suite replaces discrete-logarithm and integer-factorization algorithms (like ECDH, ECDSA, and RSA) with post-quantum equivalents standardized by the National Institute of Standards and Technology (NIST).

## 🧮 1. ML-KEM (FIPS 203) - Key Encapsulation
**Module-Lattice-Based Key-Encapsulation Mechanism** (Formerly known as CRYSTALS-Kyber).

### Architecture & Memory
ML-KEM operates over a polynomial ring $\mathbb{Z}_q[X]/(X^{256} + 1)$ with modulus $q = 3329$. To perform polynomial multiplication efficiently, the library uses the **Number Theoretic Transform (NTT)**.

We represent polynomials as `Int16List` arrays in Dart to ensure continuous memory allocation and cache locality, allowing the AOT compiler to vectorize the NTT butterfly operations where possible on ARM64/x64 targets.

### Supported Parameters & Security
| Parameter Set | Security Level | Public Key | Secret Key | Ciphertext |
|--------------|----------------|------------|------------|------------|
| **ML-KEM-512** | AES-128 | 800 bytes | 1632 bytes | 768 bytes |
| **ML-KEM-768** | AES-192 *(Default)* | 1184 bytes | 2400 bytes | 1088 bytes |
| **ML-KEM-1024** | AES-256 | 1568 bytes | 3168 bytes | 1568 bytes |

*Note: The secret key length includes the implicit rejection secret and the public key components required by FIPS 203.*

---

## ✍️ 2. ML-DSA (FIPS 204) - Digital Signatures
**Module-Lattice-Based Digital Signature Standard** (Formerly known as CRYSTALS-Dilithium).

### Architecture & Rejection Sampling
ML-DSA utilizes the "Fiat-Shamir with Aborts" paradigm. During signing, the algorithm generates polynomial vectors using an extensible output function (XOF). If the resulting signature reveals information about the secret key (violating the required security bounds), the signature is discarded, and the loop restarts.

**Our Implementation:**
- We utilize an incremental, stream-based **SHAKE XOF** state. If a signature is rejected, we do not re-initialize the hash state; we absorb the next block. This prevents heap exhaustion.
- The `ExpandA` and `ExpandS` functions are tightly constrained to avoid generating excess polynomial coefficients.

### HashML-DSA (Pre-Hashing)
For extremely large files or streaming payloads, hashing the entire message in memory before signing is unfeasible. We fully implement **§5.4 HashML-DSA**.

You must explicitly provide the Object Identifier (OID) of the pre-hash function.
```dart
final signature = MlDsa.hashSign(
  preHash: sha512HashOfPayload,
  secretKey: keyPair.secretKey,
  oid: MlDsaOid.sha512, 
);
```

### Supported Parameters & Security
| Parameter Set | Security Level | Public Key | Secret Key | Signature |
|--------------|----------------|------------|------------|------------|
| **ML-DSA-44** | SHA3-256 | 1312 bytes | 2560 bytes | 2420 bytes |
| **ML-DSA-65** | AES-192 *(Default)*| 1952 bytes | 4032 bytes | 3309 bytes |
| **ML-DSA-87** | AES-256 | 2592 bytes | 4896 bytes | 4627 bytes |

---

## ⛓️ 3. SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures

Status: planned — the SHAKE family targets release v0.4.0 and the SHA-2 family v0.5.0.

**Stateless Hash-Based Digital Signature Algorithm** (Formerly SPHINCS+).

Unlike ML-DSA which relies on the mathematical hardness of the Module Learning With Errors (MLWE) problem, SLH-DSA derives its security *entirely* from the collision resistance of cryptographic hash functions.

It is highly conservative and acts as the ultimate fallback. It features very small keys (under 100 bytes) but massive signatures (up to 49 KB) and slow signing times. 

**Implementation Roadmap:**
- Integration of WOTS+ (Winternitz One-Time Signatures) and XMSS (Extended Merkle Signature Scheme).
- Support for the FORS (Forest of Random Subsets) structure.
- Hardcoded pure Dart SHAKE and SHA-2 core primitives.

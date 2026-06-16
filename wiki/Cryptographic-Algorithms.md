# Cryptographic Algorithms

`pqcrypto` implements the post-quantum algorithms NIST selected to replace the
classical asymmetric primitives (RSA, ECDH, ECDSA) that a large quantum computer
would break. Today the package ships two of them, each byte-exact against the
official NIST Known-Answer-Test vectors.

| Algorithm | Standard | Purpose                 | Replaces      | Deep dive                        |
| --------- | -------- | ----------------------- | ------------- | -------------------------------- |
| ML-KEM    | FIPS 203 | Key encapsulation (KEM) | RSA-KEM, ECDH | [ML-KEM](ML-KEM)                 |
| ML-DSA    | FIPS 204 | Digital signatures      | RSA, ECDSA    | [ML-DSA](ML-DSA)                 |
| SLH-DSA   | FIPS 205 | Hash-based signatures   | (diversifier) | planned — see [Roadmap](Roadmap) |

Both shipped algorithms are lattice schemes built on the Module Learning With
Errors (MLWE) problem, sharing the same vendored FIPS 202 (SHA-3/SHAKE) core.

## When to use which

- Need two parties to agree on a **secret key** (then encrypt with an AEAD)?
  Use **ML-KEM**. See [ML-KEM](ML-KEM) and the
  [Cookbook](Cookbook) encrypt-to-public-key recipe.
- Need to prove a message's **authenticity / integrity** (tokens, updates,
  documents, records)? Use **ML-DSA**. See [ML-DSA](ML-DSA).
- Building a transport handshake? Combine **both** with an app-supplied
  classical exchange (hybrid) — see [Serverpod & Flutter](Serverpod-Integration).

## ML-KEM (FIPS 203) — key encapsulation

Module-Lattice-Based Key-Encapsulation Mechanism (formerly CRYSTALS-Kyber).
Operates over the ring `Z_q[X]/(X^256 + 1)` with `q = 3329`, using the Number
Theoretic Transform (NTT) for fast polynomial multiplication and the
Fujisaki–Okamoto transform (with constant-time implicit rejection) for IND-CCA2
security.

| Parameter set | NIST category | Public key | Secret key | Ciphertext | Shared secret |
| ------------- | ------------- | ---------- | ---------- | ---------- | ------------- |
| ML-KEM-512    | 1 (~AES-128)  | 800        | 1632       | 768        | 32            |
| ML-KEM-768    | 3 (~AES-192)  | 1184       | 2400       | 1088       | 32            |
| ML-KEM-1024   | 5 (~AES-256)  | 1568       | 3168       | 1568       | 32            |

Full details, data-flow diagram, and caveats: **[ML-KEM](ML-KEM)**.

## ML-DSA (FIPS 204) — digital signatures

Module-Lattice-Based Digital Signature Standard (formerly CRYSTALS-Dilithium).
Uses the "Fiat–Shamir with Aborts" paradigm: signing samples masking vectors
from a SHAKE XOF and rejection-samples until the signature reveals nothing about
the secret key. Signing is **hedged by default**.

| Parameter set | NIST category | Public key | Secret key | Signature |
| ------------- | ------------- | ---------- | ---------- | --------- |
| ML-DSA-44     | 2             | 1312       | 2560       | 2420      |
| ML-DSA-65     | 3             | 1952       | 4032       | 3309      |
| ML-DSA-87     | 5             | 2592       | 4896       | 4627      |

`HashML-DSA` (FIPS 204 §5.4) pre-hashes large messages with the level's approved
hash (SHA-256/384/512). Full details: **[ML-DSA](ML-DSA)**.

## SLH-DSA (FIPS 205)

Stateless Hash-Based Digital Signatures (formerly SPHINCS+). It derives security
*entirely* from hash-function assumptions, making it a conservative
diversifier against any future lattice cryptanalysis. It features tiny keys but
large signatures and slow signing. All 12 parameter sets — both hash families
(SHAKE and SHA-2) across 128/192/256 and the small/fast (`s`/`f`) variants —
ship in 0.4.0, byte-exact on the 1,248-case official NIST ACVP sample corpus.
Signing is **hedged by default**, with explicit deterministic and slow-signing
paths and optional verify-after-sign.

| Parameter set | NIST category | Public key | Secret key | Signature |
| ------------- | ------------- | ---------- | ---------- | --------- |
| *-128s        | 1             | 32         | 64         | 7856      |
| *-128f        | 1             | 32         | 64         | 17088     |
| *-192s        | 3             | 48         | 96         | 16224     |
| *-192f        | 3             | 48         | 96         | 35664     |
| *-256s        | 5             | 64         | 128        | 29792     |
| *-256f        | 5             | 64         | 128        | 49856     |

Each row is available in both the `SHAKE` and `SHA-2` hash families
(`SlhDsaParams.shake128s`, `SlhDsaParams.sha2128s`, and so on).

## Shared primitives

To stay dependency-free, `pqcrypto` vendors the hash primitives the algorithms
need: FIPS 202 SHA-3/SHAKE (in `lib/src/common/keccak.dart`) and FIPS 180-4
SHA-2 (used by HashML-DSA). These are **internal** and not exported as a public
hashing API today; full FIPS 202 and SP 800-185 (cSHAKE/KMAC/TupleHash) are
planned for 0.7.0. See [Architecture](Architecture) and the
[Documentation Index](Documentation-Index).

For the deeper math and code layout, see
[Architecture](https://github.com/turkananation/pqcrypto/blob/main/doc/ARCHITECTURE.md)
and
[FIPS Compliance](https://github.com/turkananation/pqcrypto/blob/main/doc/FIPS_COMPLIANCE.md).

import 'dart:math';
import 'dart:typed_data';
import 'package:pqcrypto/src/common/shake.dart';

import 'indcpa.dart';
import 'pack.dart';
import 'params.dart'; // Import params

enum KyberLevel { kem512, kem768, kem1024 }

/// Main KEM API for ML-KEM
class KyberKem {
  final KyberLevel level;
  final KyberParams params;

  // Private constructor
  const KyberKem._(this.level, this.params);

  // Factory for presets
  factory KyberKem(KyberLevel level) {
    switch (level) {
      case KyberLevel.kem512:
        return KyberKem._(
          level,
          const KyberParams(k: 2, eta1: 3, eta2: 2, du: 10, dv: 4),
        );
      case KyberLevel.kem768:
        return KyberKem._(
          level,
          const KyberParams(k: 3, eta1: 2, eta2: 2, du: 10, dv: 4),
        );
      case KyberLevel.kem1024:
        return KyberKem._(
          level,
          const KyberParams(k: 4, eta1: 2, eta2: 2, du: 11, dv: 5),
        );
    }
  }

  /// Generate public/private keypair.
  (Uint8List, Uint8List) generateKeyPair([Uint8List? seed]) {
    seed ??= _hashToSeed(); // 32-byte seed
    final h = Shake128.shake(seed, 32); // Hash seed

    // Split seed into s/t seeds
    final (sSeed, tSeed) = _splitSeed(h);
    final s = Indcpa.sampleInBall(sSeed, params); // Secret vector
    final t = Indcpa.samplePolyvec(tSeed, params); // Public polyvec

    final pk = Pack.encodePublicKey(t, h, params); // pk = (t || h)
    final sk = Pack.encodeSecretKey(s, h, pk, params); // sk = (s || pk || h)

    return (pk, sk);
  }

  /// Encapsulate: Client generates shared secret from pk.
  (Uint8List ct, Uint8List ss) encapsulate(Uint8List pk, [Uint8List? nonce]) {
    nonce ??= _hashToSeed();
    final m = _sampleMessage(nonce); // Random message

    final ct = Indcpa.encrypt(pk, m, params); // CPA encrypt
    final ss = _kemExtract(ct, m); // KDF to shared secret

    return (ct, ss);
  }

  /// Decapsulate: Server recovers ss from ct.
  Uint8List decapsulate(Uint8List sk, Uint8List ct) {
    // ignore: unused_local_variable
    final (s, _, pkFromSk) = Pack.decodeSecretKey(sk, params); // Ignore 'h'
    // TODO: Verify re-encryption check (implicit rejection)
    final m = Indcpa.decrypt(sk, ct, params); // Recover m
    final ss = _kemExtract(ct, m);
    return ss;
  }

  Uint8List _hashToSeed() {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256)));
  }

  // Stubs for split, sample, extract (implement based on NIST spec FIPS 203).
  (Uint8List, Uint8List) _splitSeed(Uint8List seed) =>
      (seed.sublist(0, 16), seed.sublist(16));
  Uint8List _sampleMessage(Uint8List nonce) => Shake128.shake(nonce, 32);
  Uint8List _kemExtract(Uint8List ct, Uint8List m) {
    final combined = Uint8List(ct.length + m.length);
    combined.setAll(0, ct);
    combined.setAll(ct.length, m);
    return Shake128.shake(combined, 32);
  }
}

// Export for public API
class PqcKem {
  static final KyberKem kyber512 = KyberKem(KyberLevel.kem512);
  static final KyberKem kyber768 = KyberKem(KyberLevel.kem768);
  static final KyberKem kyber1024 = KyberKem(KyberLevel.kem1024);
}

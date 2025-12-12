import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart'; // For SHA3Digest
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

  // Helpers for FIPS 203
  static Uint8List _H(Uint8List data) {
    final digest = SHA3Digest(256);
    return digest.process(data);
  }

  static Uint8List _G(Uint8List data) {
    final digest = SHA3Digest(512);
    return digest.process(data);
  }

  static Uint8List _J(Uint8List z, Uint8List c, int len) {
    final input = Uint8List(z.length + c.length);
    input.setAll(0, z);
    input.setAll(z.length, c);
    return Shake256.shake(input, len);
  }

  /// Generate public/private keypair.
  (Uint8List, Uint8List) generateKeyPair([Uint8List? seed]) {
    // seed can be d (32) or d||z (64)?
    // FIPS 203 keys are generated from d and z.
    // If seed is provided, assume it contains d + z (64 bytes) or just d?
    // Let's assume input seed is 64 bytes (d||z) if provided, else random.

    Uint8List d, z;
    if (seed != null) {
      if (seed.length == 32) {
        d = seed;
        z = _randomBytes(32);
      } else if (seed.length == 64) {
        d = seed.sublist(0, 32);
        z = seed.sublist(32, 64);
      } else {
        throw ArgumentError("Seed must be 32 or 64 bytes");
      }
    } else {
      d = _randomBytes(32);
      z = _randomBytes(32);
    }

    // (rho, sigma) := G(d)
    final rhoSigma = _G(d);

    // Indcpa KeyGen
    return Indcpa.generateKeyPair(rhoSigma, z, params);
  }

  /// Encapsulate: Client generates shared secret from pk.
  (Uint8List ct, Uint8List ss) encapsulate(Uint8List pk, [Uint8List? nonce]) {
    // 1. m <- Random(32)
    final m = nonce ?? _randomBytes(32);

    // 2. (K, r) := G(m || H(pk))
    final hPk = _H(pk);
    final input = Uint8List(32 + 32);
    input.setAll(0, m);
    input.setAll(32, hPk);
    final Kr = _G(input);

    final K = Kr.sublist(0, 32);
    final r = Kr.sublist(32, 64);

    // 3. c := Encrypt(pk, m, r)
    final ct = Indcpa.encrypt(pk, m, r, params);

    // 4. return (c, K)
    return (ct, K);
  }

  /// Decapsulate: Server recovers ss from ct.
  Uint8List decapsulate(Uint8List sk, Uint8List ct) {
    // 1. (s, h, pk, z) := Decode(sk)
    final (s, h, pk, z) = Pack.decodeSecretKey(sk, params);

    // 2. m' := Decrypt(s, ct)
    final mPrime = Indcpa.decrypt(
      sk,
      ct,
      params,
    ); // Indcpa.decrypt decodes s internally from sk.
    // Wait, Indcpa.decrypt takes SK (encoded).
    // And unpacks it.
    // My previous Indcpa.decrypt unpacking was ignoring z.
    // That's fine, it ignores suffix.

    // 3. (K', r') := G(m' || h)
    final input = Uint8List(32 + 32);
    input.setAll(0, mPrime);
    input.setAll(32, h);
    final KrPrime = _G(input);

    final KPrime = KrPrime.sublist(0, 32);
    final rPrime = KrPrime.sublist(32, 64);

    // 4. c' := Encrypt(pk, m', r')
    final cPrime = Indcpa.encrypt(pk, mPrime, rPrime, params);

    // 5. if c == c' return K', else return K_bar = J(z || c, 32)
    if (_constantTimeEq(ct, cPrime)) {
      return KPrime;
    } else {
      return _J(z, ct, 32);
    }
  }

  Uint8List _randomBytes(int len) {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(len, (_) => rng.nextInt(256)));
  }

  bool _constantTimeEq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    int res = 0;
    for (int i = 0; i < a.length; i++) {
      res |= a[i] ^ b[i];
    }
    return res == 0;
  }
}

// Export for public API
class PqcKem {
  static final KyberKem kyber512 = KyberKem(KyberLevel.kem512);
  static final KyberKem kyber768 = KyberKem(KyberLevel.kem768);
  static final KyberKem kyber1024 = KyberKem(KyberLevel.kem1024);
}

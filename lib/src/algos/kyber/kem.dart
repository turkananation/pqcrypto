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
  static Uint8List _h(Uint8List data) {
    final digest = SHA3Digest(256);
    return digest.process(data);
  }

  static Uint8List _g(Uint8List data) {
    final digest = SHA3Digest(512);
    return digest.process(data);
  }

  static Uint8List _j(Uint8List z, Uint8List c, int len) {
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

    // (rho, sigma) := G(d || k)  — FIPS 203 §5.1 Algorithm 13
    final Uint8List dk = Uint8List(33)
      ..setAll(0, d)
      ..[32] = params.k;
    final rhoSigma = _g(dk);

    // Indcpa KeyGen
    return Indcpa.generateKeyPair(rhoSigma, z, params);
  }

  /// Encapsulate: Client generates shared secret from pk.
  (Uint8List ct, Uint8List ss) encapsulate(Uint8List pk, [Uint8List? nonce]) {
    _validatePublicKey(pk);

    // 1. m <- Random(32)
    final m = nonce ?? _randomBytes(32);

    // 2. (K, r) := G(m || H(pk))
    final hPk = _h(pk);
    final input = Uint8List(32 + 32);
    input.setAll(0, m);
    input.setAll(32, hPk);
    final kr = _g(input);

    final k = kr.sublist(0, 32);
    final r = kr.sublist(32, 64);

    // 3. c := Encrypt(pk, m, r)
    final ct = Indcpa.encrypt(pk, m, r, params);

    // 4. return (c, K)
    return (ct, k);
  }

  /// Decapsulate: Server recovers ss from ct.
  Uint8List decapsulate(Uint8List sk, Uint8List ct) {
    _validateSecretKey(sk);
    _validateCiphertext(ct);

    // 1. (s, h, pk, z) := Decode(sk)
    final (_, h, pk, z) = Pack.decodeSecretKey(sk, params);

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
    final krPrime = _g(input);

    final kPrime = krPrime.sublist(0, 32);
    final rPrime = krPrime.sublist(32, 64);

    // 4. c' := Encrypt(pk, m', r')
    final cPrime = Indcpa.encrypt(pk, mPrime, rPrime, params);

    // 5. if c == c' return K', else return K_bar = J(z || c, 32)
    if (_constantTimeEq(ct, cPrime)) {
      return kPrime;
    } else {
      return _j(z, ct, 32);
    }
  }

  void _validatePublicKey(Uint8List pk) {
    if (pk.length != params.publicKeyBytes) {
      throw ArgumentError(
        'Invalid ML-KEM public key length: expected '
        '${params.publicKeyBytes}, got ${pk.length}',
      );
    }

    final packedPolyBytes = 384 * params.k;
    for (var offset = 0; offset < packedPolyBytes; offset += 384) {
      final encoded = Uint8List.sublistView(pk, offset, offset + 384);
      final decoded = Pack.byteDecode12(encoded);

      // FIPS 203 §7.2 Step 2 (Modulus check): verify that ByteEncode12(ByteDecode12(ek)) == ek.
      // Note: Pack.byteDecode12 already performs a strict bounds check throwing if any coefficient >= q.
      // Since all decoded coefficients are in [0, q-1] (< 2^12), the 12-bit encoding is a bijection, making
      // this round-trip mathematically redundant. We retain it here as a spec-literal implementation of the
      // modulus check, providing defense-in-depth against any future changes to Pack.byteDecode12's checks.
      final reencoded = Pack.byteEncode12(decoded);
      if (!_constantTimeEq(encoded, reencoded)) {
        throw ArgumentError('Invalid ML-KEM public key encoding');
      }
    }
  }

  void _validateSecretKey(Uint8List sk) {
    if (sk.length != params.secretKeyBytes) {
      throw ArgumentError(
        'Invalid ML-KEM secret key length: expected '
        '${params.secretKeyBytes}, got ${sk.length}',
      );
    }

    final sBytes = 384 * params.k;
    final pkStart = sBytes;
    final pkEnd = pkStart + params.publicKeyBytes;
    final hStart = pkEnd;
    final hEnd = hStart + 32;

    final pk = Uint8List.sublistView(sk, pkStart, pkEnd);
    _validatePublicKey(pk);

    final expectedHash = _h(pk);
    final storedHash = Uint8List.sublistView(sk, hStart, hEnd);
    if (!_constantTimeEq(expectedHash, storedHash)) {
      throw ArgumentError('Invalid ML-KEM secret key hash');
    }
  }

  void _validateCiphertext(Uint8List ct) {
    if (ct.length != params.ciphertextBytes) {
      throw ArgumentError(
        'Invalid ML-KEM ciphertext length: expected '
        '${params.ciphertextBytes}, got ${ct.length}',
      );
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

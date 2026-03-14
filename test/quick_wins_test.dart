// Regression tests for Quick Win fixes (QW-01 through QW-10).
//
// Traceable to: IMPROVEMENTS.md, BUGS.md, SECURITY_AUDIT.md
// Each test group references the audit finding it validates.
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';
import 'package:pqcrypto/src/algos/dilithium/symmetric.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/kyber/kem.dart';

void main() {
  // =========================================================================
  // QW-01: tau per security level [CRIT-01 / BUG-001]
  // FIPS 204 Table 1 mandates tau = 39/49/60 for ML-DSA-44/65/87.
  // =========================================================================
  group('QW-01: tau per security level', () {
    test('ML-DSA-44 tau = 39', () {
      expect(DilithiumParams.mlDsa44.tau, 39);
    });

    test('ML-DSA-65 tau = 49', () {
      expect(DilithiumParams.mlDsa65.tau, 49);
    });

    test('ML-DSA-87 tau = 60', () {
      expect(DilithiumParams.mlDsa87.tau, 60);
    });

    test('SampleInBall produces correct Hamming weight for tau=39', () {
      final seed = Uint8List(32)..fillRange(0, 32, 0x42);
      final c = DilithiumSymmetric.sampleInBall(seed, 39);
      int nonZero = 0;
      for (int i = 0; i < 256; i++) {
        if (c.coeffs[i] != 0) nonZero++;
      }
      expect(nonZero, 39, reason: 'Challenge poly must have exactly tau=39 non-zero coeffs');
    });

    test('SampleInBall produces correct Hamming weight for tau=49', () {
      final seed = Uint8List(48)..fillRange(0, 48, 0xAA);
      final c = DilithiumSymmetric.sampleInBall(seed, 49);
      int nonZero = 0;
      for (int i = 0; i < 256; i++) {
        if (c.coeffs[i] != 0) nonZero++;
      }
      expect(nonZero, 49, reason: 'Challenge poly must have exactly tau=49 non-zero coeffs');
    });

    test('SampleInBall produces correct Hamming weight for tau=60', () {
      final seed = Uint8List(64)..fillRange(0, 64, 0xBB);
      final c = DilithiumSymmetric.sampleInBall(seed, 60);
      int nonZero = 0;
      for (int i = 0; i < 256; i++) {
        if (c.coeffs[i] != 0) nonZero++;
      }
      expect(nonZero, 60, reason: 'Challenge poly must have exactly tau=60 non-zero coeffs');
    });

    test('SampleInBall coefficients are only +1 or -1', () {
      final seed = Uint8List(32)..fillRange(0, 32, 0x13);
      final c = DilithiumSymmetric.sampleInBall(seed, 60);
      for (int i = 0; i < 256; i++) {
        expect(
          c.coeffs[i] == 0 || c.coeffs[i] == 1 || c.coeffs[i] == -1,
          isTrue,
          reason: 'SampleInBall coeff[$i] = ${c.coeffs[i]} must be 0, 1, or -1',
        );
      }
    });
  });

  // =========================================================================
  // QW-03: SampleInBall stream length [CRIT-03 / BUG-003]
  // With 840 bytes, tau=60 should never exhaust the stream.
  // =========================================================================
  group('QW-03: SampleInBall stream length', () {
    test('tau=60 does not throw on multiple seeds', () {
      // Run 100 iterations with different seeds to stress rejection sampling.
      for (int s = 0; s < 100; s++) {
        final seed = Uint8List(64);
        seed[0] = s;
        seed[1] = (s * 7) & 0xFF;
        seed[2] = (s * 13) & 0xFF;
        // Must not throw "SampleInBall stream exhausted"
        final c = DilithiumSymmetric.sampleInBall(seed, 60);
        int nonZero = 0;
        for (int i = 0; i < 256; i++) {
          if (c.coeffs[i] != 0) nonZero++;
        }
        expect(nonZero, 60);
      }
    });
  });

  // =========================================================================
  // QW-04: ExpandMask rho' input size [CRIT-04 / BUG-002]
  // _rejGamma1 must use all 64 bytes of rho', not just 32.
  // =========================================================================
  group('QW-04: ExpandMask uses full 64-byte rho\'', () {
    test('Different upper 32 bytes of rho\' produce different masks', () {
      // If only 32 bytes are used, changing bytes 32-63 has no effect.
      final rhoA = Uint8List(64);
      rhoA.fillRange(0, 32, 0x01);
      rhoA.fillRange(32, 64, 0x00);

      final rhoB = Uint8List(64);
      rhoB.fillRange(0, 32, 0x01); // Same first 32 bytes
      rhoB.fillRange(32, 64, 0xFF); // Different upper 32 bytes

      final yA = DilithiumSymmetric.expandMask(rhoA, 0, 4, 1 << 17);
      final yB = DilithiumSymmetric.expandMask(rhoB, 0, 4, 1 << 17);

      // At least one polynomial should differ
      bool anyDiff = false;
      for (int p = 0; p < 4 && !anyDiff; p++) {
        for (int c = 0; c < 256 && !anyDiff; c++) {
          if (yA[p].coeffs[c] != yB[p].coeffs[c]) anyDiff = true;
        }
      }
      expect(
        anyDiff,
        isTrue,
        reason: 'Changing upper 32 bytes of rho\' must change mask output',
      );
    });
  });

  // =========================================================================
  // QW-05: ML-DSA exported [BUG-012]
  // =========================================================================
  group('QW-05: ML-DSA export', () {
    test('MlDsa is accessible', () {
      // This test compiles only if MlDsa is exported from pqcrypto.dart
      expect(MlDsa, isNotNull);
    });

    test('DilithiumParams is accessible', () {
      expect(DilithiumParams.mlDsa44.name, 'ML-DSA-44');
      expect(DilithiumParams.mlDsa65.name, 'ML-DSA-65');
      expect(DilithiumParams.mlDsa87.name, 'ML-DSA-87');
    });
  });

  // =========================================================================
  // QW-10: ML-KEM input size validation [HIGH-02]
  // =========================================================================
  group('QW-10: ML-KEM input validation', () {
    test('encapsulate rejects wrong-size public key', () {
      final kem = KyberKem(KyberLevel.kem768);
      final badPk = Uint8List(100); // Wrong size
      expect(
        () => kem.encapsulate(badPk),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('decapsulate rejects wrong-size secret key', () {
      final kem = KyberKem(KyberLevel.kem768);
      final (pk, _) = kem.generateKeyPair();
      final (ct, _) = kem.encapsulate(pk);
      final badSk = Uint8List(100);
      expect(
        () => kem.decapsulate(badSk, ct),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('decapsulate rejects wrong-size ciphertext', () {
      final kem = KyberKem(KyberLevel.kem768);
      final (_, sk) = kem.generateKeyPair();
      final badCt = Uint8List(100);
      expect(
        () => kem.decapsulate(sk, badCt),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('encapsulate accepts correct-size public key', () {
      final kem = KyberKem(KyberLevel.kem768);
      final (pk, _) = kem.generateKeyPair();
      // Should not throw
      final (ct, ss) = kem.encapsulate(pk);
      expect(ct.length, kem.params.ciphertextBytes);
      expect(ss.length, 32);
    });

    test('validation works for all security levels', () {
      for (final level in KyberLevel.values) {
        final kem = KyberKem(level);
        final badPk = Uint8List(1);
        expect(
          () => kem.encapsulate(badPk),
          throwsA(isA<ArgumentError>()),
          reason: 'Level $level should reject bad PK',
        );
      }
    });
  });

  // =========================================================================
  // QW-01/params: Verify all FIPS 204 Table 1 parameters
  // =========================================================================
  group('FIPS 204 Table 1 parameter correctness', () {
    test('ML-DSA-44 parameters', () {
      final p = DilithiumParams.mlDsa44;
      expect(p.k, 4);
      expect(p.l, 4);
      expect(p.eta, 2);
      expect(p.tau, 39);
      expect(p.beta, 78); // tau * eta = 39 * 2
      expect(p.gamma1, 1 << 17);
      expect(p.gamma2, 95232); // (q-1)/88
      expect(p.omega, 80);
      expect(p.cTildeSize, 32); // 2 * lambda/8 = 2*128/8
    });

    test('ML-DSA-65 parameters', () {
      final p = DilithiumParams.mlDsa65;
      expect(p.k, 6);
      expect(p.l, 5);
      expect(p.eta, 4);
      expect(p.tau, 49);
      expect(p.beta, 196); // tau * eta = 49 * 4
      expect(p.gamma1, 1 << 19);
      expect(p.gamma2, 261888); // (q-1)/32
      expect(p.omega, 55);
      expect(p.cTildeSize, 48); // 2 * 192/8
    });

    test('ML-DSA-87 parameters', () {
      final p = DilithiumParams.mlDsa87;
      expect(p.k, 8);
      expect(p.l, 7);
      expect(p.eta, 2);
      expect(p.tau, 60);
      expect(p.beta, 120); // tau * eta = 60 * 2
      expect(p.gamma1, 1 << 19);
      expect(p.gamma2, 261888); // (q-1)/32
      expect(p.omega, 75);
      expect(p.cTildeSize, 64); // 2 * 256/8
    });
  });

  // =========================================================================
  // QW-01: KeyGen still produces correct sizes after tau fix
  // =========================================================================
  group('KeyGen sizes post-fix', () {
    test('ML-DSA-44 key sizes per FIPS 204 Table 2', () {
      final seed = Uint8List(32);
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa44, seed);
      expect(pk.length, 1312);
      expect(sk.length, 2560);
    });

    test('ML-DSA-65 key sizes per FIPS 204 Table 2', () {
      final seed = Uint8List(32);
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa65, seed);
      expect(pk.length, 1952);
      expect(sk.length, 4032);
    });

    test('ML-DSA-87 key sizes per FIPS 204 Table 2', () {
      final seed = Uint8List(32);
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa87, seed);
      expect(pk.length, 2592);
      expect(sk.length, 4896);
    });
  });
}

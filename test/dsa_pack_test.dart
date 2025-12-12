import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/poly.dart';
import 'package:pqcrypto/src/algos/dilithium/packing.dart';

void main() {
  group('Dilithium Packing', () {
    test('SimpleBitPack Round Trip (d=13)', () {
      final rng = Random();
      final p = DilithiumPoly.zero();
      for (int i = 0; i < 256; i++) {
        p.coeffs[i] = rng.nextInt(1 << 13);
      }

      final packed = simpleBitPack(p, 13);
      expect(packed.length, 32 * 13); // 416 bytes

      final unpacked = simpleBitUnpack(packed, 13);
      for (int i = 0; i < 256; i++) {
        expect(unpacked.coeffs[i], p.coeffs[i]);
      }
    });

    test('BitPack Round Trip (eta=2)', () {
      // eta=2 range [-2, 2] mapped to [0, 4] (3 bits)
      // bitPack maps w -> eta - w ?? Wait.
      // bitPack logic: z = eta - w.
      // If w = 2, z=0. If w=-2, z=4.
      // Input w in [-eta, eta].

      final rng = Random();
      final p = DilithiumPoly.zero();
      for (int i = 0; i < 256; i++) {
        p.coeffs[i] = rng.nextInt(5) - 2; // -2..2
      }

      final packed = bitPack(p, 2);
      expect(packed.length, 32 * 3); // 96 bytes

      final unpacked = bitUnpack(packed, 2);
      for (int i = 0; i < 256; i++) {
        expect(
          unpacked.coeffs[i],
          p.coeffs[i],
          reason: "Mismatch at $i for eta=2",
        );
      }
    });

    test('BitPack Round Trip (eta=4)', () {
      final rng = Random();
      final p = DilithiumPoly.zero();
      for (int i = 0; i < 256; i++) {
        p.coeffs[i] = rng.nextInt(9) - 4; // -4..4
      }

      final packed = bitPack(p, 4);
      expect(packed.length, 32 * 4); // 128 bytes

      final unpacked = bitUnpack(packed, 4);
      for (int i = 0; i < 256; i++) {
        expect(
          unpacked.coeffs[i],
          p.coeffs[i],
          reason: "Mismatch at $i for eta=4",
        );
      }
    });

    test('PackPK Round Trip', () {
      // PK = (rho, t1)
      final rho = Uint8List(32);
      rho.fillRange(0, 32, 0xAB);

      // t1 is k vectors. ML-DSA-44 k=4.
      final k = 4;
      final t1 = DilithiumPolyVec.zero(k);
      for (int i = 0; i < k; i++) {
        for (int j = 0; j < 256; j++) {
          t1[i].coeffs[j] = j % 1024; // 10 bits
        }
      }

      final packed = packPK(rho, t1);
      final (uRho, uT1) = unpackPK(packed, k);

      expect(uRho, equals(rho));
      for (int i = 0; i < k; i++) {
        for (int j = 0; j < 256; j++) {
          expect(uT1[i].coeffs[j], t1[i].coeffs[j]);
        }
      }
    });

    test('PackSK Round Trip', () {
      // SK = (rho, K, tr, s1, s2, t0)
      final rho = Uint8List(32);
      rho.fillRange(0, 32, 1);
      final key = Uint8List(32);
      key.fillRange(0, 32, 2);
      final tr = Uint8List(64);
      tr.fillRange(0, 64, 3);

      int k = 4;
      int l = 4;
      int eta = 2;

      final s1 = DilithiumPolyVec.zero(l);
      for (int i = 0; i < l; i++) {
        s1[i].coeffs[0] = -eta;
      }

      final s2 = DilithiumPolyVec.zero(k);
      for (int i = 0; i < k; i++) {
        s2[i].coeffs[0] = eta;
      }

      final t0 = DilithiumPolyVec.zero(k);
      for (int i = 0; i < k; i++) {
        t0[i].coeffs[0] = 123;
      }

      final packed = packSK(rho, key, tr, s1, s2, t0, eta);
      final unpacked = unpackSK(packed, k, l, eta);

      expect(unpacked.$1, equals(rho)); // rho
      expect(unpacked.$2, equals(key)); // K
      expect(unpacked.$3, equals(tr)); // tr

      // Check s1
      // s1[i][0] should be -2
      expect(unpacked.$4[0].coeffs[0], -eta);

      // Check s2
      expect(unpacked.$5[0].coeffs[0], eta);

      // Check t0
      expect(unpacked.$6[0].coeffs[0], 123);
    });

    test('PackSig Round Trip', () {
      // Sig = (c_tilde, z, h)
      final cTilde = Uint8List(32);
      cTilde.fillRange(0, 32, 99);

      int k = 4;
      int l = 4;
      int gamma1 = 1 << 17; // ML-DSA-44 default
      int omega = 80;

      final z = DilithiumPolyVec.zero(l);
      // z range: -(gamma1-1) to gamma1-1
      // gamma1 = 131072. max = 131071.
      for (int i = 0; i < l; i++) {
        z[i].coeffs[0] = 50000;
      }

      final h = DilithiumPolyVec.zero(k);
      // hints are 0 or 1.
      // sparse.
      h[0].coeffs[5] = 1;
      h[0].coeffs[100] = 1;
      h[1].coeffs[20] = 1;

      final packed = packSig(cTilde, z, h, gamma1, omega);

      final unpacked = unpackSig(packed, k, l, gamma1, omega, 32);

      expect(unpacked.$1, equals(cTilde));
      expect(unpacked.$2[0].coeffs[0], 50000);

      // Check hints
      expect(unpacked.$3[0].coeffs[5], 1);
      expect(unpacked.$3[0].coeffs[100], 1);
      expect(unpacked.$3[0].coeffs[99], 0);
      expect(unpacked.$3[1].coeffs[20], 1);
    });
  });
}

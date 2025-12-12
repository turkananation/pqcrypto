import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  group('ML-DSA KeyGen', () {
    test('ML-DSA-44 Sizes', () {
      final seed = Uint8List(32); // Zero seed
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa44, seed);

      // Expected Sizes (NIST FIPS 204 Table 2)
      // PK: 1312
      // SK: 2560
      // Sig: 2420 (not tested here)
      expect(pk.length, 1312);
      expect(sk.length, 2560);
    });

    test('ML-DSA-65 Sizes', () {
      final seed = Uint8List(32);
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa65, seed);

      // PK: 1952
      // SK: 4032 (eta=4 for s1, s2? No eta=4 is for 87? 65 has eta=4?)
      // Check Params: 65 -> eta=4.
      // s1/s2 size: 5 * 32 * 4 = 640. 6 * 32 * 4 = 768.
      // t0 size: 6 * 416 = 2496.
      // Total: 32+32+64 + 640 + 768 + 2496 = 4032. Matches.

      expect(pk.length, 1952);
      expect(sk.length, 4032);
    });

    test('ML-DSA-87 Sizes', () {
      final seed = Uint8List(32);
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa87, seed);

      // PK: 2592
      // SK: 4896
      // 87 -> eta=2.
      expect(pk.length, 2592);
      expect(sk.length, 4896);
    });

    test('Determinism', () {
      final seed = Uint8List(32);
      seed[0] = 1;
      final (pk1, sk1) = MlDsa.generateKeyPair(DilithiumParams.mlDsa44, seed);
      final (pk2, sk2) = MlDsa.generateKeyPair(DilithiumParams.mlDsa44, seed);

      expect(pk1, equals(pk2));
      expect(sk1, equals(sk2));
    });
  });
}

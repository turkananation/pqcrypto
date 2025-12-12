import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  group('ML-DSA Sign/Verify', () {
    test('ML-DSA-44 Round Trip', () {
      final seed = Uint8List(32);
      seed[0] = 0x42;

      // KeyGen
      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa44, seed);

      final message = Uint8List.fromList('Hello ML-DSA'.codeUnits);

      // Sign
      final sig = MlDsa.sign(sk, message, DilithiumParams.mlDsa44);
      print('ML-DSA-44 Sig Len: ${sig.length}');
      expect(sig.length, 2420); // FIPS 204 Table 2

      // Verify
      final valid = MlDsa.verify(pk, message, sig, DilithiumParams.mlDsa44);
      expect(valid, isTrue, reason: "Signature verification failed");

      // Bad Message
      final badMsg = Uint8List.fromList('Bye ML-DSA'.codeUnits);
      final validBad = MlDsa.verify(pk, badMsg, sig, DilithiumParams.mlDsa44);
      expect(validBad, isFalse, reason: "Bad message verified");

      // Bad Sig
      final badSig = Uint8List.fromList(sig);
      badSig[0] ^= 0xFF;
      final validBadSig = MlDsa.verify(
        pk,
        message,
        badSig,
        DilithiumParams.mlDsa44,
      );
      expect(validBadSig, isFalse, reason: "Bad signature verified");
    });

    test('ML-DSA-65 Round Trip', () {
      final seed = Uint8List(32);
      seed[1] = 0xAA;

      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa65, seed);
      final m = Uint8List(10);

      final sig = MlDsa.sign(sk, m, DilithiumParams.mlDsa65);
      print('ML-DSA-65 Sig Len: ${sig.length}');
      expect(sig.length, 3309);

      expect(MlDsa.verify(pk, m, sig, DilithiumParams.mlDsa65), isTrue);
    });

    test('ML-DSA-87 Round Trip', () {
      final seed = Uint8List(32);
      seed[2] = 0xBB;

      final (pk, sk) = MlDsa.generateKeyPair(DilithiumParams.mlDsa87, seed);
      final m = Uint8List(50);

      final sig = MlDsa.sign(sk, m, DilithiumParams.mlDsa87);
      print('ML-DSA-87 Sig Len: ${sig.length}');
      expect(sig.length, 4627);

      expect(MlDsa.verify(pk, m, sig, DilithiumParams.mlDsa87), isTrue);
    });
  });
}

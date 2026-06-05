import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  final p = DilithiumParams.mlDsa44;
  final (pk, sk) = MlDsa.generateKeyPairSeeded(p, Uint8List(32)..[0] = 7);
  final msg = Uint8List.fromList('FIPS 204 external API'.codeUnits);

  group('Context binding', () {
    test('empty context round-trips by default', () {
      final sig = MlDsa.sign(sk, msg, p);
      expect(MlDsa.verify(pk, msg, sig, p), isTrue);
    });

    test('non-empty context must match', () {
      final ctx = Uint8List.fromList('app-v1'.codeUnits);
      final sig = MlDsa.sign(sk, msg, p, ctx: ctx);
      expect(MlDsa.verify(pk, msg, sig, p, ctx: ctx), isTrue);
      expect(MlDsa.verify(pk, msg, sig, p), isFalse); // empty != ctx
      expect(
        MlDsa.verify(
          pk,
          msg,
          sig,
          p,
          ctx: Uint8List.fromList('app-v2'.codeUnits),
        ),
        isFalse,
      );
    });

    test('255-byte context is allowed; 256 is rejected', () {
      final ctx = Uint8List(255)..fillRange(0, 255, 0xAB);
      final sig = MlDsa.sign(sk, msg, p, ctx: ctx);
      expect(MlDsa.verify(pk, msg, sig, p, ctx: ctx), isTrue);
      expect(
        () => MlDsa.sign(sk, msg, p, ctx: Uint8List(256)),
        throwsArgumentError,
      );
    });
  });

  group('Hedged vs deterministic signing', () {
    test('hedged signatures differ but all verify', () {
      final a = MlDsa.sign(sk, msg, p);
      final b = MlDsa.sign(sk, msg, p);
      expect(a, isNot(equals(b)), reason: 'fresh rnd => different signatures');
      expect(MlDsa.verify(pk, msg, a, p), isTrue);
      expect(MlDsa.verify(pk, msg, b, p), isTrue);
    });

    test('deterministic signatures are stable', () {
      final a = MlDsa.signDeterministic(sk, msg, p);
      final b = MlDsa.signDeterministic(sk, msg, p);
      expect(a, equals(b));
      expect(MlDsa.verify(pk, msg, a, p), isTrue);
    });

    test('explicit rnd controls the signature', () {
      final r = Uint8List(32)..fillRange(0, 32, 0x11);
      expect(
        MlDsa.sign(sk, msg, p, rnd: r),
        equals(MlDsa.sign(sk, msg, p, rnd: r)),
      );
    });
  });

  group('External KeyGen uses fresh randomness', () {
    test('two key pairs differ and each works', () {
      final (pk1, sk1) = MlDsa.generateKeyPair(p);
      final (pk2, sk2) = MlDsa.generateKeyPair(p);
      expect(pk1, isNot(equals(pk2)));
      expect(pk1.length, p.publicKeyBytes);
      expect(sk1.length, p.secretKeyBytes);
      final s1 = MlDsa.sign(sk1, msg, p);
      expect(MlDsa.verify(pk1, msg, s1, p), isTrue);
      expect(MlDsa.verify(pk2, msg, s1, p), isFalse);
      // silence unused
      expect(sk2.length, p.secretKeyBytes);
    });
  });

  group('HashML-DSA domain separation', () {
    test('hash round-trips with matching context', () {
      final ctx = Uint8List.fromList('ph'.codeUnits);
      final sig = MlDsa.hashSign(sk, msg, p, ctx: ctx);
      expect(MlDsa.hashVerify(pk, msg, sig, p, ctx: ctx), isTrue);
    });

    test('pure and pre-hash domains do not cross-verify', () {
      final pure = MlDsa.sign(sk, msg, p);
      final hashed = MlDsa.hashSign(sk, msg, p);
      expect(MlDsa.hashVerify(pk, msg, pure, p), isFalse);
      expect(MlDsa.verify(pk, msg, hashed, p), isFalse);
    });
  });
}

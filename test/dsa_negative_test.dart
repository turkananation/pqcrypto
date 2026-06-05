import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

void main() {
  final p = DilithiumParams.mlDsa44;
  final seed = Uint8List(32)..[0] = 0x9E;
  final (pk, sk) = MlDsa.generateKeyPairSeeded(p, seed);
  final msg = Uint8List.fromList('negative-tests'.codeUnits);
  final sig = MlDsa.signDeterministic(sk, msg, p);

  group('Verify is total (returns false, never throws) on bad input', () {
    test('valid signature verifies', () {
      expect(MlDsa.verify(pk, msg, sig, p), isTrue);
    });

    test('public key too short / too long', () {
      expect(MlDsa.verify(pk.sublist(0, pk.length - 1), msg, sig, p), isFalse);
      final longer = Uint8List(pk.length + 1)..setRange(0, pk.length, pk);
      expect(MlDsa.verify(longer, msg, sig, p), isFalse);
      expect(MlDsa.verify(Uint8List(0), msg, sig, p), isFalse);
    });

    test('signature too short / too long / empty', () {
      expect(MlDsa.verify(pk, msg, sig.sublist(0, sig.length - 1), p), isFalse);
      final longer = Uint8List(sig.length + 1)..setRange(0, sig.length, sig);
      expect(MlDsa.verify(pk, msg, longer, p), isFalse);
      expect(MlDsa.verify(pk, msg, Uint8List(0), p), isFalse);
    });

    test('tampered challenge / response bytes', () {
      final s1 = Uint8List.fromList(sig)..[0] ^= 0xFF; // c~ region
      expect(MlDsa.verify(pk, msg, s1, p), isFalse);
      final s2 = Uint8List.fromList(sig)
        ..[p.cTildeSize + 4] ^= 0xFF; // z region
      expect(MlDsa.verify(pk, msg, s2, p), isFalse);
    });

    test('wrong message / wrong context', () {
      expect(
        MlDsa.verify(pk, Uint8List.fromList('other'.codeUnits), sig, p),
        isFalse,
      );
      expect(MlDsa.verify(pk, msg, sig, p, ctx: Uint8List(3)), isFalse);
    });

    test('context longer than 255 bytes', () {
      expect(MlDsa.verify(pk, msg, sig, p, ctx: Uint8List(256)), isFalse);
    });

    test('cross-parameter verification', () {
      // A ML-DSA-44 signature must not verify under ML-DSA-65/87 (length guard).
      expect(MlDsa.verify(pk, msg, sig, DilithiumParams.mlDsa65), isFalse);
      expect(MlDsa.verify(pk, msg, sig, DilithiumParams.mlDsa87), isFalse);
    });
  });

  group('Malformed hint encodings (FIPS 204 HintBitUnpack)', () {
    final hintBase = p.cTildeSize + p.l * p.zPolyBytes;

    test('cumulative count exceeding omega', () {
      final bad = Uint8List.fromList(sig);
      bad[hintBase + p.omega + p.k - 1] =
          p.omega + 1; // last poly count > omega
      expect(MlDsa.verify(pk, msg, bad, p), isFalse);
    });

    test('decreasing cumulative counts', () {
      final bad = Uint8List.fromList(sig);
      for (int i = 0; i < p.k; i++) {
        bad[hintBase + p.omega + i] = p.k - i; // strictly decreasing
      }
      expect(MlDsa.verify(pk, msg, bad, p), isFalse);
    });

    test('non-zero padding in the index area', () {
      final bad = Uint8List.fromList(sig);
      bad[hintBase + p.omega - 1] =
          0xFF; // last index slot is padding for typical sigs
      expect(MlDsa.verify(pk, msg, bad, p), isFalse);
    });
  });

  group('Signing rejects caller misuse with typed errors', () {
    test('context longer than 255 bytes throws', () {
      expect(
        () => MlDsa.sign(sk, msg, p, ctx: Uint8List(256)),
        throwsArgumentError,
      );
    });
    test('non-32-byte rnd throws', () {
      expect(
        () => MlDsa.sign(sk, msg, p, rnd: Uint8List(31)),
        throwsArgumentError,
      );
    });
    test('non-32-byte seed throws', () {
      expect(
        () => MlDsa.generateKeyPairSeeded(p, Uint8List(31)),
        throwsArgumentError,
      );
    });
  });
}

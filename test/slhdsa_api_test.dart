import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:pqcrypto/src/algos/slhdsa/slhdsa.dart';
import 'package:test/test.dart';

Uint8List _sequence(int start, int length) => Uint8List.fromList(
  List<int>.generate(length, (index) => (start + index) & 0xff),
);

void main() {
  final params = SlhDsaParams.shake128f;
  final secretSeed = _sequence(0x10, params.n);
  final secretPrf = _sequence(0x30, params.n);
  final publicSeed = _sequence(0x50, params.n);
  final message = _sequence(0x70, 41);
  final context = _sequence(0x90, 17);
  final (publicKey, secretKey) = SlhDsaInternal.generateKeyPairSeeded(
    params,
    secretSeed,
    secretPrf,
    publicSeed,
  );

  group('SLH-DSA Algorithms 18-25', () {
    test('seeded and random key generation return encoded key sizes', () {
      expect(publicKey, hasLength(params.publicKeyBytes));
      expect(secretKey, hasLength(params.secretKeyBytes));
      expect(
        secretKey.sublist(0, 3 * params.n),
        equals(<int>[...secretSeed, ...secretPrf, ...publicSeed]),
      );

      final (randomPublicKey, randomSecretKey) = SlhDsa.generateKeyPair(params);
      expect(randomPublicKey, hasLength(params.publicKeyBytes));
      expect(randomSecretKey, hasLength(params.secretKeyBytes));
    });

    test(
      'pure deterministic signatures are stable and context-bound',
      () {
        final first = SlhDsa.signDeterministic(
          secretKey,
          message,
          params,
          context: context,
        );
        final second = SlhDsa.signDeterministic(
          secretKey,
          message,
          params,
          context: context,
        );

        expect(first, equals(second));
        expect(first, hasLength(params.signatureBytes));
        expect(
          SlhDsa.verify(publicKey, message, first, params, context: context),
          isTrue,
        );
        expect(
          SlhDsa.verify(
            publicKey,
            message,
            first,
            params,
            context: Uint8List.fromList(<int>[...context, 0]),
          ),
          isFalse,
        );
      },
      timeout: Timeout.none,
    );

    test('supplied hedging randomness changes signatures', () {
      final first = SlhDsa.sign(
        secretKey,
        message,
        params,
        additionalRandomness: Uint8List(params.n),
      );
      final second = SlhDsa.sign(
        secretKey,
        message,
        params,
        additionalRandomness: Uint8List(params.n)..[0] = 1,
      );

      expect(first, isNot(equals(second)));
      expect(SlhDsa.verify(publicKey, message, first, params), isTrue);
      expect(SlhDsa.verify(publicKey, message, second, params), isTrue);
    }, timeout: Timeout.none);

    test('HashSLH-DSA is pre-hash and OID domain separated', () {
      final signature = SlhDsa.hashSignDeterministic(
        secretKey,
        message,
        SlhDsaPreHash.sha3256,
        params,
        context: context,
      );

      expect(
        SlhDsa.hashVerify(
          publicKey,
          message,
          signature,
          SlhDsaPreHash.sha3256,
          params,
          context: context,
        ),
        isTrue,
      );
      expect(
        SlhDsa.hashVerify(
          publicKey,
          message,
          signature,
          SlhDsaPreHash.sha256,
          params,
          context: context,
        ),
        isFalse,
      );
      expect(
        SlhDsa.verify(publicKey, message, signature, params, context: context),
        isFalse,
      );
    }, timeout: Timeout.none);

    test('verify-after-sign accepts valid signatures', () {
      final signature = SlhDsa.signDeterministic(
        secretKey,
        message,
        params,
        context: context,
        verifyAfterSign: true,
      );

      expect(
        SlhDsa.verify(publicKey, message, signature, params, context: context),
        isTrue,
      );
    }, timeout: Timeout.none);

    test(
      'verify-after-sign rejects an inconsistent secret key',
      () {
        final inconsistentSecretKey = Uint8List.fromList(secretKey)
          ..[3 * params.n] ^= 1;

        expect(
          () => SlhDsa.signDeterministic(
            inconsistentSecretKey,
            message,
            params,
            verifyAfterSign: true,
          ),
          throwsStateError,
        );
      },
      timeout: Timeout.none,
    );
  });
}

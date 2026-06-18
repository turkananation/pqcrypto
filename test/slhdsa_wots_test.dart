import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/address.dart';
import 'package:pqcrypto/src/algos/slhdsa/hashing.dart';
import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:pqcrypto/src/algos/slhdsa/wots.dart';
import 'package:test/test.dart';

Uint8List _sequence(int start, int length) => Uint8List.fromList(
  List<int>.generate(length, (index) => (start + index) & 0xff),
);

void main() {
  group('WOTS+ Algorithms 5-8', () {
    test('chain composition matches a single combined chain', () {
      final params = SlhDsaParams.shake128f;
      final wots = SlhDsaWots(SlhDsaHashFunctions.forParams(params));
      final input = _sequence(0x10, params.n);
      final publicSeed = _sequence(0x20, params.n);
      final address = Adrs()
        ..setTypeAndClear(AdrsType.wotsHash)
        ..setKeyPairAddress(7)
        ..setChainAddress(3);

      final first = wots.chain(input, 2, 5, publicSeed, address);
      final split = wots.chain(first, 7, 4, publicSeed, address);
      final combined = wots.chain(input, 2, 9, publicSeed, address);

      expect(split, equals(combined));
    });

    test('signatures recover the generated key for every SHAKE set', () {
      final shakeSets = SlhDsaParams.values.where(
        (candidate) => candidate.hashFamily == SlhDsaHashFamily.shake,
      );

      for (final params in shakeSets) {
        final wots = SlhDsaWots(SlhDsaHashFunctions.forParams(params));
        final secretSeed = _sequence(0x10, params.n);
        final publicSeed = _sequence(0x40, params.n);
        final message = _sequence(0x80, params.n);
        final address = Adrs()
          ..setLayerAddress(2)
          ..setTreeAddress(BigInt.from(0x1234))
          ..setTypeAndClear(AdrsType.wotsHash)
          ..setKeyPairAddress(5);
        final addressBefore = address.toBytes();

        final publicKey = wots.publicKey(secretSeed, publicSeed, address);
        final signature = wots.sign(message, secretSeed, publicSeed, address);
        final recovered = wots.publicKeyFromSignature(
          signature,
          message,
          publicSeed,
          address,
        );

        expect(publicKey, hasLength(params.n), reason: params.name);
        expect(
          signature,
          hasLength(params.wotsSignatureBytes),
          reason: params.name,
        );
        expect(recovered, equals(publicKey), reason: params.name);
        expect(address.toBytes(), equals(addressBefore), reason: params.name);
      }
    });

    test('a signature does not recover the same key for another message', () {
      final params = SlhDsaParams.shake128f;
      final wots = SlhDsaWots(SlhDsaHashFunctions.forParams(params));
      final secretSeed = _sequence(0x10, params.n);
      final publicSeed = _sequence(0x40, params.n);
      final message = _sequence(0x80, params.n);
      final otherMessage = Uint8List.fromList(message)..[0] ^= 1;
      final address = Adrs()..setKeyPairAddress(3);
      final publicKey = wots.publicKey(secretSeed, publicSeed, address);
      final signature = wots.sign(message, secretSeed, publicSeed, address);

      expect(
        wots.publicKeyFromSignature(
          signature,
          otherMessage,
          publicSeed,
          address,
        ),
        isNot(equals(publicKey)),
      );
    });

    test('rejects invalid lengths and chain ranges', () {
      final params = SlhDsaParams.shake128f;
      final wots = SlhDsaWots(SlhDsaHashFunctions.forParams(params));
      final nBytes = Uint8List(params.n);
      final short = Uint8List(params.n - 1);
      final address = Adrs();

      expect(
        () => wots.chain(short, 0, 1, nBytes, address),
        throwsArgumentError,
      );
      expect(
        () => wots.chain(nBytes, 0, 1, short, address),
        throwsArgumentError,
      );
      expect(
        () => wots.chain(nBytes, -1, 1, nBytes, address),
        throwsRangeError,
      );
      expect(
        () => wots.chain(nBytes, 0, params.w, nBytes, address),
        throwsRangeError,
      );
      expect(() => wots.publicKey(short, nBytes, address), throwsArgumentError);
      expect(
        () => wots.sign(short, nBytes, nBytes, address),
        throwsArgumentError,
      );
      expect(
        () => wots.publicKeyFromSignature(
          Uint8List(params.wotsSignatureBytes - 1),
          nBytes,
          nBytes,
          address,
        ),
        throwsArgumentError,
      );
    });
  });
}

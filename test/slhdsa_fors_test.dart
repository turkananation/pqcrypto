import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/address.dart';
import 'package:pqcrypto/src/algos/slhdsa/fors.dart';
import 'package:pqcrypto/src/algos/slhdsa/hashing.dart';
import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:test/test.dart';

Uint8List _sequence(int start, int length) => Uint8List.fromList(
  List<int>.generate(length, (index) => (start + index) & 0xff),
);

void main() {
  final params = SlhDsaParams.shake128f;
  final hashes = SlhDsaHashFunctions.forParams(params);
  final fors = SlhDsaFors(hashes);
  final secretSeed = _sequence(0x10, params.n);
  final publicSeed = _sequence(0x40, params.n);
  final messageDigest = _sequence(0x80, params.forsMessageBytes);
  final address = Adrs()
    ..setLayerAddress(1)
    ..setTreeAddress(BigInt.parse('123456789abcdef', radix: 16))
    ..setTypeAndClear(AdrsType.forsTree)
    ..setKeyPairAddress(5);

  group('FORS Algorithms 14-17', () {
    test('signature recovers the public key and preserves the address', () {
      final addressBefore = address.toBytes();
      final signature = fors.sign(
        messageDigest,
        secretSeed,
        publicSeed,
        address,
      );
      final publicKey = fors.publicKeyFromSignature(
        signature,
        messageDigest,
        publicSeed,
        address,
      );
      final roots = Uint8List(params.k * params.n);
      for (var tree = 0; tree < params.k; tree++) {
        roots.setRange(
          tree * params.n,
          (tree + 1) * params.n,
          fors.node(secretSeed, tree, params.a, publicSeed, address),
        );
      }
      final rootsAddress = address.copy()
        ..setTypeAndClear(AdrsType.forsRoots)
        ..setKeyPairAddress(address.getKeyPairAddress());
      final independentlyGenerated = hashes.tLen(
        publicSeed,
        rootsAddress,
        roots,
      );

      expect(signature, hasLength(params.forsSignatureBytes));
      expect(publicKey, hasLength(params.n));
      expect(publicKey, equals(independentlyGenerated));
      expect(address.toBytes(), equals(addressBefore));

      final repeated = fors.publicKeyFromSignature(
        signature,
        messageDigest,
        publicSeed,
        address,
      );
      expect(repeated, equals(publicKey));
    });

    test('node roots use the global index space across all FORS trees', () {
      for (var tree = 0; tree < params.k; tree++) {
        final root = fors.node(secretSeed, tree, params.a, publicSeed, address);
        expect(root, hasLength(params.n), reason: 'tree=$tree');
      }
    });

    test('tampering or changing the digest changes the recovered key', () {
      final signature = fors.sign(
        messageDigest,
        secretSeed,
        publicSeed,
        address,
      );
      final publicKey = fors.publicKeyFromSignature(
        signature,
        messageDigest,
        publicSeed,
        address,
      );
      final tampered = Uint8List.fromList(signature)..[params.n] ^= 1;
      final otherDigest = Uint8List.fromList(messageDigest)..[0] ^= 1;

      expect(
        fors.publicKeyFromSignature(
          tampered,
          messageDigest,
          publicSeed,
          address,
        ),
        isNot(equals(publicKey)),
      );
      expect(
        fors.publicKeyFromSignature(
          signature,
          otherDigest,
          publicSeed,
          address,
        ),
        isNot(equals(publicKey)),
      );
    });

    test('rejects invalid lengths, heights, and global indices', () {
      final shortN = Uint8List(params.n - 1);
      final shortDigest = Uint8List(params.forsMessageBytes - 1);

      expect(
        () => fors.secretKeyElement(shortN, publicSeed, address, 0),
        throwsArgumentError,
      );
      expect(
        () => fors.node(secretSeed, 0, params.a + 1, publicSeed, address),
        throwsRangeError,
      );
      expect(
        () => fors.node(secretSeed, params.k, params.a, publicSeed, address),
        throwsRangeError,
      );
      expect(
        () => fors.sign(shortDigest, secretSeed, publicSeed, address),
        throwsArgumentError,
      );
      expect(
        () => fors.publicKeyFromSignature(
          Uint8List(params.forsSignatureBytes - 1),
          messageDigest,
          publicSeed,
          address,
        ),
        throwsArgumentError,
      );
    });
  });
}

import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/address.dart';
import 'package:pqcrypto/src/algos/slhdsa/hashing.dart';
import 'package:pqcrypto/src/algos/slhdsa/hypertree.dart';
import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:pqcrypto/src/algos/slhdsa/xmss.dart';
import 'package:test/test.dart';

Uint8List _sequence(int start, int length) => Uint8List.fromList(
  List<int>.generate(length, (index) => (start + index) & 0xff),
);

void main() {
  final params = SlhDsaParams.shake128f;
  final hashes = SlhDsaHashFunctions.forParams(params);
  final secretSeed = _sequence(0x10, params.n);
  final publicSeed = _sequence(0x40, params.n);
  final message = _sequence(0x80, params.n);

  group('XMSS Algorithms 9-11', () {
    test('signature recovers the independently generated tree root', () {
      final xmss = SlhDsaXmss(hashes);
      final address = Adrs()
        ..setLayerAddress(4)
        ..setTreeAddress(BigInt.parse('123456789abcdef', radix: 16));
      final addressBefore = address.toBytes();
      const leafIndex = 5;

      final root = xmss.node(secretSeed, 0, params.hPrime, publicSeed, address);
      final signature = xmss.sign(
        message,
        secretSeed,
        leafIndex,
        publicSeed,
        address,
      );
      final recovered = xmss.publicKeyFromSignature(
        signature,
        message,
        leafIndex,
        publicSeed,
        address,
      );

      expect(root, hasLength(params.n));
      expect(signature, hasLength(params.xmssSignatureBytes));
      expect(recovered, equals(root));
      expect(address.toBytes(), equals(addressBefore));
    });

    test('tampering changes the recovered root', () {
      final xmss = SlhDsaXmss(hashes);
      final address = Adrs()
        ..setTreeAddress(BigInt.from(7))
        ..setLayerAddress(2);
      const leafIndex = 3;
      final root = xmss.node(secretSeed, 0, params.hPrime, publicSeed, address);
      final signature = xmss.sign(
        message,
        secretSeed,
        leafIndex,
        publicSeed,
        address,
      )..[params.wotsSignatureBytes] ^= 1;

      expect(
        xmss.publicKeyFromSignature(
          signature,
          message,
          leafIndex,
          publicSeed,
          address,
        ),
        isNot(equals(root)),
      );
    });

    test('rejects invalid node, leaf, and input lengths', () {
      final xmss = SlhDsaXmss(hashes);
      final short = Uint8List(params.n - 1);
      final address = Adrs();

      expect(
        () => xmss.node(secretSeed, 0, params.hPrime + 1, publicSeed, address),
        throwsRangeError,
      );
      expect(
        () => xmss.node(secretSeed, 1, params.hPrime, publicSeed, address),
        throwsRangeError,
      );
      expect(
        () => xmss.sign(short, secretSeed, 0, publicSeed, address),
        throwsArgumentError,
      );
      expect(
        () => xmss.sign(
          message,
          secretSeed,
          1 << params.hPrime,
          publicSeed,
          address,
        ),
        throwsRangeError,
      );
      expect(
        () => xmss.publicKeyFromSignature(
          Uint8List(params.xmssSignatureBytes - 1),
          message,
          0,
          publicSeed,
          address,
        ),
        throwsArgumentError,
      );
    });
  });

  group('hypertree Algorithms 12-13', () {
    test('full 128f hypertree signs and verifies across all 22 layers', () {
      final hypertree = SlhDsaHypertree(hashes);
      final treeIndex = BigInt.parse('123456789abcde', radix: 16);
      const leafIndex = 6;
      final topAddress = Adrs()
        ..setLayerAddress(params.d - 1)
        ..setTreeAddress(BigInt.zero);
      final publicRoot = hypertree.xmss.node(
        secretSeed,
        0,
        params.hPrime,
        publicSeed,
        topAddress,
      );
      final signature = hypertree.sign(
        message,
        secretSeed,
        publicSeed,
        treeIndex,
        leafIndex,
      );

      expect(signature, hasLength(params.hypertreeSignatureBytes));
      expect(
        hypertree.verify(
          message,
          signature,
          publicSeed,
          treeIndex,
          leafIndex,
          publicRoot,
        ),
        isTrue,
      );
    });

    test('rejects tampering, wrong roots, and out-of-range indices', () {
      final hypertree = SlhDsaHypertree(hashes);
      final treeIndex = BigInt.from(9);
      const leafIndex = 1;
      final topAddress = Adrs()
        ..setLayerAddress(params.d - 1)
        ..setTreeAddress(BigInt.zero);
      final publicRoot = hypertree.xmss.node(
        secretSeed,
        0,
        params.hPrime,
        publicSeed,
        topAddress,
      );
      final signature = hypertree.sign(
        message,
        secretSeed,
        publicSeed,
        treeIndex,
        leafIndex,
      )..[0] ^= 1;

      expect(
        hypertree.verify(
          message,
          signature,
          publicSeed,
          treeIndex,
          leafIndex,
          publicRoot,
        ),
        isFalse,
      );
      expect(
        () => hypertree.sign(
          message,
          secretSeed,
          publicSeed,
          BigInt.one << (params.h - params.hPrime),
          leafIndex,
        ),
        throwsRangeError,
      );
      expect(
        () => hypertree.verify(
          message,
          Uint8List(params.hypertreeSignatureBytes - 1),
          publicSeed,
          treeIndex,
          leafIndex,
          publicRoot,
        ),
        throwsArgumentError,
      );
    });
  });
}

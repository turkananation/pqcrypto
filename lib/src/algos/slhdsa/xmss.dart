import 'dart:typed_data';

import '../../common/zeroize.dart';
import 'address.dart';
import 'hashing.dart';
import 'params.dart';
import 'wots.dart';

/// FIPS 205 Algorithms 9-11: XMSS node generation, signing, and public-key
/// recovery.
final class SlhDsaXmss {
  SlhDsaXmss(this.hashes) : params = hashes.params, wots = SlhDsaWots(hashes);

  final SlhDsaHashFunctions hashes;
  final SlhDsaParams params;
  final SlhDsaWots wots;

  /// FIPS 205 Algorithm 9.
  Uint8List node(
    Uint8List secretSeed,
    int index,
    int height,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');
    if (height < 0 || height > params.hPrime) {
      throw RangeError.range(height, 0, params.hPrime, 'height');
    }
    final nodeCount = 1 << (params.hPrime - height);
    if (index < 0 || index >= nodeCount) {
      throw RangeError.range(index, 0, nodeCount - 1, 'index');
    }

    return _node(secretSeed, index, height, publicSeed, address.copy());
  }

  /// FIPS 205 Algorithm 10.
  Uint8List sign(
    Uint8List message,
    Uint8List secretSeed,
    int leafIndex,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireN(message, 'message');
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');
    _requireLeafIndex(leafIndex);

    final signature = Uint8List(params.xmssSignatureBytes);
    final xmssAddress = address.copy();

    for (var j = 0; j < params.hPrime; j++) {
      final authNode = _node(
        secretSeed,
        (leafIndex >> j) ^ 1,
        j,
        publicSeed,
        xmssAddress,
      );
      try {
        final offset = (params.len + j) * params.n;
        signature.setRange(offset, offset + params.n, authNode);
      } finally {
        secureZero(authNode);
      }
    }

    final wotsAddress = address.copy()
      ..setTypeAndClear(AdrsType.wotsHash)
      ..setKeyPairAddress(leafIndex);
    final wotsSignature = wots.sign(
      message,
      secretSeed,
      publicSeed,
      wotsAddress,
    );
    try {
      signature.setRange(0, params.wotsSignatureBytes, wotsSignature);
    } finally {
      secureZero(wotsSignature);
    }
    return signature;
  }

  /// FIPS 205 Algorithm 11.
  Uint8List publicKeyFromSignature(
    Uint8List signature,
    Uint8List message,
    int leafIndex,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireLength(signature, params.xmssSignatureBytes, 'signature');
    _requireN(message, 'message');
    _requireN(publicSeed, 'publicSeed');
    _requireLeafIndex(leafIndex);

    final wotsAddress = address.copy()
      ..setTypeAndClear(AdrsType.wotsHash)
      ..setKeyPairAddress(leafIndex);
    var current = wots.publicKeyFromSignature(
      Uint8List.sublistView(signature, 0, params.wotsSignatureBytes),
      message,
      publicSeed,
      wotsAddress,
    );
    final treeAddress = address.copy()
      ..setTypeAndClear(AdrsType.tree)
      ..setTreeIndex(leafIndex);
    var treeIndex = leafIndex;

    for (var k = 0; k < params.hPrime; k++) {
      final authOffset = (params.len + k) * params.n;
      final authNode = Uint8List.sublistView(
        signature,
        authOffset,
        authOffset + params.n,
      );
      treeAddress.setTreeHeight(k + 1);

      final hashInput = Uint8List(2 * params.n);
      if (((leafIndex >> k) & 1) == 0) {
        treeIndex ~/= 2;
        treeAddress.setTreeIndex(treeIndex);
        hashInput
          ..setRange(0, params.n, current)
          ..setRange(params.n, 2 * params.n, authNode);
      } else {
        treeIndex = (treeIndex - 1) ~/ 2;
        treeAddress.setTreeIndex(treeIndex);
        hashInput
          ..setRange(0, params.n, authNode)
          ..setRange(params.n, 2 * params.n, current);
      }

      try {
        final parent = hashes.h(publicSeed, treeAddress, hashInput);
        secureZero(current);
        current = parent;
      } finally {
        secureZero(hashInput);
      }
    }
    return current;
  }

  Uint8List _node(
    Uint8List secretSeed,
    int index,
    int height,
    Uint8List publicSeed,
    Adrs address,
  ) {
    if (height == 0) {
      final wotsAddress = address.copy()
        ..setTypeAndClear(AdrsType.wotsHash)
        ..setKeyPairAddress(index);
      return wots.publicKey(secretSeed, publicSeed, wotsAddress);
    }

    final left = _node(secretSeed, 2 * index, height - 1, publicSeed, address);
    final right = _node(
      secretSeed,
      2 * index + 1,
      height - 1,
      publicSeed,
      address,
    );
    final hashInput = Uint8List(2 * params.n)
      ..setRange(0, params.n, left)
      ..setRange(params.n, 2 * params.n, right);
    final treeAddress = address.copy()
      ..setTypeAndClear(AdrsType.tree)
      ..setTreeHeight(height)
      ..setTreeIndex(index);

    try {
      return hashes.h(publicSeed, treeAddress, hashInput);
    } finally {
      secureZero(left);
      secureZero(right);
      secureZero(hashInput);
    }
  }

  void _requireLeafIndex(int leafIndex) {
    final leafCount = 1 << params.hPrime;
    if (leafIndex < 0 || leafIndex >= leafCount) {
      throw RangeError.range(leafIndex, 0, leafCount - 1, 'leafIndex');
    }
  }

  void _requireN(Uint8List value, String name) {
    _requireLength(value, params.n, name);
  }

  void _requireLength(Uint8List value, int length, String name) {
    if (value.length != length) {
      throw ArgumentError.value(
        value.length,
        '$name.length',
        'must be exactly $length',
      );
    }
  }
}

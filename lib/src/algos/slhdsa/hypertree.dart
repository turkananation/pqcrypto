import 'dart:typed_data';

import '../../common/zeroize.dart';
import 'address.dart';
import 'hashing.dart';
import 'params.dart';
import 'xmss.dart';

/// FIPS 205 Algorithms 12-13: hypertree signing and verification.
final class SlhDsaHypertree {
  SlhDsaHypertree(this.hashes)
    : params = hashes.params,
      xmss = SlhDsaXmss(hashes);

  final SlhDsaHashFunctions hashes;
  final SlhDsaParams params;
  final SlhDsaXmss xmss;

  /// FIPS 205 Algorithm 12.
  Uint8List sign(
    Uint8List message,
    Uint8List secretSeed,
    Uint8List publicSeed,
    BigInt treeIndex,
    int leafIndex,
  ) {
    _requireN(message, 'message');
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');
    _requireTreeIndex(treeIndex);
    _requireLeafIndex(leafIndex);

    final signature = Uint8List(params.hypertreeSignatureBytes);
    var currentTree = treeIndex;
    var currentLeaf = leafIndex;
    final address = Adrs()..setTreeAddress(currentTree);

    var xmssSignature = xmss.sign(
      message,
      secretSeed,
      currentLeaf,
      publicSeed,
      address,
    );
    signature.setRange(0, params.xmssSignatureBytes, xmssSignature);
    var currentRoot = xmss.publicKeyFromSignature(
      xmssSignature,
      message,
      currentLeaf,
      publicSeed,
      address,
    );
    secureZero(xmssSignature);

    final leafMask = (BigInt.one << params.hPrime) - BigInt.one;
    for (var layer = 1; layer < params.d; layer++) {
      currentLeaf = (currentTree & leafMask).toInt();
      currentTree >>= params.hPrime;
      address
        ..setLayerAddress(layer)
        ..setTreeAddress(currentTree);

      xmssSignature = xmss.sign(
        currentRoot,
        secretSeed,
        currentLeaf,
        publicSeed,
        address,
      );
      final offset = layer * params.xmssSignatureBytes;
      signature.setRange(
        offset,
        offset + params.xmssSignatureBytes,
        xmssSignature,
      );

      if (layer < params.d - 1) {
        final nextRoot = xmss.publicKeyFromSignature(
          xmssSignature,
          currentRoot,
          currentLeaf,
          publicSeed,
          address,
        );
        secureZero(currentRoot);
        currentRoot = nextRoot;
      }
      secureZero(xmssSignature);
    }
    secureZero(currentRoot);
    return signature;
  }

  /// FIPS 205 Algorithm 13.
  bool verify(
    Uint8List message,
    Uint8List signature,
    Uint8List publicSeed,
    BigInt treeIndex,
    int leafIndex,
    Uint8List publicRoot,
  ) {
    _requireN(message, 'message');
    _requireLength(signature, params.hypertreeSignatureBytes, 'signature');
    _requireN(publicSeed, 'publicSeed');
    _requireTreeIndex(treeIndex);
    _requireLeafIndex(leafIndex);
    _requireN(publicRoot, 'publicRoot');

    var currentTree = treeIndex;
    var currentLeaf = leafIndex;
    final address = Adrs()..setTreeAddress(currentTree);
    var currentRoot = xmss.publicKeyFromSignature(
      Uint8List.sublistView(signature, 0, params.xmssSignatureBytes),
      message,
      currentLeaf,
      publicSeed,
      address,
    );

    final leafMask = (BigInt.one << params.hPrime) - BigInt.one;
    for (var layer = 1; layer < params.d; layer++) {
      currentLeaf = (currentTree & leafMask).toInt();
      currentTree >>= params.hPrime;
      address
        ..setLayerAddress(layer)
        ..setTreeAddress(currentTree);
      final offset = layer * params.xmssSignatureBytes;
      final nextRoot = xmss.publicKeyFromSignature(
        Uint8List.sublistView(
          signature,
          offset,
          offset + params.xmssSignatureBytes,
        ),
        currentRoot,
        currentLeaf,
        publicSeed,
        address,
      );
      secureZero(currentRoot);
      currentRoot = nextRoot;
    }

    var difference = 0;
    for (var i = 0; i < params.n; i++) {
      difference |= currentRoot[i] ^ publicRoot[i];
    }
    secureZero(currentRoot);
    return difference == 0;
  }

  void _requireTreeIndex(BigInt treeIndex) {
    final treeBits = params.h - params.hPrime;
    if (treeIndex.isNegative || treeIndex >= (BigInt.one << treeBits)) {
      throw RangeError('treeIndex must fit in $treeBits bits');
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

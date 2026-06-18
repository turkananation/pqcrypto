import 'dart:typed_data';

import '../../common/zeroize.dart';
import 'address.dart';
import 'hashing.dart';
import 'params.dart';
import 'util.dart';

/// FIPS 205 Algorithms 14-17: FORS secret generation, node generation,
/// signing, and public-key recovery.
final class SlhDsaFors {
  SlhDsaFors(this.hashes) : params = hashes.params;

  final SlhDsaHashFunctions hashes;
  final SlhDsaParams params;

  /// FIPS 205 Algorithm 14.
  Uint8List secretKeyElement(
    Uint8List secretSeed,
    Uint8List publicSeed,
    Adrs address,
    int index,
  ) {
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');
    _requireGlobalIndex(index, 0);

    return _secretKeyElement(secretSeed, publicSeed, address.copy(), index);
  }

  /// FIPS 205 Algorithm 15.
  Uint8List node(
    Uint8List secretSeed,
    int index,
    int height,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');
    if (height < 0 || height > params.a) {
      throw RangeError.range(height, 0, params.a, 'height');
    }
    _requireGlobalIndex(index, height);

    return _node(secretSeed, index, height, publicSeed, address.copy());
  }

  /// FIPS 205 Algorithm 16.
  Uint8List sign(
    Uint8List messageDigest,
    Uint8List secretSeed,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireLength(messageDigest, params.forsMessageBytes, 'messageDigest');
    _requireN(secretSeed, 'secretSeed');
    _requireN(publicSeed, 'publicSeed');

    final indices = base2b(messageDigest, params.a, params.k);
    final signature = Uint8List(params.forsSignatureBytes);
    final forsAddress = address.copy();

    for (var i = 0; i < params.k; i++) {
      final treeOffset = i * params.t;
      final secretIndex = treeOffset + indices[i];
      final secret = _secretKeyElement(
        secretSeed,
        publicSeed,
        forsAddress,
        secretIndex,
      );
      try {
        final treeSignatureOffset = i * (params.a + 1) * params.n;
        signature.setRange(
          treeSignatureOffset,
          treeSignatureOffset + params.n,
          secret,
        );
      } finally {
        secureZero(secret);
      }

      for (var j = 0; j < params.a; j++) {
        final authIndex = i * (1 << (params.a - j)) + ((indices[i] >> j) ^ 1);
        final authNode = _node(
          secretSeed,
          authIndex,
          j,
          publicSeed,
          forsAddress,
        );
        try {
          final authOffset = (i * (params.a + 1) + j + 1) * params.n;
          signature.setRange(authOffset, authOffset + params.n, authNode);
        } finally {
          secureZero(authNode);
        }
      }
    }
    return signature;
  }

  /// FIPS 205 Algorithm 17.
  Uint8List publicKeyFromSignature(
    Uint8List signature,
    Uint8List messageDigest,
    Uint8List publicSeed,
    Adrs address,
  ) {
    _requireLength(signature, params.forsSignatureBytes, 'signature');
    _requireLength(messageDigest, params.forsMessageBytes, 'messageDigest');
    _requireN(publicSeed, 'publicSeed');

    final indices = base2b(messageDigest, params.a, params.k);
    final roots = Uint8List(params.k * params.n);
    final keyPair = address.getKeyPairAddress();

    try {
      for (var i = 0; i < params.k; i++) {
        final treeOffset = i * params.t;
        var treeIndex = treeOffset + indices[i];
        final signatureOffset = i * (params.a + 1) * params.n;
        final treeAddress = address.copy()
          ..setTypeAndClear(AdrsType.forsTree)
          ..setKeyPairAddress(keyPair)
          ..setTreeHeight(0)
          ..setTreeIndex(treeIndex);
        var current = hashes.f(
          publicSeed,
          treeAddress,
          Uint8List.sublistView(
            signature,
            signatureOffset,
            signatureOffset + params.n,
          ),
        );

        for (var j = 0; j < params.a; j++) {
          final authOffset = signatureOffset + (j + 1) * params.n;
          final authNode = Uint8List.sublistView(
            signature,
            authOffset,
            authOffset + params.n,
          );
          treeAddress.setTreeHeight(j + 1);
          final hashInput = Uint8List(2 * params.n);

          // Parent index is treeIndex ~/ 2 in both cases: for odd treeIndex
          // (the else branch) (treeIndex - 1) ~/ 2 == treeIndex ~/ 2, since
          // ~/ truncates toward zero for non-negative ints. Only the left/right
          // hash ordering differs per branch.
          treeIndex ~/= 2;
          treeAddress.setTreeIndex(treeIndex);
          if (((indices[i] >> j) & 1) == 0) {
            hashInput
              ..setRange(0, params.n, current)
              ..setRange(params.n, 2 * params.n, authNode);
          } else {
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

        roots.setRange(i * params.n, (i + 1) * params.n, current);
        secureZero(current);
      }

      final rootsAddress = address.copy()
        ..setTypeAndClear(AdrsType.forsRoots)
        ..setKeyPairAddress(keyPair);
      return hashes.tLen(publicSeed, rootsAddress, roots);
    } finally {
      secureZero(roots);
    }
  }

  Uint8List _secretKeyElement(
    Uint8List secretSeed,
    Uint8List publicSeed,
    Adrs address,
    int index,
  ) {
    final keyPair = address.getKeyPairAddress();
    final secretAddress = address.copy()
      ..setTypeAndClear(AdrsType.forsPrf)
      ..setKeyPairAddress(keyPair)
      ..setTreeIndex(index);
    return hashes.prf(publicSeed, secretSeed, secretAddress);
  }

  Uint8List _node(
    Uint8List secretSeed,
    int index,
    int height,
    Uint8List publicSeed,
    Adrs address,
  ) {
    final keyPair = address.getKeyPairAddress();
    if (height == 0) {
      final secret = _secretKeyElement(secretSeed, publicSeed, address, index);
      final treeAddress = address.copy()
        ..setTypeAndClear(AdrsType.forsTree)
        ..setKeyPairAddress(keyPair)
        ..setTreeHeight(0)
        ..setTreeIndex(index);
      try {
        return hashes.f(publicSeed, treeAddress, secret);
      } finally {
        secureZero(secret);
      }
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
      ..setTypeAndClear(AdrsType.forsTree)
      ..setKeyPairAddress(keyPair)
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

  void _requireGlobalIndex(int index, int height) {
    final nodeCount = params.k * (1 << (params.a - height));
    if (index < 0 || index >= nodeCount) {
      throw RangeError.range(index, 0, nodeCount - 1, 'index');
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

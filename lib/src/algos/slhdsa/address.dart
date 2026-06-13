import 'dart:typed_data';

import 'util.dart';

/// FIPS 205 Table 1 address types.
enum AdrsType {
  wotsHash(0),
  wotsPk(1),
  tree(2),
  forsTree(3),
  forsRoots(4),
  wotsPrf(5),
  forsPrf(6);

  const AdrsType(this.value);

  final int value;
}

/// The 32-byte FIPS 205 address structure.
///
/// Layout: layer (4) || tree (12) || type (4) || type-specific (12).
final class Adrs {
  Adrs() : _bytes = Uint8List(byteLength);

  Adrs.fromBytes(Uint8List bytes) : _bytes = Uint8List.fromList(bytes) {
    if (bytes.length != byteLength) {
      throw ArgumentError.value(
        bytes.length,
        'bytes.length',
        'must be exactly $byteLength',
      );
    }
  }

  static const int byteLength = 32;
  static const int _layerOffset = 0;
  static const int _treeOffset = 4;
  static const int _typeOffset = 16;
  static const int _keyPairOffset = 20;
  static const int _chainOrHeightOffset = 24;
  static const int _hashOrIndexOffset = 28;

  final Uint8List _bytes;

  Uint8List toBytes() => Uint8List.fromList(_bytes);

  Adrs copy() => Adrs.fromBytes(_bytes);

  void setLayerAddress(int layer) {
    _setUint32(_layerOffset, layer, 'layer');
  }

  void setTreeAddress(BigInt tree) {
    _bytes.setRange(_treeOffset, _typeOffset, toByte(tree, 12));
  }

  /// Set the address type and clear all type-specific fields.
  void setTypeAndClear(AdrsType type) {
    _setUint32(_typeOffset, type.value, 'type');
    _bytes.fillRange(_keyPairOffset, byteLength, 0);
  }

  void setKeyPairAddress(int keyPair) {
    _setUint32(_keyPairOffset, keyPair, 'keyPair');
  }

  int getKeyPairAddress() => _getUint32(_keyPairOffset);

  void setChainAddress(int chain) {
    _setUint32(_chainOrHeightOffset, chain, 'chain');
  }

  void setTreeHeight(int height) {
    _setUint32(_chainOrHeightOffset, height, 'height');
  }

  void setHashAddress(int hash) {
    _setUint32(_hashOrIndexOffset, hash, 'hash');
  }

  void setTreeIndex(int index) {
    _setUint32(_hashOrIndexOffset, index, 'index');
  }

  int getTreeIndex() => _getUint32(_hashOrIndexOffset);

  void _setUint32(int offset, int value, String name) {
    if (value < 0 || value > 0xffffffff) {
      throw RangeError.range(value, 0, 0xffffffff, name);
    }
    _bytes.setRange(offset, offset + 4, toByte(BigInt.from(value), 4));
  }

  int _getUint32(int offset) =>
      toInt(Uint8List.sublistView(_bytes, offset, offset + 4)).toInt();
}

import 'dart:typed_data';

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
  Adrs() : this._(Uint8List(byteLength));

  factory Adrs.fromBytes(Uint8List bytes) {
    if (bytes.length != byteLength) {
      throw ArgumentError.value(
        bytes.length,
        'bytes.length',
        'must be exactly $byteLength',
      );
    }
    return Adrs._(Uint8List.fromList(bytes));
  }

  Adrs._(this._bytes) : _byteData = ByteData.sublistView(_bytes);

  static const int byteLength = 32;
  static const int compressedByteLength = 22;
  static const int _layerOffset = 0;
  static const int _treeOffset = 4;
  static const int _typeOffset = 16;
  static const int _keyPairOffset = 20;
  static const int _chainOrHeightOffset = 24;
  static const int _hashOrIndexOffset = 28;

  final Uint8List _bytes;
  final ByteData _byteData;

  Uint8List toBytes() => Uint8List.fromList(_bytes);

  /// Return the FIPS 205 Figure 18 compressed address `ADRS^c`.
  ///
  /// The canonical in-memory address remains the 32-byte Table 1 form. SHA-2
  /// hashing compresses it at the hash boundary, avoiding two mutable address
  /// layouts with different field offsets.
  Uint8List toCompressedBytes() {
    final output = Uint8List(compressedByteLength);
    copyCompressedBytesTo(output, 0);
    return output;
  }

  Adrs copy() => Adrs.fromBytes(_bytes);

  /// Copy this address into [destination] without exposing its backing store.
  void copyBytesTo(Uint8List destination, int offset) {
    RangeError.checkValidRange(
      offset,
      offset + byteLength,
      destination.length,
      'offset',
      'offset + byteLength',
    );
    destination.setRange(offset, offset + byteLength, _bytes);
  }

  /// Copy the FIPS 205 Figure 18 compressed address into [destination].
  void copyCompressedBytesTo(Uint8List destination, int offset) {
    RangeError.checkValidRange(
      offset,
      offset + compressedByteLength,
      destination.length,
      'offset',
      'offset + compressedByteLength',
    );
    destination[offset] = _bytes[3];
    destination.setRange(offset + 1, offset + 9, _bytes, 8);
    destination[offset + 9] = _bytes[19];
    destination.setRange(offset + 10, offset + 22, _bytes, 20);
  }

  void setLayerAddress(int layer) {
    _setUint32(_layerOffset, layer, 'layer');
  }

  void setTreeAddress(BigInt tree) {
    if (tree.isNegative) {
      throw ArgumentError.value(tree, 'tree', 'must be non-negative');
    }
    if (tree >= (BigInt.one << 96)) {
      throw RangeError('tree does not fit in 12 bytes');
    }

    var remaining = tree;
    final wordMask = BigInt.from(0xffffffff);
    for (var offset = _typeOffset - 4; offset >= _treeOffset; offset -= 4) {
      _byteData.setUint32(offset, (remaining & wordMask).toInt(), Endian.big);
      remaining >>= 32;
    }
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
    _byteData.setUint32(offset, value, Endian.big);
  }

  int _getUint32(int offset) => _byteData.getUint32(offset, Endian.big);
}

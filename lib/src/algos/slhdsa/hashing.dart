import 'dart:typed_data';

import '../../common/keccak.dart';
import '../../common/zeroize.dart';
import 'address.dart';
import 'params.dart';

/// Hash-family boundary used by SLH-DSA components.
abstract interface class SlhDsaHashFunctions {
  factory SlhDsaHashFunctions.forParams(SlhDsaParams params) {
    return switch (params.hashFamily) {
      SlhDsaHashFamily.shake => SlhDsaShakeHashFunctions(params),
      SlhDsaHashFamily.sha2 => throw UnsupportedError(
        'The SLH-DSA SHA-2 hash family is planned for v0.5.0',
      ),
    };
  }

  SlhDsaParams get params;

  Uint8List hMsg(
    Uint8List randomizer,
    Uint8List publicSeed,
    Uint8List publicRoot,
    Uint8List message,
  );

  Uint8List prf(Uint8List publicSeed, Uint8List secretSeed, Adrs address);

  Uint8List prfMsg(Uint8List secretPrf, Uint8List optRand, Uint8List message);

  Uint8List f(Uint8List publicSeed, Adrs address, Uint8List message);

  Uint8List h(Uint8List publicSeed, Adrs address, Uint8List message);

  Uint8List tLen(Uint8List publicSeed, Adrs address, Uint8List message);
}

/// FIPS 205 Section 11.1 SHAKE instantiation.
final class SlhDsaShakeHashFunctions implements SlhDsaHashFunctions {
  SlhDsaShakeHashFunctions(this.params) {
    if (params.hashFamily != SlhDsaHashFamily.shake) {
      throw ArgumentError.value(
        params.name,
        'params',
        'must select the SHAKE hash family',
      );
    }
  }

  @override
  final SlhDsaParams params;

  @override
  Uint8List hMsg(
    Uint8List randomizer,
    Uint8List publicSeed,
    Uint8List publicRoot,
    Uint8List message,
  ) {
    _requireN(randomizer, 'randomizer');
    _requireN(publicSeed, 'publicSeed');
    _requireN(publicRoot, 'publicRoot');
    return _shake(<Uint8List>[
      randomizer,
      publicSeed,
      publicRoot,
      message,
    ], params.messageDigestBytes);
  }

  @override
  Uint8List prf(Uint8List publicSeed, Uint8List secretSeed, Adrs address) {
    _requireN(publicSeed, 'publicSeed');
    _requireN(secretSeed, 'secretSeed');
    return _shakeWithAddress(publicSeed, address, secretSeed, params.n);
  }

  @override
  Uint8List prfMsg(Uint8List secretPrf, Uint8List optRand, Uint8List message) {
    _requireN(secretPrf, 'secretPrf');
    _requireN(optRand, 'optRand');
    return _shake(<Uint8List>[secretPrf, optRand, message], params.n);
  }

  @override
  Uint8List f(Uint8List publicSeed, Adrs address, Uint8List message) {
    _requireN(publicSeed, 'publicSeed');
    _requireLength(message, params.n, 'message');
    return _tweakableHash(publicSeed, address, message);
  }

  @override
  Uint8List h(Uint8List publicSeed, Adrs address, Uint8List message) {
    _requireN(publicSeed, 'publicSeed');
    _requireLength(message, 2 * params.n, 'message');
    return _tweakableHash(publicSeed, address, message);
  }

  @override
  Uint8List tLen(Uint8List publicSeed, Adrs address, Uint8List message) {
    _requireN(publicSeed, 'publicSeed');
    if (message.isEmpty || message.length % params.n != 0) {
      throw ArgumentError.value(
        message.length,
        'message.length',
        'must be a non-zero multiple of n (${params.n})',
      );
    }
    return _tweakableHash(publicSeed, address, message);
  }

  Uint8List _tweakableHash(
    Uint8List publicSeed,
    Adrs address,
    Uint8List message,
  ) => _shakeWithAddress(publicSeed, address, message, params.n);

  Uint8List _shakeWithAddress(
    Uint8List prefix,
    Adrs address,
    Uint8List suffix,
    int outputLength,
  ) {
    final addressOffset = prefix.length;
    final suffixOffset = addressOffset + Adrs.byteLength;
    final input = Uint8List(suffixOffset + suffix.length);
    try {
      input.setRange(0, addressOffset, prefix);
      address.copyBytesTo(input, addressOffset);
      input.setRange(suffixOffset, input.length, suffix);
      return shake256(input, outputLength);
    } finally {
      secureZero(input);
    }
  }

  Uint8List _shake(List<Uint8List> parts, int outputLength) {
    final inputLength = parts.fold<int>(0, (sum, part) => sum + part.length);
    final input = Uint8List(inputLength);
    try {
      var offset = 0;
      for (final part in parts) {
        input.setRange(offset, offset + part.length, part);
        offset += part.length;
      }
      return shake256(input, outputLength);
    } finally {
      secureZero(input);
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

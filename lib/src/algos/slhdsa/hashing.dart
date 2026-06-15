import 'dart:typed_data';

import '../../common/hmac.dart';
import '../../common/keccak.dart';
import '../../common/mgf1.dart';
import '../../common/sha2.dart';
import '../../common/zeroize.dart';
import 'address.dart';
import 'params.dart';

/// Hash-family boundary used by SLH-DSA components.
abstract interface class SlhDsaHashFunctions {
  factory SlhDsaHashFunctions.forParams(SlhDsaParams params) {
    return switch (params.hashFamily) {
      SlhDsaHashFamily.shake => SlhDsaShakeHashFunctions(params),
      SlhDsaHashFamily.sha2 => SlhDsaSha2HashFunctions(params),
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

/// FIPS 205 Section 11.2 SHA-2 instantiation.
final class SlhDsaSha2HashFunctions implements SlhDsaHashFunctions {
  SlhDsaSha2HashFunctions(this.params) {
    if (params.hashFamily != SlhDsaHashFamily.sha2) {
      throw ArgumentError.value(
        params.name,
        'params',
        'must select the SHA-2 hash family',
      );
    }
  }

  @override
  final SlhDsaParams params;

  bool get _isCategory1 => params.securityCategory == 1;

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

    final innerInput = Uint8List(
      randomizer.length +
          publicSeed.length +
          publicRoot.length +
          message.length,
    );
    Uint8List? innerDigest;
    Uint8List? mgfSeed;
    try {
      var offset = 0;
      for (final part in <Uint8List>[
        randomizer,
        publicSeed,
        publicRoot,
        message,
      ]) {
        innerInput.setRange(offset, offset + part.length, part);
        offset += part.length;
      }
      innerDigest = _isCategory1 ? sha256(innerInput) : sha512(innerInput);

      mgfSeed =
          Uint8List(randomizer.length + publicSeed.length + innerDigest.length)
            ..setRange(0, randomizer.length, randomizer)
            ..setRange(
              randomizer.length,
              randomizer.length + publicSeed.length,
              publicSeed,
            )
            ..setRange(
              randomizer.length + publicSeed.length,
              randomizer.length + publicSeed.length + innerDigest.length,
              innerDigest,
            );
      return _isCategory1
          ? mgf1Sha256(mgfSeed, params.messageDigestBytes)
          : mgf1Sha512(mgfSeed, params.messageDigestBytes);
    } finally {
      secureZero(innerInput);
      if (innerDigest != null) secureZero(innerDigest);
      if (mgfSeed != null) secureZero(mgfSeed);
    }
  }

  @override
  Uint8List prf(Uint8List publicSeed, Uint8List secretSeed, Adrs address) {
    _requireN(publicSeed, 'publicSeed');
    _requireN(secretSeed, 'secretSeed');
    return _hashWithAddress(
      publicSeed,
      address,
      secretSeed,
      blockLength: 64,
      digest: sha256,
    );
  }

  @override
  Uint8List prfMsg(Uint8List secretPrf, Uint8List optRand, Uint8List message) {
    _requireN(secretPrf, 'secretPrf');
    _requireN(optRand, 'optRand');
    final input = Uint8List(optRand.length + message.length)
      ..setRange(0, optRand.length, optRand)
      ..setRange(optRand.length, optRand.length + message.length, message);
    Uint8List? digest;
    try {
      digest = _isCategory1
          ? hmacSha256(secretPrf, input)
          : hmacSha512(secretPrf, input);
      return _truncate(digest);
    } finally {
      secureZero(input);
      if (digest != null) secureZero(digest);
    }
  }

  @override
  Uint8List f(Uint8List publicSeed, Adrs address, Uint8List message) {
    _requireN(publicSeed, 'publicSeed');
    _requireLength(message, params.n, 'message');
    return _hashWithAddress(
      publicSeed,
      address,
      message,
      blockLength: 64,
      digest: sha256,
    );
  }

  @override
  Uint8List h(Uint8List publicSeed, Adrs address, Uint8List message) {
    _requireN(publicSeed, 'publicSeed');
    _requireLength(message, 2 * params.n, 'message');
    return _isCategory1
        ? _hashWithAddress(
            publicSeed,
            address,
            message,
            blockLength: 64,
            digest: sha256,
          )
        : _hashWithAddress(
            publicSeed,
            address,
            message,
            blockLength: 128,
            digest: sha512,
          );
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
    return _isCategory1
        ? _hashWithAddress(
            publicSeed,
            address,
            message,
            blockLength: 64,
            digest: sha256,
          )
        : _hashWithAddress(
            publicSeed,
            address,
            message,
            blockLength: 128,
            digest: sha512,
          );
  }

  Uint8List _hashWithAddress(
    Uint8List publicSeed,
    Adrs address,
    Uint8List message, {
    required int blockLength,
    required Uint8List Function(Uint8List) digest,
  }) {
    final input = Uint8List(
      blockLength + Adrs.compressedByteLength + message.length,
    );
    Uint8List? fullDigest;
    try {
      input.setRange(0, publicSeed.length, publicSeed);
      address.copyCompressedBytesTo(input, blockLength);
      input.setRange(
        blockLength + Adrs.compressedByteLength,
        input.length,
        message,
      );
      fullDigest = digest(input);
      return _truncate(fullDigest);
    } finally {
      secureZero(input);
      if (fullDigest != null) secureZero(fullDigest);
    }
  }

  Uint8List _truncate(Uint8List digest) =>
      Uint8List.fromList(digest.sublist(0, params.n));

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

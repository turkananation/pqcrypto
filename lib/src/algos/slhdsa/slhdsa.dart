import 'dart:math';
import 'dart:typed_data';

import '../../common/keccak.dart';
import '../../common/sha2.dart';
import '../../common/zeroize.dart';
import 'address.dart';
import 'fors.dart';
import 'hashing.dart';
import 'hypertree.dart';
import 'params.dart';
import 'util.dart';
import 'xmss.dart';

/// Hash and XOF identifiers supported by HashSLH-DSA and the ACVP corpus.
///
/// Applications remain responsible for selecting a pre-hash whose collision
/// and second-preimage strength is sufficient for the SLH-DSA parameter set,
/// as required by FIPS 205 Section 10.2.
enum SlhDsaPreHash {
  sha224(0x04),
  sha256(0x01),
  sha384(0x02),
  sha512(0x03),
  sha512224(0x05),
  sha512256(0x06),
  sha3224(0x07),
  sha3256(0x08),
  sha3384(0x09),
  sha3512(0x0a),
  shake128(0x0b),
  shake256(0x0c);

  const SlhDsaPreHash(this.oidFinalByte);

  /// Final byte of the DER OID `06 09 60 86 48 01 65 03 04 02 XX`.
  final int oidFinalByte;
}

/// FIPS 205 Stateless Hash-Based Digital Signature Algorithm.
///
/// The public functions implement Algorithms 21-25 for all 12 FIPS 205
/// parameter sets. Signing is hedged by default; deterministic signing is an
/// explicit opt-in. The `s` parameter sets also require an explicit
/// slow-signing opt-in.
///
/// Message binding (BUFF): SLH-DSA's message-bound property is
/// parameter-dependent. Only the `*-128f` sets reach the category-1
/// message-binding bound (FIPS 205 Section 11); for other sets a signature may
/// be valid for more than one message in adversarial signer scenarios. When a
/// signature authorizes an action, bind it to its purpose with a unique context
/// and a nonce or unique message identity in the signed payload. The library
/// cannot enforce protocol-level message binding.
final class SlhDsa {
  SlhDsa._();

  static final Random _secureRng = Random.secure();
  static final Uint8List _emptyContext = Uint8List(0);
  static const List<int> _oidPrefix = <int>[
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
  ];

  /// FIPS 205 Algorithm 21. Returns `(publicKey, secretKey)`.
  static (Uint8List, Uint8List) generateKeyPair(SlhDsaParams params) {
    _requireSupportedParams(params);
    final secretSeed = _randomBytes(params.n);
    final secretPrf = _randomBytes(params.n);
    final publicSeed = _randomBytes(params.n);
    try {
      return _generateKeyPairSeeded(params, secretSeed, secretPrf, publicSeed);
    } finally {
      secureZero(secretSeed);
      secureZero(secretPrf);
      secureZero(publicSeed);
    }
  }

  static (Uint8List, Uint8List) _generateKeyPairSeeded(
    SlhDsaParams params,
    Uint8List secretSeed,
    Uint8List secretPrf,
    Uint8List publicSeed,
  ) {
    _requireSupportedParams(params);
    _requireLength(secretSeed, params.n, 'secretSeed');
    _requireLength(secretPrf, params.n, 'secretPrf');
    _requireLength(publicSeed, params.n, 'publicSeed');

    final hashes = SlhDsaHashFunctions.forParams(params);
    final topAddress = Adrs()..setLayerAddress(params.d - 1);
    final publicRoot = SlhDsaXmss(
      hashes,
    ).node(secretSeed, 0, params.hPrime, publicSeed, topAddress);
    try {
      final publicKey = Uint8List(params.publicKeyBytes)
        ..setRange(0, params.n, publicSeed)
        ..setRange(params.n, 2 * params.n, publicRoot);
      final secretKey = Uint8List(params.secretKeyBytes)
        ..setRange(0, params.n, secretSeed)
        ..setRange(params.n, 2 * params.n, secretPrf)
        ..setRange(2 * params.n, 3 * params.n, publicSeed)
        ..setRange(3 * params.n, 4 * params.n, publicRoot);
      return (publicKey, secretKey);
    } finally {
      secureZero(publicRoot);
    }
  }

  /// FIPS 205 Algorithm 22, hedged by default.
  ///
  /// Slow `s` parameter sets require [allowSlowSigning] because a single
  /// signature can take substantially longer than an `f` parameter signature.
  /// Set [verifyAfterSign] to detect generation faults by verifying the result
  /// before it is returned. This adds the full verification cost and is not a
  /// substitute for platform fault protections.
  ///
  /// SLH-DSA's message-bound (BUFF) property is parameter-dependent: only the
  /// `*-128f` sets reach the category-1 bound (FIPS 205 Section 11). When a
  /// signature authorizes an action, transfer, or consent, bind it with a unique
  /// context and a nonce or unique message identity in [message].
  static Uint8List sign(
    Uint8List secretKey,
    Uint8List message,
    SlhDsaParams params, {
    Uint8List? context,
    Uint8List? additionalRandomness,
    bool allowSlowSigning = false,
    bool verifyAfterSign = false,
  }) {
    _requireSupportedParams(params);
    _requireSigningAllowed(params, allowSlowSigning);
    _requireLength(secretKey, params.secretKeyBytes, 'secretKey');
    if (additionalRandomness != null) {
      _requireLength(additionalRandomness, params.n, 'additionalRandomness');
    }
    final formatted = _formatMessage(0x00, context, message);
    final randomness = additionalRandomness ?? _randomBytes(params.n);
    try {
      final signature = _signInternal(
        secretKey,
        formatted,
        params,
        additionalRandomness: randomness,
      );
      return _verifyGeneratedSignature(
        secretKey,
        formatted,
        signature,
        params,
        verifyAfterSign,
      );
    } finally {
      secureZero(formatted);
      if (additionalRandomness == null) secureZero(randomness);
    }
  }

  /// Deterministic FIPS 205 Algorithm 22 (`opt_rand = PK.seed`).
  static Uint8List signDeterministic(
    Uint8List secretKey,
    Uint8List message,
    SlhDsaParams params, {
    Uint8List? context,
    bool allowSlowSigning = false,
    bool verifyAfterSign = false,
  }) {
    _requireSupportedParams(params);
    _requireSigningAllowed(params, allowSlowSigning);
    _requireLength(secretKey, params.secretKeyBytes, 'secretKey');
    final formatted = _formatMessage(0x00, context, message);
    try {
      final signature = _signInternal(secretKey, formatted, params);
      return _verifyGeneratedSignature(
        secretKey,
        formatted,
        signature,
        params,
        verifyAfterSign,
      );
    } finally {
      secureZero(formatted);
    }
  }

  /// FIPS 205 Algorithm 23, hedged by default.
  static Uint8List hashSign(
    Uint8List secretKey,
    Uint8List message,
    SlhDsaPreHash preHash,
    SlhDsaParams params, {
    Uint8List? context,
    Uint8List? additionalRandomness,
    bool allowSlowSigning = false,
    bool verifyAfterSign = false,
  }) {
    _requireSupportedParams(params);
    _requireSigningAllowed(params, allowSlowSigning);
    _requireLength(secretKey, params.secretKeyBytes, 'secretKey');
    if (additionalRandomness != null) {
      _requireLength(additionalRandomness, params.n, 'additionalRandomness');
    }
    final formatted = _formatPreHashMessage(context, message, preHash);
    final randomness = additionalRandomness ?? _randomBytes(params.n);
    try {
      final signature = _signInternal(
        secretKey,
        formatted,
        params,
        additionalRandomness: randomness,
      );
      return _verifyGeneratedSignature(
        secretKey,
        formatted,
        signature,
        params,
        verifyAfterSign,
      );
    } finally {
      secureZero(formatted);
      if (additionalRandomness == null) secureZero(randomness);
    }
  }

  /// Deterministic FIPS 205 Algorithm 23 (`opt_rand = PK.seed`).
  static Uint8List hashSignDeterministic(
    Uint8List secretKey,
    Uint8List message,
    SlhDsaPreHash preHash,
    SlhDsaParams params, {
    Uint8List? context,
    bool allowSlowSigning = false,
    bool verifyAfterSign = false,
  }) {
    _requireSupportedParams(params);
    _requireSigningAllowed(params, allowSlowSigning);
    _requireLength(secretKey, params.secretKeyBytes, 'secretKey');
    final formatted = _formatPreHashMessage(context, message, preHash);
    try {
      final signature = _signInternal(secretKey, formatted, params);
      return _verifyGeneratedSignature(
        secretKey,
        formatted,
        signature,
        params,
        verifyAfterSign,
      );
    } finally {
      secureZero(formatted);
    }
  }

  static Uint8List _signInternal(
    Uint8List secretKey,
    Uint8List message,
    SlhDsaParams params, {
    Uint8List? additionalRandomness,
  }) {
    _requireSupportedParams(params);
    _requireLength(secretKey, params.secretKeyBytes, 'secretKey');
    if (additionalRandomness != null) {
      _requireLength(additionalRandomness, params.n, 'additionalRandomness');
    }

    final hashes = SlhDsaHashFunctions.forParams(params);
    final fors = SlhDsaFors(hashes);
    final hypertree = SlhDsaHypertree(hashes);
    final secretSeed = Uint8List.fromList(secretKey.sublist(0, params.n));
    final secretPrf = Uint8List.fromList(
      secretKey.sublist(params.n, 2 * params.n),
    );
    final publicSeed = Uint8List.fromList(
      secretKey.sublist(2 * params.n, 3 * params.n),
    );
    final publicRoot = Uint8List.fromList(
      secretKey.sublist(3 * params.n, 4 * params.n),
    );
    final optRand = Uint8List.fromList(additionalRandomness ?? publicSeed);

    Uint8List? randomizer;
    Uint8List? digest;
    Uint8List? messageDigest;
    Uint8List? forsSignature;
    Uint8List? forsPublicKey;
    Uint8List? hypertreeSignature;
    try {
      randomizer = hashes.prfMsg(secretPrf, optRand, message);
      digest = hashes.hMsg(randomizer, publicSeed, publicRoot, message);
      final indices = _splitDigest(digest, params);
      messageDigest = indices.messageDigest;

      final forsAddress = Adrs()
        ..setTreeAddress(indices.treeIndex)
        ..setTypeAndClear(AdrsType.forsTree)
        ..setKeyPairAddress(indices.leafIndex);
      forsSignature = fors.sign(
        messageDigest,
        secretSeed,
        publicSeed,
        forsAddress,
      );
      forsPublicKey = fors.publicKeyFromSignature(
        forsSignature,
        messageDigest,
        publicSeed,
        forsAddress,
      );
      hypertreeSignature = hypertree.sign(
        forsPublicKey,
        secretSeed,
        publicSeed,
        indices.treeIndex,
        indices.leafIndex,
      );

      return Uint8List(params.signatureBytes)
        ..setRange(0, params.n, randomizer)
        ..setRange(
          params.n,
          params.n + params.forsSignatureBytes,
          forsSignature,
        )
        ..setRange(
          params.n + params.forsSignatureBytes,
          params.signatureBytes,
          hypertreeSignature,
        );
    } finally {
      secureZero(secretSeed);
      secureZero(secretPrf);
      secureZero(publicSeed);
      secureZero(publicRoot);
      secureZero(optRand);
      secureZero(randomizer);
      secureZero(digest);
      secureZero(messageDigest);
      secureZero(forsSignature);
      secureZero(forsPublicKey);
      secureZero(hypertreeSignature);
    }
  }

  /// FIPS 205 Algorithm 24. Malformed inputs return `false`.
  static bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
    SlhDsaParams params, {
    Uint8List? context,
  }) {
    _requireSupportedParams(params);
    if ((context?.length ?? 0) > 255) return false;
    final formatted = _formatMessage(0x00, context, message);
    try {
      return _verifyInternal(publicKey, formatted, signature, params);
    } finally {
      secureZero(formatted);
    }
  }

  /// FIPS 205 Algorithm 25. Malformed inputs return `false`.
  static bool hashVerify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
    SlhDsaPreHash preHash,
    SlhDsaParams params, {
    Uint8List? context,
  }) {
    _requireSupportedParams(params);
    if ((context?.length ?? 0) > 255) return false;
    final formatted = _formatPreHashMessage(context, message, preHash);
    try {
      return _verifyInternal(publicKey, formatted, signature, params);
    } finally {
      secureZero(formatted);
    }
  }

  static bool _verifyInternal(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
    SlhDsaParams params,
  ) {
    _requireSupportedParams(params);
    if (publicKey.length != params.publicKeyBytes ||
        signature.length != params.signatureBytes) {
      return false;
    }

    final hashes = SlhDsaHashFunctions.forParams(params);
    final publicSeed = Uint8List.sublistView(publicKey, 0, params.n);
    final publicRoot = Uint8List.sublistView(publicKey, params.n, 2 * params.n);
    final randomizer = Uint8List.sublistView(signature, 0, params.n);
    final forsEnd = params.n + params.forsSignatureBytes;
    final forsSignature = Uint8List.sublistView(signature, params.n, forsEnd);
    final hypertreeSignature = Uint8List.sublistView(
      signature,
      forsEnd,
      params.signatureBytes,
    );

    Uint8List? digest;
    Uint8List? messageDigest;
    Uint8List? forsPublicKey;
    try {
      digest = hashes.hMsg(randomizer, publicSeed, publicRoot, message);
      final indices = _splitDigest(digest, params);
      messageDigest = indices.messageDigest;
      final forsAddress = Adrs()
        ..setTreeAddress(indices.treeIndex)
        ..setTypeAndClear(AdrsType.forsTree)
        ..setKeyPairAddress(indices.leafIndex);
      forsPublicKey = SlhDsaFors(hashes).publicKeyFromSignature(
        forsSignature,
        messageDigest,
        publicSeed,
        forsAddress,
      );
      return SlhDsaHypertree(hashes).verify(
        forsPublicKey,
        hypertreeSignature,
        publicSeed,
        indices.treeIndex,
        indices.leafIndex,
        publicRoot,
      );
    } catch (_) {
      return false;
    } finally {
      secureZero(digest);
      secureZero(messageDigest);
      secureZero(forsPublicKey);
    }
  }

  static Uint8List _formatMessage(
    int domain,
    Uint8List? context,
    Uint8List payload, [
    Uint8List? oid,
  ]) {
    final actualContext = context ?? _emptyContext;
    if (actualContext.length > 255) {
      throw ArgumentError('Context string must be at most 255 bytes');
    }
    final oidLength = oid?.length ?? 0;
    final output = Uint8List(
      2 + actualContext.length + oidLength + payload.length,
    );
    output[0] = domain;
    output[1] = actualContext.length;
    var offset = 2;
    output.setRange(offset, offset + actualContext.length, actualContext);
    offset += actualContext.length;
    if (oid != null) {
      output.setRange(offset, offset + oid.length, oid);
      offset += oid.length;
    }
    output.setRange(offset, output.length, payload);
    return output;
  }

  static Uint8List _formatPreHashMessage(
    Uint8List? context,
    Uint8List message,
    SlhDsaPreHash preHash,
  ) {
    final oid = Uint8List(11)
      ..setRange(0, 10, _oidPrefix)
      ..[10] = preHash.oidFinalByte;
    final digest = _preHash(message, preHash);
    try {
      return _formatMessage(0x01, context, digest, oid);
    } finally {
      secureZero(oid);
      secureZero(digest);
    }
  }

  static Uint8List _preHash(Uint8List message, SlhDsaPreHash preHash) =>
      switch (preHash) {
        SlhDsaPreHash.sha224 => sha224(message),
        SlhDsaPreHash.sha256 => sha256(message),
        SlhDsaPreHash.sha384 => sha384(message),
        SlhDsaPreHash.sha512 => sha512(message),
        SlhDsaPreHash.sha512224 => sha512224(message),
        SlhDsaPreHash.sha512256 => sha512256(message),
        SlhDsaPreHash.sha3224 => sha3224(message),
        SlhDsaPreHash.sha3256 => sha3256(message),
        SlhDsaPreHash.sha3384 => sha3384(message),
        SlhDsaPreHash.sha3512 => sha3512(message),
        SlhDsaPreHash.shake128 => shake128(message, 32),
        SlhDsaPreHash.shake256 => shake256(message, 64),
      };

  static ({Uint8List messageDigest, BigInt treeIndex, int leafIndex})
  _splitDigest(Uint8List digest, SlhDsaParams params) {
    var offset = 0;
    final messageDigest = Uint8List.fromList(
      digest.sublist(offset, offset + params.forsMessageBytes),
    );
    offset += params.forsMessageBytes;
    final treeBytes = Uint8List.sublistView(
      digest,
      offset,
      offset + params.treeIndexBytes,
    );
    offset += params.treeIndexBytes;
    final leafBytes = Uint8List.sublistView(
      digest,
      offset,
      offset + params.leafIndexBytes,
    );
    final treeMask = (BigInt.one << (params.h - params.hPrime)) - BigInt.one;
    final leafMask = (BigInt.one << params.hPrime) - BigInt.one;
    return (
      messageDigest: messageDigest,
      treeIndex: toInt(treeBytes) & treeMask,
      leafIndex: (toInt(leafBytes) & leafMask).toInt(),
    );
  }

  static Uint8List _randomBytes(int length) {
    final output = Uint8List(length);
    for (var i = 0; i < length; i++) {
      output[i] = _secureRng.nextInt(256);
    }
    return output;
  }

  static Uint8List _verifyGeneratedSignature(
    Uint8List secretKey,
    Uint8List formattedMessage,
    Uint8List signature,
    SlhDsaParams params,
    bool verifyAfterSign,
  ) {
    if (!verifyAfterSign) return signature;

    final publicKey = Uint8List.sublistView(
      secretKey,
      2 * params.n,
      4 * params.n,
    );
    if (!_verifyInternal(publicKey, formattedMessage, signature, params)) {
      secureZero(signature);
      throw StateError(
        'Generated ${params.name} signature failed self-verification',
      );
    }
    return signature;
  }

  static void _requireSupportedParams(SlhDsaParams params) {
    if (!params.isSupported) {
      throw UnsupportedError(
        '${params.name} is not implemented; use one of '
        'SlhDsaParams.supportedValues',
      );
    }
  }

  static void _requireSigningAllowed(
    SlhDsaParams params,
    bool allowSlowSigning,
  ) {
    if (!params.isFast && !allowSlowSigning) {
      throw UnsupportedError(
        '${params.name} signing is disabled by default because it is slow; '
        'pass allowSlowSigning: true to opt in',
      );
    }
  }

  static void _requireLength(Uint8List value, int expected, String name) {
    if (value.length != expected) {
      throw ArgumentError.value(
        value.length,
        '$name.length',
        'must be exactly $expected',
      );
    }
  }
}

/// Source-only FIPS 205 Algorithms 18-20 used by the ACVP runner.
///
/// This facade is intentionally not exported from `package:pqcrypto/pqcrypto.dart`.
/// Application code should use [SlhDsa].
final class SlhDsaInternal {
  SlhDsaInternal._();

  /// FIPS 205 Algorithm 18. Returns `(publicKey, secretKey)`.
  static (Uint8List, Uint8List) generateKeyPairSeeded(
    SlhDsaParams params,
    Uint8List secretSeed,
    Uint8List secretPrf,
    Uint8List publicSeed,
  ) => SlhDsa._generateKeyPairSeeded(params, secretSeed, secretPrf, publicSeed);

  /// FIPS 205 Algorithm 19 over an already formatted message.
  ///
  /// If [additionalRandomness] is omitted, the deterministic variant uses
  /// `PK.seed` as `opt_rand`.
  static Uint8List sign(
    Uint8List secretKey,
    Uint8List message,
    SlhDsaParams params, {
    Uint8List? additionalRandomness,
  }) => SlhDsa._signInternal(
    secretKey,
    message,
    params,
    additionalRandomness: additionalRandomness,
  );

  /// FIPS 205 Algorithm 20 over an already formatted message.
  static bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
    SlhDsaParams params,
  ) => SlhDsa._verifyInternal(publicKey, message, signature, params);
}

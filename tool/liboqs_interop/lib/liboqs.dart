import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

final class OqsKem extends Opaque {}

final class OqsSig extends Opaque {}

typedef _OqsInitNative = Void Function();
typedef _OqsInitDart = void Function();
typedef _OqsDestroyNative = Void Function();
typedef _OqsDestroyDart = void Function();
typedef _OqsVersionNative = Pointer<Utf8> Function();
typedef _OqsVersionDart = Pointer<Utf8> Function();

typedef _AlgorithmEnabledNative = Int32 Function(Pointer<Utf8>);
typedef _AlgorithmEnabledDart = int Function(Pointer<Utf8>);

typedef _KemNewNative = Pointer<OqsKem> Function(Pointer<Utf8>);
typedef _KemNewDart = Pointer<OqsKem> Function(Pointer<Utf8>);
typedef _KemFreeNative = Void Function(Pointer<OqsKem>);
typedef _KemFreeDart = void Function(Pointer<OqsKem>);
typedef _KemKeyPairNative =
    Int32 Function(Pointer<OqsKem>, Pointer<Uint8>, Pointer<Uint8>);
typedef _KemKeyPairDart =
    int Function(Pointer<OqsKem>, Pointer<Uint8>, Pointer<Uint8>);
typedef _KemKeyPairDerandNative =
    Int32 Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemKeyPairDerandDart =
    int Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemEncapsNative =
    Int32 Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemEncapsDart =
    int Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemEncapsDerandNative =
    Int32 Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemEncapsDerandDart =
    int Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemDecapsNative =
    Int32 Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _KemDecapsDart =
    int Function(
      Pointer<OqsKem>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );

typedef _SigSupportsContextNative = Bool Function(Pointer<Utf8>);
typedef _SigSupportsContextDart = bool Function(Pointer<Utf8>);
typedef _SigNewNative = Pointer<OqsSig> Function(Pointer<Utf8>);
typedef _SigNewDart = Pointer<OqsSig> Function(Pointer<Utf8>);
typedef _SigFreeNative = Void Function(Pointer<OqsSig>);
typedef _SigFreeDart = void Function(Pointer<OqsSig>);
typedef _SigKeyPairNative =
    Int32 Function(Pointer<OqsSig>, Pointer<Uint8>, Pointer<Uint8>);
typedef _SigKeyPairDart =
    int Function(Pointer<OqsSig>, Pointer<Uint8>, Pointer<Uint8>);
typedef _SigSignContextNative =
    Int32 Function(
      Pointer<OqsSig>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
    );
typedef _SigSignContextDart =
    int Function(
      Pointer<OqsSig>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
    );
typedef _SigVerifyContextNative =
    Int32 Function(
      Pointer<OqsSig>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
    );
typedef _SigVerifyContextDart =
    int Function(
      Pointer<OqsSig>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
    );

/// Thin, provider-wide FFI adapter over liboqs's generic KEM and signature APIs.
final class LiboqsInterop {
  LiboqsInterop.load(String path) : _library = DynamicLibrary.open(path) {
    _init = _library.lookupFunction<_OqsInitNative, _OqsInitDart>('OQS_init');
    _destroy = _library.lookupFunction<_OqsDestroyNative, _OqsDestroyDart>(
      'OQS_destroy',
    );
    _version = _library.lookupFunction<_OqsVersionNative, _OqsVersionDart>(
      'OQS_version',
    );

    _kemAlgorithmEnabled = _library
        .lookupFunction<_AlgorithmEnabledNative, _AlgorithmEnabledDart>(
          'OQS_KEM_alg_is_enabled',
        );
    _kemNew = _library.lookupFunction<_KemNewNative, _KemNewDart>(
      'OQS_KEM_new',
    );
    _kemFree = _library.lookupFunction<_KemFreeNative, _KemFreeDart>(
      'OQS_KEM_free',
    );
    _kemKeyPair = _library.lookupFunction<_KemKeyPairNative, _KemKeyPairDart>(
      'OQS_KEM_keypair',
    );
    _kemKeyPairDerand = _library
        .lookupFunction<_KemKeyPairDerandNative, _KemKeyPairDerandDart>(
          'OQS_KEM_keypair_derand',
        );
    _kemEncaps = _library.lookupFunction<_KemEncapsNative, _KemEncapsDart>(
      'OQS_KEM_encaps',
    );
    _kemEncapsDerand = _library
        .lookupFunction<_KemEncapsDerandNative, _KemEncapsDerandDart>(
          'OQS_KEM_encaps_derand',
        );
    _kemDecaps = _library.lookupFunction<_KemDecapsNative, _KemDecapsDart>(
      'OQS_KEM_decaps',
    );

    _sigAlgorithmEnabled = _library
        .lookupFunction<_AlgorithmEnabledNative, _AlgorithmEnabledDart>(
          'OQS_SIG_alg_is_enabled',
        );
    _sigSupportsContext = _library
        .lookupFunction<_SigSupportsContextNative, _SigSupportsContextDart>(
          'OQS_SIG_supports_ctx_str',
        );
    _sigNew = _library.lookupFunction<_SigNewNative, _SigNewDart>(
      'OQS_SIG_new',
    );
    _sigFree = _library.lookupFunction<_SigFreeNative, _SigFreeDart>(
      'OQS_SIG_free',
    );
    _sigKeyPair = _library.lookupFunction<_SigKeyPairNative, _SigKeyPairDart>(
      'OQS_SIG_keypair',
    );
    _sigSign = _library
        .lookupFunction<_SigSignContextNative, _SigSignContextDart>(
          'OQS_SIG_sign_with_ctx_str',
        );
    _sigVerify = _library
        .lookupFunction<_SigVerifyContextNative, _SigVerifyContextDart>(
          'OQS_SIG_verify_with_ctx_str',
        );

    _init();
  }

  final DynamicLibrary _library;
  late final _OqsInitDart _init;
  late final _OqsDestroyDart _destroy;
  late final _OqsVersionDart _version;
  late final _AlgorithmEnabledDart _kemAlgorithmEnabled;
  late final _KemNewDart _kemNew;
  late final _KemFreeDart _kemFree;
  late final _KemKeyPairDart _kemKeyPair;
  late final _KemKeyPairDerandDart _kemKeyPairDerand;
  late final _KemEncapsDart _kemEncaps;
  late final _KemEncapsDerandDart _kemEncapsDerand;
  late final _KemDecapsDart _kemDecaps;
  late final _AlgorithmEnabledDart _sigAlgorithmEnabled;
  late final _SigSupportsContextDart _sigSupportsContext;
  late final _SigNewDart _sigNew;
  late final _SigFreeDart _sigFree;
  late final _SigKeyPairDart _sigKeyPair;
  late final _SigSignContextDart _sigSign;
  late final _SigVerifyContextDart _sigVerify;
  var _disposed = false;

  String version() => _version().toDartString();

  bool isKemEnabled(String algorithm) =>
      _withAlgorithmName(algorithm, _kemAlgorithmEnabled) == 1;

  bool isSignatureEnabled(String algorithm) =>
      _withAlgorithmName(algorithm, _sigAlgorithmEnabled) == 1;

  bool signatureSupportsContext(String algorithm) =>
      _withAlgorithmNameBool(algorithm, _sigSupportsContext);

  (Uint8List, Uint8List) generateKemKeyPair(
    String algorithm, {
    required int publicKeyBytes,
    required int secretKeyBytes,
    Uint8List? seed,
  }) {
    final kem = _newKem(algorithm);
    final publicKey = calloc<Uint8>(publicKeyBytes);
    final secretKey = calloc<Uint8>(secretKeyBytes);
    final seedPointer = seed == null ? nullptr : _copy(seed);
    try {
      final result = seed == null
          ? _kemKeyPair(kem, publicKey, secretKey)
          : _kemKeyPairDerand(kem, publicKey, secretKey, seedPointer);
      if (result != 0) {
        throw StateError('liboqs keypair failed for $algorithm');
      }
      return (
        Uint8List.fromList(publicKey.asTypedList(publicKeyBytes)),
        Uint8List.fromList(secretKey.asTypedList(secretKeyBytes)),
      );
    } finally {
      secretKey.asTypedList(secretKeyBytes).fillRange(0, secretKeyBytes, 0);
      if (seed != null) {
        seedPointer.asTypedList(seed.length).fillRange(0, seed.length, 0);
        calloc.free(seedPointer);
      }
      calloc.free(publicKey);
      calloc.free(secretKey);
      _kemFree(kem);
    }
  }

  (Uint8List, Uint8List) encapsulate(
    String algorithm,
    Uint8List publicKey, {
    required int ciphertextBytes,
    required int sharedSecretBytes,
    Uint8List? seed,
  }) {
    final kem = _newKem(algorithm);
    final publicKeyPointer = _copy(publicKey);
    final ciphertext = calloc<Uint8>(ciphertextBytes);
    final sharedSecret = calloc<Uint8>(sharedSecretBytes);
    final seedPointer = seed == null ? nullptr : _copy(seed);
    try {
      final result = seed == null
          ? _kemEncaps(kem, ciphertext, sharedSecret, publicKeyPointer)
          : _kemEncapsDerand(
              kem,
              ciphertext,
              sharedSecret,
              publicKeyPointer,
              seedPointer,
            );
      if (result != 0) {
        throw StateError('liboqs encapsulation failed for $algorithm');
      }
      return (
        Uint8List.fromList(ciphertext.asTypedList(ciphertextBytes)),
        Uint8List.fromList(sharedSecret.asTypedList(sharedSecretBytes)),
      );
    } finally {
      sharedSecret
          .asTypedList(sharedSecretBytes)
          .fillRange(0, sharedSecretBytes, 0);
      if (seed != null) {
        seedPointer.asTypedList(seed.length).fillRange(0, seed.length, 0);
        calloc.free(seedPointer);
      }
      calloc.free(publicKeyPointer);
      calloc.free(ciphertext);
      calloc.free(sharedSecret);
      _kemFree(kem);
    }
  }

  Uint8List decapsulate(
    String algorithm,
    Uint8List secretKey,
    Uint8List ciphertext, {
    required int sharedSecretBytes,
  }) {
    final kem = _newKem(algorithm);
    final secretKeyPointer = _copy(secretKey);
    final ciphertextPointer = _copy(ciphertext);
    final sharedSecret = calloc<Uint8>(sharedSecretBytes);
    try {
      if (_kemDecaps(kem, sharedSecret, ciphertextPointer, secretKeyPointer) !=
          0) {
        throw StateError('liboqs decapsulation failed for $algorithm');
      }
      return Uint8List.fromList(sharedSecret.asTypedList(sharedSecretBytes));
    } finally {
      secretKeyPointer
          .asTypedList(secretKey.length)
          .fillRange(0, secretKey.length, 0);
      sharedSecret
          .asTypedList(sharedSecretBytes)
          .fillRange(0, sharedSecretBytes, 0);
      calloc.free(secretKeyPointer);
      calloc.free(ciphertextPointer);
      calloc.free(sharedSecret);
      _kemFree(kem);
    }
  }

  (Uint8List, Uint8List) generateSignatureKeyPair(
    String algorithm, {
    required int publicKeyBytes,
    required int secretKeyBytes,
  }) {
    final signature = _newSignature(algorithm);
    final publicKey = calloc<Uint8>(publicKeyBytes);
    final secretKey = calloc<Uint8>(secretKeyBytes);
    try {
      if (_sigKeyPair(signature, publicKey, secretKey) != 0) {
        throw StateError('liboqs signature keypair failed for $algorithm');
      }
      return (
        Uint8List.fromList(publicKey.asTypedList(publicKeyBytes)),
        Uint8List.fromList(secretKey.asTypedList(secretKeyBytes)),
      );
    } finally {
      secretKey.asTypedList(secretKeyBytes).fillRange(0, secretKeyBytes, 0);
      calloc.free(publicKey);
      calloc.free(secretKey);
      _sigFree(signature);
    }
  }

  Uint8List sign(
    String algorithm,
    Uint8List secretKey,
    Uint8List message,
    Uint8List context, {
    required int signatureBytes,
  }) {
    final signature = _newSignature(algorithm);
    final secretKeyPointer = _copy(secretKey);
    final messagePointer = _copy(message);
    final contextPointer = _copy(context);
    final output = calloc<Uint8>(signatureBytes);
    final outputLength = calloc<IntPtr>();
    try {
      if (_sigSign(
            signature,
            output,
            outputLength,
            messagePointer,
            message.length,
            contextPointer,
            context.length,
            secretKeyPointer,
          ) !=
          0) {
        throw StateError('liboqs signing failed for $algorithm');
      }
      if (outputLength.value != signatureBytes) {
        throw StateError(
          '$algorithm returned ${outputLength.value} signature bytes; '
          'expected $signatureBytes',
        );
      }
      return Uint8List.fromList(output.asTypedList(signatureBytes));
    } finally {
      secretKeyPointer
          .asTypedList(secretKey.length)
          .fillRange(0, secretKey.length, 0);
      calloc.free(secretKeyPointer);
      calloc.free(messagePointer);
      calloc.free(contextPointer);
      calloc.free(output);
      calloc.free(outputLength);
      _sigFree(signature);
    }
  }

  bool verify(
    String algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signatureBytes,
    Uint8List context,
  ) {
    final signature = _newSignature(algorithm);
    final publicKeyPointer = _copy(publicKey);
    final messagePointer = _copy(message);
    final signaturePointer = _copy(signatureBytes);
    final contextPointer = _copy(context);
    try {
      return _sigVerify(
            signature,
            messagePointer,
            message.length,
            signaturePointer,
            signatureBytes.length,
            contextPointer,
            context.length,
            publicKeyPointer,
          ) ==
          0;
    } finally {
      calloc.free(publicKeyPointer);
      calloc.free(messagePointer);
      calloc.free(signaturePointer);
      calloc.free(contextPointer);
      _sigFree(signature);
    }
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _destroy();
  }

  Pointer<OqsKem> _newKem(String algorithm) {
    return _withAlgorithmName(algorithm, _kemNewChecked);
  }

  Pointer<OqsKem> _kemNewChecked(Pointer<Utf8> name) {
    final kem = _kemNew(name);
    if (kem == nullptr) {
      throw StateError('OQS_KEM_new failed for ${name.toDartString()}');
    }
    return kem;
  }

  Pointer<OqsSig> _newSignature(String algorithm) {
    return _withAlgorithmName(algorithm, _sigNewChecked);
  }

  Pointer<OqsSig> _sigNewChecked(Pointer<Utf8> name) {
    final signature = _sigNew(name);
    if (signature == nullptr) {
      throw StateError('OQS_SIG_new failed for ${name.toDartString()}');
    }
    return signature;
  }

  T _withAlgorithmName<T>(
    String algorithm,
    T Function(Pointer<Utf8>) operation,
  ) {
    final name = algorithm.toNativeUtf8();
    try {
      return operation(name);
    } finally {
      calloc.free(name);
    }
  }

  bool _withAlgorithmNameBool(
    String algorithm,
    bool Function(Pointer<Utf8>) operation,
  ) {
    final name = algorithm.toNativeUtf8();
    try {
      return operation(name);
    } finally {
      calloc.free(name);
    }
  }

  Pointer<Uint8> _copy(Uint8List bytes) {
    final pointer = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
    if (bytes.isNotEmpty) {
      pointer.asTypedList(bytes.length).setAll(0, bytes);
    }
    return pointer;
  }
}

String? resolveLiboqsPath() {
  final override = Platform.environment['LIBOQS_PATH'];
  if (override != null && override.isNotEmpty) {
    return File(override).existsSync() ? override : null;
  }
  for (final candidate in liboqsProbePaths()) {
    if (File(candidate).existsSync()) return candidate;
  }
  return null;
}

List<String> liboqsProbePaths() => <String>[
  if (Platform.isLinux) ...[
    '/usr/local/lib64/liboqs.so',
    '/usr/local/lib/liboqs.so',
  ],
  if (Platform.isMacOS) ...[
    '/opt/homebrew/lib/liboqs.dylib',
    '/usr/local/lib/liboqs.dylib',
  ],
];

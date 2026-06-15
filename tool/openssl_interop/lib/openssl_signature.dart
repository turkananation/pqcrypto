import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// OpenSSL 3.5+ EVP adapter shared by ML-DSA and SLH-DSA interop tests.
///
/// Both standardized signature families expose the same raw key import/export,
/// seeded key generation, message-signing, context, deterministic, and
/// test-entropy controls through EVP.
final class EvpPkey extends Opaque {}

final class EvpPkeyCtx extends Opaque {}

final class EvpSignature extends Opaque {}

final class OsslParam extends Opaque {}

final class OsslParamBld extends Opaque {}

typedef _CtxNewFromNameNative =
    Pointer<EvpPkeyCtx> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef _CtxNewFromNameDart =
    Pointer<EvpPkeyCtx> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef _CtxNewFromPkeyNative =
    Pointer<EvpPkeyCtx> Function(
      Pointer<Void>,
      Pointer<EvpPkey>,
      Pointer<Void>,
    );
typedef _CtxNewFromPkeyDart =
    Pointer<EvpPkeyCtx> Function(
      Pointer<Void>,
      Pointer<EvpPkey>,
      Pointer<Void>,
    );
typedef _CtxFreeNative = Void Function(Pointer<EvpPkeyCtx>);
typedef _CtxFreeDart = void Function(Pointer<EvpPkeyCtx>);
typedef _PkeyFreeNative = Void Function(Pointer<EvpPkey>);
typedef _PkeyFreeDart = void Function(Pointer<EvpPkey>);
typedef _KeygenInitNative = Int32 Function(Pointer<EvpPkeyCtx>);
typedef _KeygenInitDart = int Function(Pointer<EvpPkeyCtx>);
typedef _CtxSetParamsNative =
    Int32 Function(Pointer<EvpPkeyCtx>, Pointer<OsslParam>);
typedef _CtxSetParamsDart =
    int Function(Pointer<EvpPkeyCtx>, Pointer<OsslParam>);
typedef _KeygenNative =
    Int32 Function(Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>);
typedef _KeygenDart =
    int Function(Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>);
typedef _FromdataInitNative = Int32 Function(Pointer<EvpPkeyCtx>);
typedef _FromdataInitDart = int Function(Pointer<EvpPkeyCtx>);
typedef _FromdataNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Pointer<EvpPkey>>,
      Int32,
      Pointer<OsslParam>,
    );
typedef _FromdataDart =
    int Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Pointer<EvpPkey>>,
      int,
      Pointer<OsslParam>,
    );
typedef _GetOctetParamNative =
    Int32 Function(
      Pointer<EvpPkey>,
      Pointer<Utf8>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<IntPtr>,
    );
typedef _GetOctetParamDart =
    int Function(
      Pointer<EvpPkey>,
      Pointer<Utf8>,
      Pointer<Uint8>,
      int,
      Pointer<IntPtr>,
    );
typedef _SignatureFetchNative =
    Pointer<EvpSignature> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef _SignatureFetchDart =
    Pointer<EvpSignature> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef _SignatureFreeNative = Void Function(Pointer<EvpSignature>);
typedef _SignatureFreeDart = void Function(Pointer<EvpSignature>);
typedef _MessageInitNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<EvpSignature>,
      Pointer<OsslParam>,
    );
typedef _MessageInitDart =
    int Function(
      Pointer<EvpPkeyCtx>,
      Pointer<EvpSignature>,
      Pointer<OsslParam>,
    );
typedef _SignNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      IntPtr,
    );
typedef _SignDart =
    int Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      int,
    );
typedef _VerifyNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
    );
typedef _VerifyDart =
    int Function(Pointer<EvpPkeyCtx>, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _BldNewNative = Pointer<OsslParamBld> Function();
typedef _BldNewDart = Pointer<OsslParamBld> Function();
typedef _BldFreeNative = Void Function(Pointer<OsslParamBld>);
typedef _BldFreeDart = void Function(Pointer<OsslParamBld>);
typedef _BldToParamNative = Pointer<OsslParam> Function(Pointer<OsslParamBld>);
typedef _BldToParamDart = Pointer<OsslParam> Function(Pointer<OsslParamBld>);
typedef _BldPushOctetNative =
    Int32 Function(
      Pointer<OsslParamBld>,
      Pointer<Utf8>,
      Pointer<Uint8>,
      IntPtr,
    );
typedef _BldPushOctetDart =
    int Function(Pointer<OsslParamBld>, Pointer<Utf8>, Pointer<Uint8>, int);
typedef _BldPushIntNative =
    Int32 Function(Pointer<OsslParamBld>, Pointer<Utf8>, Int32);
typedef _BldPushIntDart =
    int Function(Pointer<OsslParamBld>, Pointer<Utf8>, int);
typedef _ParamFreeNative = Void Function(Pointer<OsslParam>);
typedef _ParamFreeDart = void Function(Pointer<OsslParam>);
typedef _VersionNative = Pointer<Utf8> Function(Int32);
typedef _VersionDart = Pointer<Utf8> Function(int);

const int _evpPkeyPrivateKey = 0x85;
const int _evpPkeyPublicKey = 0x86;

final class OpenSslSignatureInterop {
  OpenSslSignatureInterop.load(String path) : _lib = DynamicLibrary.open(path) {
    _ctxNewFromName = _lib
        .lookupFunction<_CtxNewFromNameNative, _CtxNewFromNameDart>(
          'EVP_PKEY_CTX_new_from_name',
        );
    _ctxNewFromPkey = _lib
        .lookupFunction<_CtxNewFromPkeyNative, _CtxNewFromPkeyDart>(
          'EVP_PKEY_CTX_new_from_pkey',
        );
    _ctxFree = _lib.lookupFunction<_CtxFreeNative, _CtxFreeDart>(
      'EVP_PKEY_CTX_free',
    );
    _pkeyFree = _lib.lookupFunction<_PkeyFreeNative, _PkeyFreeDart>(
      'EVP_PKEY_free',
    );
    _keygenInit = _lib.lookupFunction<_KeygenInitNative, _KeygenInitDart>(
      'EVP_PKEY_keygen_init',
    );
    _ctxSetParams = _lib.lookupFunction<_CtxSetParamsNative, _CtxSetParamsDart>(
      'EVP_PKEY_CTX_set_params',
    );
    _keygen = _lib.lookupFunction<_KeygenNative, _KeygenDart>(
      'EVP_PKEY_keygen',
    );
    _fromdataInit = _lib.lookupFunction<_FromdataInitNative, _FromdataInitDart>(
      'EVP_PKEY_fromdata_init',
    );
    _fromdata = _lib.lookupFunction<_FromdataNative, _FromdataDart>(
      'EVP_PKEY_fromdata',
    );
    _getOctetParam = _lib
        .lookupFunction<_GetOctetParamNative, _GetOctetParamDart>(
          'EVP_PKEY_get_octet_string_param',
        );
    _signatureFetch = _lib
        .lookupFunction<_SignatureFetchNative, _SignatureFetchDart>(
          'EVP_SIGNATURE_fetch',
        );
    _signatureFree = _lib
        .lookupFunction<_SignatureFreeNative, _SignatureFreeDart>(
          'EVP_SIGNATURE_free',
        );
    _signInit = _lib.lookupFunction<_MessageInitNative, _MessageInitDart>(
      'EVP_PKEY_sign_message_init',
    );
    _verifyInit = _lib.lookupFunction<_MessageInitNative, _MessageInitDart>(
      'EVP_PKEY_verify_message_init',
    );
    _sign = _lib.lookupFunction<_SignNative, _SignDart>('EVP_PKEY_sign');
    _verify = _lib.lookupFunction<_VerifyNative, _VerifyDart>(
      'EVP_PKEY_verify',
    );
    _bldNew = _lib.lookupFunction<_BldNewNative, _BldNewDart>(
      'OSSL_PARAM_BLD_new',
    );
    _bldFree = _lib.lookupFunction<_BldFreeNative, _BldFreeDart>(
      'OSSL_PARAM_BLD_free',
    );
    _bldToParam = _lib.lookupFunction<_BldToParamNative, _BldToParamDart>(
      'OSSL_PARAM_BLD_to_param',
    );
    _bldPushOctet = _lib.lookupFunction<_BldPushOctetNative, _BldPushOctetDart>(
      'OSSL_PARAM_BLD_push_octet_string',
    );
    _bldPushInt = _lib.lookupFunction<_BldPushIntNative, _BldPushIntDart>(
      'OSSL_PARAM_BLD_push_int',
    );
    _paramFree = _lib.lookupFunction<_ParamFreeNative, _ParamFreeDart>(
      'OSSL_PARAM_free',
    );
    _version = _lib.lookupFunction<_VersionNative, _VersionDart>(
      'OpenSSL_version',
    );
  }

  final DynamicLibrary _lib;
  late final _CtxNewFromNameDart _ctxNewFromName;
  late final _CtxNewFromPkeyDart _ctxNewFromPkey;
  late final _CtxFreeDart _ctxFree;
  late final _PkeyFreeDart _pkeyFree;
  late final _KeygenInitDart _keygenInit;
  late final _CtxSetParamsDart _ctxSetParams;
  late final _KeygenDart _keygen;
  late final _FromdataInitDart _fromdataInit;
  late final _FromdataDart _fromdata;
  late final _GetOctetParamDart _getOctetParam;
  late final _SignatureFetchDart _signatureFetch;
  late final _SignatureFreeDart _signatureFree;
  late final _MessageInitDart _signInit;
  late final _MessageInitDart _verifyInit;
  late final _SignDart _sign;
  late final _VerifyDart _verify;
  late final _BldNewDart _bldNew;
  late final _BldFreeDart _bldFree;
  late final _BldToParamDart _bldToParam;
  late final _BldPushOctetDart _bldPushOctet;
  late final _BldPushIntDart _bldPushInt;
  late final _ParamFreeDart _paramFree;
  late final _VersionDart _version;

  String version() => _version(0).toDartString();

  (Uint8List, Uint8List) generateKeyPairFromSeed(
    String algorithm,
    Uint8List seed, {
    required int publicKeyBytes,
    required int secretKeyBytes,
  }) {
    final params = _ParamsBuilder(this)..addOctets('seed', seed);
    final algorithmName = algorithm.toNativeUtf8();
    final ctx = _ctxNewFromName(nullptr, algorithmName, nullptr);
    calloc.free(algorithmName);
    if (ctx == nullptr) {
      params.dispose();
      throw StateError('EvpPkeyCtx_new_from_name failed for $algorithm');
    }
    final pkeyPointer = calloc<Pointer<EvpPkey>>();
    Pointer<EvpPkey>? pkey;
    try {
      if (_keygenInit(ctx) != 1) {
        throw StateError('EvpPkey_keygen_init failed for $algorithm');
      }
      if (_ctxSetParams(ctx, params.pointer) != 1) {
        throw StateError('EvpPkeyCtx_set_params failed for $algorithm');
      }
      if (_keygen(ctx, pkeyPointer) != 1) {
        throw StateError('EvpPkey_keygen failed for $algorithm');
      }
      pkey = pkeyPointer.value;
      return (
        _getKeyBytes(pkey, 'pub', publicKeyBytes),
        _getKeyBytes(pkey, 'priv', secretKeyBytes),
      );
    } finally {
      if (pkey != null) _pkeyFree(pkey);
      calloc.free(pkeyPointer);
      _ctxFree(ctx);
      params.dispose();
    }
  }

  /// Signs an already encoded internal message.
  ///
  /// This is currently used for SLH-DSA's internal interface, where OpenSSL's
  /// `message-encoding=0` control suppresses the external domain encoding.
  Uint8List signRaw(
    String algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? additionalRandomness,
  }) {
    return _signMessage(
      algorithm,
      secretKey,
      message,
      context: null,
      additionalRandomness: additionalRandomness,
    );
  }

  /// Signs through the standardized external interface with [context].
  Uint8List signWithContext(
    String algorithm,
    Uint8List secretKey,
    Uint8List message,
    Uint8List context, {
    Uint8List? additionalRandomness,
  }) {
    return _signMessage(
      algorithm,
      secretKey,
      message,
      context: context,
      additionalRandomness: additionalRandomness,
    );
  }

  bool verifyRaw(
    String algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) {
    return _verifyMessage(
      algorithm,
      publicKey,
      message,
      signature,
      context: null,
    );
  }

  bool verifyWithContext(
    String algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
    Uint8List context,
  ) {
    return _verifyMessage(
      algorithm,
      publicKey,
      message,
      signature,
      context: context,
    );
  }

  Uint8List _signMessage(
    String algorithm,
    Uint8List secretKey,
    Uint8List message, {
    required Uint8List? context,
    required Uint8List? additionalRandomness,
  }) {
    final pkey = _importKey(algorithm, 'priv', secretKey, _evpPkeyPrivateKey);
    final signature = _fetchSignature(algorithm);
    final params = _ParamsBuilder(this)
      ..addInt('deterministic', additionalRandomness == null ? 1 : 0);
    if (additionalRandomness != null) {
      params.addOctets('test-entropy', additionalRandomness);
    }
    if (context == null) {
      params.addInt('message-encoding', 0);
    } else {
      params.addOctets('context-string', context);
    }
    final ctx = _ctxNewFromPkey(nullptr, pkey, nullptr);
    if (ctx == nullptr) {
      params.dispose();
      _signatureFree(signature);
      _pkeyFree(pkey);
      throw StateError('EvpPkeyCtx_new_from_pkey failed for $algorithm');
    }
    final messagePointer = _copy(message);
    final signatureLength = calloc<IntPtr>();
    Pointer<Uint8>? signaturePointer;
    try {
      if (_signInit(ctx, signature, params.pointer) != 1) {
        throw StateError('EvpPkey_sign_message_init failed for $algorithm');
      }
      if (_sign(
            ctx,
            nullptr,
            signatureLength,
            messagePointer,
            message.length,
          ) !=
          1) {
        throw StateError('EvpPkey_sign size query failed for $algorithm');
      }
      signaturePointer = calloc<Uint8>(signatureLength.value);
      if (_sign(
            ctx,
            signaturePointer,
            signatureLength,
            messagePointer,
            message.length,
          ) !=
          1) {
        throw StateError('EvpPkey_sign failed for $algorithm');
      }
      return Uint8List.fromList(
        signaturePointer.asTypedList(signatureLength.value),
      );
    } finally {
      calloc.free(messagePointer);
      calloc.free(signatureLength);
      if (signaturePointer != null) calloc.free(signaturePointer);
      _ctxFree(ctx);
      params.dispose();
      _signatureFree(signature);
      _pkeyFree(pkey);
    }
  }

  bool _verifyMessage(
    String algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signatureBytes, {
    required Uint8List? context,
  }) {
    final pkey = _importKey(algorithm, 'pub', publicKey, _evpPkeyPublicKey);
    final signature = _fetchSignature(algorithm);
    final params = _ParamsBuilder(this);
    if (context == null) {
      params.addInt('message-encoding', 0);
    } else {
      params.addOctets('context-string', context);
    }
    final ctx = _ctxNewFromPkey(nullptr, pkey, nullptr);
    if (ctx == nullptr) {
      params.dispose();
      _signatureFree(signature);
      _pkeyFree(pkey);
      throw StateError('EvpPkeyCtx_new_from_pkey failed for $algorithm');
    }
    final messagePointer = _copy(message);
    final signaturePointer = _copy(signatureBytes);
    try {
      if (_verifyInit(ctx, signature, params.pointer) != 1) {
        throw StateError('EvpPkey_verify_message_init failed for $algorithm');
      }
      return _verify(
            ctx,
            signaturePointer,
            signatureBytes.length,
            messagePointer,
            message.length,
          ) ==
          1;
    } finally {
      calloc.free(messagePointer);
      calloc.free(signaturePointer);
      _ctxFree(ctx);
      params.dispose();
      _signatureFree(signature);
      _pkeyFree(pkey);
    }
  }

  Pointer<EvpPkey> _importKey(
    String algorithm,
    String parameter,
    Uint8List bytes,
    int selection,
  ) {
    final params = _ParamsBuilder(this)..addOctets(parameter, bytes);
    final algorithmName = algorithm.toNativeUtf8();
    final ctx = _ctxNewFromName(nullptr, algorithmName, nullptr);
    calloc.free(algorithmName);
    if (ctx == nullptr) {
      params.dispose();
      throw StateError('EvpPkeyCtx_new_from_name failed for $algorithm');
    }
    final pkeyPointer = calloc<Pointer<EvpPkey>>();
    try {
      if (_fromdataInit(ctx) != 1) {
        throw StateError('EvpPkey_fromdata_init failed for $algorithm');
      }
      if (_fromdata(ctx, pkeyPointer, selection, params.pointer) != 1) {
        throw StateError('EvpPkey_fromdata failed for $algorithm');
      }
      return pkeyPointer.value;
    } finally {
      calloc.free(pkeyPointer);
      _ctxFree(ctx);
      params.dispose();
    }
  }

  Pointer<EvpSignature> _fetchSignature(String algorithm) {
    final algorithmName = algorithm.toNativeUtf8();
    try {
      final signature = _signatureFetch(nullptr, algorithmName, nullptr);
      if (signature == nullptr) {
        throw StateError('EvpSignature_fetch failed for $algorithm');
      }
      return signature;
    } finally {
      calloc.free(algorithmName);
    }
  }

  Uint8List _getKeyBytes(
    Pointer<EvpPkey> pkey,
    String parameter,
    int expectedLength,
  ) {
    final parameterName = parameter.toNativeUtf8();
    final output = calloc<Uint8>(expectedLength);
    final outputLength = calloc<IntPtr>();
    try {
      if (_getOctetParam(
            pkey,
            parameterName,
            output,
            expectedLength,
            outputLength,
          ) !=
          1) {
        throw StateError('EvpPkey_get_octet_string_param failed: $parameter');
      }
      if (outputLength.value != expectedLength) {
        throw StateError(
          '$parameter length ${outputLength.value}; expected $expectedLength',
        );
      }
      return Uint8List.fromList(output.asTypedList(expectedLength));
    } finally {
      calloc.free(parameterName);
      calloc.free(output);
      calloc.free(outputLength);
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

final class _ParamsBuilder {
  _ParamsBuilder(this._openssl) : _builder = _openssl._bldNew() {
    if (_builder == nullptr) {
      throw StateError('OsslParamBld_new failed');
    }
  }

  final OpenSslSignatureInterop _openssl;
  final Pointer<OsslParamBld> _builder;
  final List<Pointer<NativeType>> _allocations = <Pointer<NativeType>>[];
  Pointer<OsslParam>? _params;

  Pointer<OsslParam> get pointer {
    _params ??= _openssl._bldToParam(_builder);
    if (_params == nullptr) {
      throw StateError('OsslParamBld_to_param failed');
    }
    return _params!;
  }

  void addOctets(String name, Uint8List value) {
    _ensureMutable();
    final namePointer = name.toNativeUtf8();
    final valuePointer = calloc<Uint8>(value.isEmpty ? 1 : value.length);
    if (value.isNotEmpty) {
      valuePointer.asTypedList(value.length).setAll(0, value);
    }
    _allocations
      ..add(namePointer)
      ..add(valuePointer);
    if (_openssl._bldPushOctet(
          _builder,
          namePointer,
          valuePointer,
          value.length,
        ) !=
        1) {
      throw StateError('OsslParamBld_push_octet_string failed: $name');
    }
  }

  void addInt(String name, int value) {
    _ensureMutable();
    final namePointer = name.toNativeUtf8();
    _allocations.add(namePointer);
    if (_openssl._bldPushInt(_builder, namePointer, value) != 1) {
      throw StateError('OsslParamBld_push_int failed: $name');
    }
  }

  void dispose() {
    if (_params != null) _openssl._paramFree(_params!);
    _openssl._bldFree(_builder);
    for (final pointer in _allocations) {
      calloc.free(pointer);
    }
  }

  void _ensureMutable() {
    if (_params != null) {
      throw StateError('Cannot add parameters after materialization');
    }
  }
}

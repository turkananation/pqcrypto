/// OpenSSL ML-KEM bindings (via `dart:ffi` → `libcrypto`) plus the shared
/// scaffolding used by both the runnable harness
/// ([bin/openssl_pqcrypto_interop.dart]) and the rigorous test suite
/// ([test/mlkem_interop_test.dart]).
///
/// IMPORTANT — purity boundary: this file lives in the **separate**
/// `openssl_pqcrypto_interop` dev-tool package (`publish_to: none`), NOT in the
/// published `pqcrypto` package. `pqcrypto`'s own `lib/` contains no `dart:ffi`
/// and stays pure Dart / Flutter / Web compatible. The FFI here only exists to
/// cross-check `pqcrypto` against an independent FIPS 203 implementation.
///
/// The EVP API is algorithm-agnostic: every binding below is generic and the
/// only thing that differs between ML-KEM-512/768/1024 is the algorithm *name*
/// string passed to `EvpPkeyCtx_new_from_name`. So a single loaded
/// [OpenSslMlKem] instance serves all three parameter sets — the level is just
/// a method argument.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';

// ── OpenSSL EVP opaque types ──────────────────────────────────────────────────
final class EvpPkey extends Opaque {}

final class EvpPkeyCtx extends Opaque {}

final class OsslParam extends Opaque {}

final class OsslParamBld extends Opaque {}

// ── FFI typedefs ─────────────────────────────────────────────────────────────

// EvpPkeyCtx_new_from_name(NULL, "ML-KEM-768", NULL)
typedef EvpPkeyCtxNewFromNameNative =
    Pointer<EvpPkeyCtx> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef EvpPkeyCtxNewFromNameDart =
    Pointer<EvpPkeyCtx> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);

// EvpPkeyCtx_new(EvpPkey*, ENGINE*)  — for encaps/decaps ctx from a key
typedef EvpPkeyCtxNewNative =
    Pointer<EvpPkeyCtx> Function(Pointer<EvpPkey>, Pointer<Void>);
typedef EvpPkeyCtxNewDart =
    Pointer<EvpPkeyCtx> Function(Pointer<EvpPkey>, Pointer<Void>);

typedef EvpPkeyCtxFreeNative = Void Function(Pointer<EvpPkeyCtx>);
typedef EvpPkeyCtxFreeDart = void Function(Pointer<EvpPkeyCtx>);

typedef EvpPkeyFreeNative = Void Function(Pointer<EvpPkey>);
typedef EvpPkeyFreeDart = void Function(Pointer<EvpPkey>);

// EvpPkey_keygen_init(ctx)
typedef EvpPkeyKeygenInitNative = Int32 Function(Pointer<EvpPkeyCtx>);
typedef EvpPkeyKeygenInitDart = int Function(Pointer<EvpPkeyCtx>);

// EvpPkey_encapsulate_init(ctx, params[]) / EvpPkey_decapsulate_init(ctx, params[])
typedef EvpPkeyKemInitNative =
    Int32 Function(Pointer<EvpPkeyCtx>, Pointer<Void>);
typedef EvpPkeyKemInitDart = int Function(Pointer<EvpPkeyCtx>, Pointer<Void>);

// EvpPkey_fromdata_init(ctx)
typedef EvpPkeyFromdataInitNative = Int32 Function(Pointer<EvpPkeyCtx>);
typedef EvpPkeyFromdataInitDart = int Function(Pointer<EvpPkeyCtx>);

// EvpPkey_keygen(ctx, EvpPkey**)
typedef EvpPkeyKeygenNative =
    Int32 Function(Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>);
typedef EvpPkeyKeygenDart =
    int Function(Pointer<EvpPkeyCtx>, Pointer<Pointer<EvpPkey>>);

// EvpPkey_get1_encoded_public_key(pkey, unsigned char**) -> size_t
typedef EvpPkeyGet1EncodedPublicKeyNative =
    IntPtr Function(Pointer<EvpPkey>, Pointer<Pointer<Uint8>>);
typedef EvpPkeyGet1EncodedPublicKeyDart =
    int Function(Pointer<EvpPkey>, Pointer<Pointer<Uint8>>);

// EvpPkey_encapsulate(ctx, wrappedkey*, wrappedkeylen*, genkey*, genkeylen*)
typedef EvpPkeyEncapsulateNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
    );
typedef EvpPkeyEncapsulateDart =
    int Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
    );

// EvpPkey_decapsulate(ctx, unwrapped*, unwrappedlen*, wrapped*, wrappedlen)
typedef EvpPkeyDecapsulateNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      IntPtr,
    );
typedef EvpPkeyDecapsulateDart =
    int Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      int,
    );

// OsslParamBld_new / free / to_param
typedef OsslParamBldNewNative = Pointer<OsslParamBld> Function();
typedef OsslParamBldNewDart = Pointer<OsslParamBld> Function();

typedef OsslParamBldFreeNative = Void Function(Pointer<OsslParamBld>);
typedef OsslParamBldFreeDart = void Function(Pointer<OsslParamBld>);

typedef OsslParamBldToParamNative =
    Pointer<OsslParam> Function(Pointer<OsslParamBld>);
typedef OsslParamBldToParamDart =
    Pointer<OsslParam> Function(Pointer<OsslParamBld>);

typedef OsslParamBldPushOctetStringNative =
    Int32 Function(
      Pointer<OsslParamBld>,
      Pointer<Utf8>,
      Pointer<Uint8>,
      IntPtr,
    );
typedef OsslParamBldPushOctetStringDart =
    int Function(Pointer<OsslParamBld>, Pointer<Utf8>, Pointer<Uint8>, int);

typedef OsslParamFreeNative = Void Function(Pointer<OsslParam>);
typedef OsslParamFreeDart = void Function(Pointer<OsslParam>);

// EvpPkey_fromdata(ctx, EvpPkey**, selection, OsslParam[])
typedef EvpPkeyFromdataNative =
    Int32 Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Pointer<EvpPkey>>,
      Int32,
      Pointer<OsslParam>,
    );
typedef EvpPkeyFromdataDart =
    int Function(
      Pointer<EvpPkeyCtx>,
      Pointer<Pointer<EvpPkey>>,
      int,
      Pointer<OsslParam>,
    );

// CRYPTO_free
typedef CryptoFreeNative = Void Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef CryptoFreeDart = void Function(Pointer<Void>, Pointer<Utf8>, int);

// const char *OpenSSL_version(int type);  type 0 = OPENSSL_VERSION (full string)
typedef OpenSslVersionNative = Pointer<Utf8> Function(Int32);
typedef OpenSslVersionDart = Pointer<Utf8> Function(int);

// ── OpenSSL selection constants ───────────────────────────────────────────────
// OSSL_KEYMGMT_SELECT_ALL_PARAMETERS = 0x04 | 0x80 = 0x84
// EvpPkey_PUBLIC_KEY = ALL_PARAMETERS | PUBLIC_KEY(0x02)              = 0x86
// EvpPkey_KEYPAIR    = ALL_PARAMETERS | PUBLIC_KEY | PRIVATE_KEY(0x01) = 0x87
const int _evpPkeyPublicKey = 0x86;
const int _evpPkeyKeypair = 0x87;

/// Every ML-KEM shared secret (the KEM output `K`) is 32 bytes, regardless of
/// parameter set (FIPS 203).
// ── OpenSSL FFI wrapper ───────────────────────────────────────────────────────

/// Thin FFI wrapper over OpenSSL's EVP ML-KEM API. One instance is bound to a
/// loaded `libcrypto`; the ML-KEM parameter set is selected per call via the
/// `algName` argument (e.g. `"ML-KEM-512"`).
class OpenSslMlKem {
  final DynamicLibrary _lib;

  late final EvpPkeyCtxNewFromNameDart _ctxNewFromName;
  late final EvpPkeyCtxNewDart _ctxNew;
  late final EvpPkeyCtxFreeDart _ctxFree;
  late final EvpPkeyFreeDart _pkeyFree;
  late final EvpPkeyKeygenInitDart _keygenInit;
  late final EvpPkeyKeygenDart _keygen;
  late final EvpPkeyGet1EncodedPublicKeyDart _get1EncodedPubKey;
  late final EvpPkeyKemInitDart _encapsInit;
  late final EvpPkeyEncapsulateDart _encapsulate;
  late final EvpPkeyKemInitDart _decapsInit;
  late final EvpPkeyDecapsulateDart _decapsulate;
  late final OsslParamBldNewDart _bldNew;
  late final OsslParamBldFreeDart _bldFree;
  late final OsslParamBldToParamDart _bldToParam;
  late final OsslParamBldPushOctetStringDart _bldPushOctet;
  late final OsslParamFreeDart _paramFree;
  late final EvpPkeyFromdataInitDart _fromdataInit;
  late final EvpPkeyFromdataDart _fromdata;
  late final CryptoFreeDart _cryptoFree;
  late final OpenSslVersionDart _opensslVersion;

  OpenSslMlKem.load(String path) : _lib = DynamicLibrary.open(path) {
    _ctxNewFromName = _lib
        .lookupFunction<EvpPkeyCtxNewFromNameNative, EvpPkeyCtxNewFromNameDart>(
          'EVP_PKEY_CTX_new_from_name',
        );
    _ctxNew = _lib.lookupFunction<EvpPkeyCtxNewNative, EvpPkeyCtxNewDart>(
      'EVP_PKEY_CTX_new',
    );
    _ctxFree = _lib.lookupFunction<EvpPkeyCtxFreeNative, EvpPkeyCtxFreeDart>(
      'EVP_PKEY_CTX_free',
    );
    _pkeyFree = _lib.lookupFunction<EvpPkeyFreeNative, EvpPkeyFreeDart>(
      'EVP_PKEY_free',
    );
    _keygenInit = _lib
        .lookupFunction<EvpPkeyKeygenInitNative, EvpPkeyKeygenInitDart>(
          'EVP_PKEY_keygen_init',
        );
    _keygen = _lib.lookupFunction<EvpPkeyKeygenNative, EvpPkeyKeygenDart>(
      'EVP_PKEY_keygen',
    );
    _get1EncodedPubKey = _lib
        .lookupFunction<
          EvpPkeyGet1EncodedPublicKeyNative,
          EvpPkeyGet1EncodedPublicKeyDart
        >('EVP_PKEY_get1_encoded_public_key');
    _encapsInit = _lib.lookupFunction<EvpPkeyKemInitNative, EvpPkeyKemInitDart>(
      'EVP_PKEY_encapsulate_init',
    );
    _encapsulate = _lib
        .lookupFunction<EvpPkeyEncapsulateNative, EvpPkeyEncapsulateDart>(
          'EVP_PKEY_encapsulate',
        );
    _decapsInit = _lib.lookupFunction<EvpPkeyKemInitNative, EvpPkeyKemInitDart>(
      'EVP_PKEY_decapsulate_init',
    );
    _decapsulate = _lib
        .lookupFunction<EvpPkeyDecapsulateNative, EvpPkeyDecapsulateDart>(
          'EVP_PKEY_decapsulate',
        );
    _bldNew = _lib.lookupFunction<OsslParamBldNewNative, OsslParamBldNewDart>(
      'OSSL_PARAM_BLD_new',
    );
    _bldFree = _lib
        .lookupFunction<OsslParamBldFreeNative, OsslParamBldFreeDart>(
          'OSSL_PARAM_BLD_free',
        );
    _bldToParam = _lib
        .lookupFunction<OsslParamBldToParamNative, OsslParamBldToParamDart>(
          'OSSL_PARAM_BLD_to_param',
        );
    _bldPushOctet = _lib
        .lookupFunction<
          OsslParamBldPushOctetStringNative,
          OsslParamBldPushOctetStringDart
        >('OSSL_PARAM_BLD_push_octet_string');
    _paramFree = _lib.lookupFunction<OsslParamFreeNative, OsslParamFreeDart>(
      'OSSL_PARAM_free',
    );
    _fromdataInit = _lib
        .lookupFunction<EvpPkeyFromdataInitNative, EvpPkeyFromdataInitDart>(
          'EVP_PKEY_fromdata_init',
        );
    _fromdata = _lib.lookupFunction<EvpPkeyFromdataNative, EvpPkeyFromdataDart>(
      'EVP_PKEY_fromdata',
    );
    _cryptoFree = _lib.lookupFunction<CryptoFreeNative, CryptoFreeDart>(
      'CRYPTO_free',
    );
    _opensslVersion = _lib
        .lookupFunction<OpenSslVersionNative, OpenSslVersionDart>(
          'OpenSSL_version',
        );
  }

  /// Generate an ML-KEM keypair for [algName] (e.g. `"ML-KEM-768"`). Returns
  /// `(publicKeyBytes, EvpPkey*)`. Caller must free the key with [freeKey].
  (Uint8List, Pointer<EvpPkey>) generateKeypair(String algName) {
    final algNamePtr = algName.toNativeUtf8();
    final ctx = _ctxNewFromName(nullptr, algNamePtr, nullptr);
    calloc.free(algNamePtr);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_name failed');

    try {
      if (_keygenInit(ctx) <= 0) {
        throw StateError('EVP_PKEY_keygen_init failed');
      }
      final pkeyPtr = calloc<Pointer<EvpPkey>>();
      try {
        if (_keygen(ctx, pkeyPtr) <= 0) {
          throw StateError('EVP_PKEY_keygen failed');
        }
        final pkey = pkeyPtr.value;
        return (exportPublicKey(pkey), pkey);
      } finally {
        calloc.free(pkeyPtr);
      }
    } finally {
      _ctxFree(ctx);
    }
  }

  /// Deterministically derive a full ML-KEM keypair for [algName] from a
  /// 64-byte FIPS 203 seed `(d ‖ z)`, via `EvpPkey_fromdata` with the `"seed"`
  /// `OsslParam` (`OSSL_PKEY_PARAM_ML_KEM_SEED`) and `EvpPkey_KEYPAIR`
  /// selection. The returned key can both encapsulate and decapsulate. Caller
  /// must free with [freeKey].
  ///
  /// This is the key to the strongest interop checks: feeding the *same* seed
  /// to OpenSSL and to `pqcrypto` must yield byte-identical public keys, and a
  /// shared `z` makes the FIPS 203 implicit-rejection secret comparable across
  /// implementations.
  Pointer<EvpPkey> keypairFromSeed(String algName, Uint8List seed) {
    if (seed.length != mlKemKeyPairSeedBytes) {
      throw ArgumentError(
        'ML-KEM seed must be $mlKemKeyPairSeedBytes bytes (d||z)',
      );
    }
    return _fromData(algName, 'seed', seed, _evpPkeyKeypair);
  }

  /// Import a raw public key for [algName] and return an `EvpPkey*` (public
  /// only). Caller must free with [freeKey].
  Pointer<EvpPkey> importPublicKey(String algName, Uint8List pubKeyBytes) {
    return _fromData(algName, 'pub', pubKeyBytes, _evpPkeyPublicKey);
  }

  /// Shared `EvpPkey_fromdata` path: build a single-entry `OsslParam`
  /// (octet string [paramName] → [data]) and import it under [selection].
  ///
  /// All native buffers must outlive the `EvpPkey_fromdata` call —
  /// `OsslParamBld` stores pointers, not copies.
  Pointer<EvpPkey> _fromData(
    String algName,
    String paramName,
    Uint8List data,
    int selection,
  ) {
    final algNamePtr = algName.toNativeUtf8();
    final paramNamePtr = paramName.toNativeUtf8();
    final dataBuf = calloc<Uint8>(data.length);
    dataBuf.asTypedList(data.length).setAll(0, data);

    Pointer<OsslParam>? params;
    Pointer<EvpPkeyCtx>? ctx;
    final pkeyPtr = calloc<Pointer<EvpPkey>>();

    try {
      final bld = _bldNew();
      if (bld == nullptr) throw StateError('OSSL_PARAM_BLD_new failed');
      if (_bldPushOctet(bld, paramNamePtr, dataBuf, data.length) <= 0) {
        _bldFree(bld);
        throw StateError('OSSL_PARAM_BLD_push_octet_string failed');
      }
      params = _bldToParam(bld);
      _bldFree(bld);
      if (params == nullptr) throw StateError('OSSL_PARAM_BLD_to_param failed');

      ctx = _ctxNewFromName(nullptr, algNamePtr, nullptr);
      if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_name failed');

      if (_fromdataInit(ctx) <= 0) {
        throw StateError('EVP_PKEY_fromdata_init failed');
      }
      if (_fromdata(ctx, pkeyPtr, selection, params) <= 0) {
        throw StateError('EVP_PKEY_fromdata failed');
      }
      return pkeyPtr.value;
    } finally {
      if (ctx != null) _ctxFree(ctx);
      if (params != null) _paramFree(params);
      // Free input buffers only after fromdata has completed.
      calloc.free(dataBuf);
      calloc.free(paramNamePtr);
      calloc.free(algNamePtr);
      calloc.free(pkeyPtr);
    }
  }

  /// Extract the raw encoded public key bytes from an `EvpPkey`.
  Uint8List exportPublicKey(Pointer<EvpPkey> pkey) {
    final ppub = calloc<Pointer<Uint8>>();
    try {
      final len = _get1EncodedPubKey(pkey, ppub);
      if (len <= 0) throw StateError('EVP_PKEY_get1_encoded_public_key failed');
      final bytes = Uint8List.fromList(ppub.value.asTypedList(len));
      _cryptoFree(ppub.value.cast(), nullptr, 0);
      return bytes;
    } finally {
      calloc.free(ppub);
    }
  }

  /// Encapsulate against a public `EvpPkey*`. Returns `(ciphertext, sharedSecret)`.
  (Uint8List, Uint8List) encapsulate(Pointer<EvpPkey> pubKey) {
    final ctx = _ctxNew(pubKey, nullptr);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new failed');
    try {
      if (_encapsInit(ctx, nullptr) <= 0) {
        throw StateError('EVP_PKEY_encapsulate_init failed');
      }

      // Query sizes.
      final ctLen = calloc<IntPtr>();
      final ssLen = calloc<IntPtr>();
      try {
        if (_encapsulate(ctx, nullptr, ctLen, nullptr, ssLen) <= 0) {
          throw StateError('EVP_PKEY_encapsulate (size query) failed');
        }

        final ctBuf = calloc<Uint8>(ctLen.value);
        final ssBuf = calloc<Uint8>(ssLen.value);
        try {
          if (_encapsulate(ctx, ctBuf, ctLen, ssBuf, ssLen) <= 0) {
            throw StateError('EVP_PKEY_encapsulate failed');
          }
          return (
            Uint8List.fromList(ctBuf.asTypedList(ctLen.value)),
            Uint8List.fromList(ssBuf.asTypedList(ssLen.value)),
          );
        } finally {
          calloc.free(ctBuf);
          calloc.free(ssBuf);
        }
      } finally {
        calloc.free(ctLen);
        calloc.free(ssLen);
      }
    } finally {
      _ctxFree(ctx);
    }
  }

  /// Decapsulate [ciphertext] using a full keypair `EvpPkey*`. Returns the
  /// shared secret. Per FIPS 203 this never fails for a correctly-sized
  /// ciphertext: an invalid ciphertext yields the implicit-rejection secret
  /// `J(z ‖ c)` rather than an error.
  Uint8List decapsulate(Pointer<EvpPkey> secretKey, Uint8List ciphertext) {
    final ctx = _ctxNew(secretKey, nullptr);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new failed');
    try {
      if (_decapsInit(ctx, nullptr) <= 0) {
        throw StateError('EVP_PKEY_decapsulate_init failed');
      }

      final ssLen = calloc<IntPtr>();
      final ctBuf = calloc<Uint8>(ciphertext.length);
      ctBuf.asTypedList(ciphertext.length).setAll(0, ciphertext);
      try {
        // Query shared secret size.
        if (_decapsulate(ctx, nullptr, ssLen, ctBuf, ciphertext.length) <= 0) {
          throw StateError('EVP_PKEY_decapsulate (size query) failed');
        }
        final ssBuf = calloc<Uint8>(ssLen.value);
        try {
          if (_decapsulate(ctx, ssBuf, ssLen, ctBuf, ciphertext.length) <= 0) {
            throw StateError('EVP_PKEY_decapsulate failed');
          }
          return Uint8List.fromList(ssBuf.asTypedList(ssLen.value));
        } finally {
          calloc.free(ssBuf);
        }
      } finally {
        calloc.free(ssLen);
        calloc.free(ctBuf);
      }
    } finally {
      _ctxFree(ctx);
    }
  }

  void freeKey(Pointer<EvpPkey> pkey) => _pkeyFree(pkey);

  /// Full OpenSSL version string, e.g. `"OpenSSL 4.0.0 14 Apr 2026"`.
  String version() => _opensslVersion(0).toDartString();

  bool? _seedSupport;

  /// Whether this `libcrypto` supports deterministic ML-KEM keygen from a seed
  /// (`EvpPkey_fromdata` with the `"seed"` param). Probed once and cached.
  ///
  /// OpenSSL exposes this from 3.5; some builds may differ, so the seed-based
  /// conformance checks are gated on this rather than assumed.
  bool get supportsSeedKeygen {
    final cached = _seedSupport;
    if (cached != null) return cached;
    var ok = false;
    try {
      // A fixed, obviously-not-secret probe seed. ML-KEM-768 is always present
      // wherever ML-KEM is, so it is a safe probe target.
      final probe = Uint8List(mlKemKeyPairSeedBytes);
      for (var i = 0; i < probe.length; i++) {
        probe[i] = i & 0xFF;
      }
      final key = keypairFromSeed('ML-KEM-768', probe);
      ok = key != nullptr;
      if (ok) freeKey(key);
    } catch (_) {
      ok = false;
    }
    return _seedSupport = ok;
  }
}

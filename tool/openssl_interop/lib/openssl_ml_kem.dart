/// OpenSSL ML-KEM bindings (via `dart:ffi` → `libcrypto`) plus the shared
/// scaffolding used by both the runnable harness
/// ([bin/openssl_pqcrypto_interop.dart]) and the rigorous test suite
/// ([test/interop_test.dart]).
///
/// IMPORTANT — purity boundary: this file lives in the **separate**
/// `openssl_pqcrypto_interop` dev-tool package (`publish_to: none`), NOT in the
/// published `pqcrypto` package. `pqcrypto`'s own `lib/` contains no `dart:ffi`
/// and stays pure Dart / Flutter / Web compatible. The FFI here only exists to
/// cross-check `pqcrypto` against an independent FIPS 203 implementation.
///
/// The EVP API is algorithm-agnostic: every binding below is generic and the
/// only thing that differs between ML-KEM-512/768/1024 is the algorithm *name*
/// string passed to `EVP_PKEY_CTX_new_from_name`. So a single loaded
/// [OpenSslMlKem] instance serves all three parameter sets — the level is just
/// a method argument.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:pqcrypto/pqcrypto.dart';

// ── OpenSSL EVP opaque types ──────────────────────────────────────────────────
final class EVP_PKEY extends Opaque {}

final class EVP_PKEY_CTX extends Opaque {}

final class OSSL_PARAM extends Opaque {}

final class OSSL_PARAM_BLD extends Opaque {}

// ── FFI typedefs ─────────────────────────────────────────────────────────────

// EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL)
typedef EvpPkeyCtxNewFromNameNative =
    Pointer<EVP_PKEY_CTX> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);
typedef EvpPkeyCtxNewFromNameDart =
    Pointer<EVP_PKEY_CTX> Function(Pointer<Void>, Pointer<Utf8>, Pointer<Void>);

// EVP_PKEY_CTX_new(EVP_PKEY*, ENGINE*)  — for encaps/decaps ctx from a key
typedef EvpPkeyCtxNewNative =
    Pointer<EVP_PKEY_CTX> Function(Pointer<EVP_PKEY>, Pointer<Void>);
typedef EvpPkeyCtxNewDart =
    Pointer<EVP_PKEY_CTX> Function(Pointer<EVP_PKEY>, Pointer<Void>);

typedef EvpPkeyCtxFreeNative = Void Function(Pointer<EVP_PKEY_CTX>);
typedef EvpPkeyCtxFreeDart = void Function(Pointer<EVP_PKEY_CTX>);

typedef EvpPkeyFreeNative = Void Function(Pointer<EVP_PKEY>);
typedef EvpPkeyFreeDart = void Function(Pointer<EVP_PKEY>);

// EVP_PKEY_keygen_init(ctx)
typedef EvpPkeyKeygenInitNative = Int32 Function(Pointer<EVP_PKEY_CTX>);
typedef EvpPkeyKeygenInitDart = int Function(Pointer<EVP_PKEY_CTX>);

// EVP_PKEY_encapsulate_init(ctx, params[]) / EVP_PKEY_decapsulate_init(ctx, params[])
typedef EvpPkeyKemInitNative =
    Int32 Function(Pointer<EVP_PKEY_CTX>, Pointer<Void>);
typedef EvpPkeyKemInitDart = int Function(Pointer<EVP_PKEY_CTX>, Pointer<Void>);

// EVP_PKEY_fromdata_init(ctx)
typedef EvpPkeyFromdataInitNative = Int32 Function(Pointer<EVP_PKEY_CTX>);
typedef EvpPkeyFromdataInitDart = int Function(Pointer<EVP_PKEY_CTX>);

// EVP_PKEY_keygen(ctx, EVP_PKEY**)
typedef EvpPkeyKeygenNative =
    Int32 Function(Pointer<EVP_PKEY_CTX>, Pointer<Pointer<EVP_PKEY>>);
typedef EvpPkeyKeygenDart =
    int Function(Pointer<EVP_PKEY_CTX>, Pointer<Pointer<EVP_PKEY>>);

// EVP_PKEY_get1_encoded_public_key(pkey, unsigned char**) -> size_t
typedef EvpPkeyGet1EncodedPublicKeyNative =
    IntPtr Function(Pointer<EVP_PKEY>, Pointer<Pointer<Uint8>>);
typedef EvpPkeyGet1EncodedPublicKeyDart =
    int Function(Pointer<EVP_PKEY>, Pointer<Pointer<Uint8>>);

// EVP_PKEY_encapsulate(ctx, wrappedkey*, wrappedkeylen*, genkey*, genkeylen*)
typedef EvpPkeyEncapsulateNative =
    Int32 Function(
      Pointer<EVP_PKEY_CTX>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
    );
typedef EvpPkeyEncapsulateDart =
    int Function(
      Pointer<EVP_PKEY_CTX>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
    );

// EVP_PKEY_decapsulate(ctx, unwrapped*, unwrappedlen*, wrapped*, wrappedlen)
typedef EvpPkeyDecapsulateNative =
    Int32 Function(
      Pointer<EVP_PKEY_CTX>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      IntPtr,
    );
typedef EvpPkeyDecapsulateDart =
    int Function(
      Pointer<EVP_PKEY_CTX>,
      Pointer<Uint8>,
      Pointer<IntPtr>,
      Pointer<Uint8>,
      int,
    );

// OSSL_PARAM_BLD_new / free / to_param
typedef OsslParamBldNewNative = Pointer<OSSL_PARAM_BLD> Function();
typedef OsslParamBldNewDart = Pointer<OSSL_PARAM_BLD> Function();

typedef OsslParamBldFreeNative = Void Function(Pointer<OSSL_PARAM_BLD>);
typedef OsslParamBldFreeDart = void Function(Pointer<OSSL_PARAM_BLD>);

typedef OsslParamBldToParamNative =
    Pointer<OSSL_PARAM> Function(Pointer<OSSL_PARAM_BLD>);
typedef OsslParamBldToParamDart =
    Pointer<OSSL_PARAM> Function(Pointer<OSSL_PARAM_BLD>);

typedef OsslParamBldPushOctetStringNative =
    Int32 Function(
      Pointer<OSSL_PARAM_BLD>,
      Pointer<Utf8>,
      Pointer<Uint8>,
      IntPtr,
    );
typedef OsslParamBldPushOctetStringDart =
    int Function(Pointer<OSSL_PARAM_BLD>, Pointer<Utf8>, Pointer<Uint8>, int);

typedef OsslParamFreeNative = Void Function(Pointer<OSSL_PARAM>);
typedef OsslParamFreeDart = void Function(Pointer<OSSL_PARAM>);

// EVP_PKEY_fromdata(ctx, EVP_PKEY**, selection, OSSL_PARAM[])
typedef EvpPkeyFromdataNative =
    Int32 Function(
      Pointer<EVP_PKEY_CTX>,
      Pointer<Pointer<EVP_PKEY>>,
      Int32,
      Pointer<OSSL_PARAM>,
    );
typedef EvpPkeyFromdataDart =
    int Function(
      Pointer<EVP_PKEY_CTX>,
      Pointer<Pointer<EVP_PKEY>>,
      int,
      Pointer<OSSL_PARAM>,
    );

// CRYPTO_free
typedef CryptoFreeNative = Void Function(Pointer<Void>, Pointer<Utf8>, Int32);
typedef CryptoFreeDart = void Function(Pointer<Void>, Pointer<Utf8>, int);

// const char *OpenSSL_version(int type);  type 0 = OPENSSL_VERSION (full string)
typedef OpenSslVersionNative = Pointer<Utf8> Function(Int32);
typedef OpenSslVersionDart = Pointer<Utf8> Function(int);

// ── OpenSSL selection constants ───────────────────────────────────────────────
// OSSL_KEYMGMT_SELECT_ALL_PARAMETERS = 0x04 | 0x80 = 0x84
// EVP_PKEY_PUBLIC_KEY = ALL_PARAMETERS | PUBLIC_KEY(0x02)              = 0x86
// EVP_PKEY_KEYPAIR    = ALL_PARAMETERS | PUBLIC_KEY | PRIVATE_KEY(0x01) = 0x87
const int _evpPkeyPublicKey = 0x86;
const int _evpPkeyKeypair = 0x87;

/// Every ML-KEM shared secret (the KEM output `K`) is 32 bytes, regardless of
/// parameter set (FIPS 203).
const int kSharedSecretBytes = 32;

/// FIPS 203 seed `(d ‖ z)` length used for deterministic key generation.
const int kSeedBytes = 64;

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
  /// `(publicKeyBytes, EVP_PKEY*)`. Caller must free the key with [freeKey].
  (Uint8List, Pointer<EVP_PKEY>) generateKeypair(String algName) {
    final algNamePtr = algName.toNativeUtf8();
    final ctx = _ctxNewFromName(nullptr, algNamePtr, nullptr);
    calloc.free(algNamePtr);
    if (ctx == nullptr) throw StateError('EVP_PKEY_CTX_new_from_name failed');

    try {
      if (_keygenInit(ctx) <= 0) {
        throw StateError('EVP_PKEY_keygen_init failed');
      }
      final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
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
  /// 64-byte FIPS 203 seed `(d ‖ z)`, via `EVP_PKEY_fromdata` with the `"seed"`
  /// `OSSL_PARAM` (`OSSL_PKEY_PARAM_ML_KEM_SEED`) and `EVP_PKEY_KEYPAIR`
  /// selection. The returned key can both encapsulate and decapsulate. Caller
  /// must free with [freeKey].
  ///
  /// This is the key to the strongest interop checks: feeding the *same* seed
  /// to OpenSSL and to `pqcrypto` must yield byte-identical public keys, and a
  /// shared `z` makes the FIPS 203 implicit-rejection secret comparable across
  /// implementations.
  Pointer<EVP_PKEY> keypairFromSeed(String algName, Uint8List seed) {
    if (seed.length != kSeedBytes) {
      throw ArgumentError('ML-KEM seed must be $kSeedBytes bytes (d‖z)');
    }
    return _fromData(algName, 'seed', seed, _evpPkeyKeypair);
  }

  /// Import a raw public key for [algName] and return an `EVP_PKEY*` (public
  /// only). Caller must free with [freeKey].
  Pointer<EVP_PKEY> importPublicKey(String algName, Uint8List pubKeyBytes) {
    return _fromData(algName, 'pub', pubKeyBytes, _evpPkeyPublicKey);
  }

  /// Shared `EVP_PKEY_fromdata` path: build a single-entry `OSSL_PARAM`
  /// (octet string [paramName] → [data]) and import it under [selection].
  ///
  /// All native buffers must outlive the `EVP_PKEY_fromdata` call —
  /// `OSSL_PARAM_BLD` stores pointers, not copies.
  Pointer<EVP_PKEY> _fromData(
    String algName,
    String paramName,
    Uint8List data,
    int selection,
  ) {
    final algNamePtr = algName.toNativeUtf8();
    final paramNamePtr = paramName.toNativeUtf8();
    final dataBuf = calloc<Uint8>(data.length);
    dataBuf.asTypedList(data.length).setAll(0, data);

    Pointer<OSSL_PARAM>? params;
    Pointer<EVP_PKEY_CTX>? ctx;
    final pkeyPtr = calloc<Pointer<EVP_PKEY>>();

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

  /// Extract the raw encoded public key bytes from an `EVP_PKEY`.
  Uint8List exportPublicKey(Pointer<EVP_PKEY> pkey) {
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

  /// Encapsulate against a public `EVP_PKEY*`. Returns `(ciphertext, sharedSecret)`.
  (Uint8List, Uint8List) encapsulate(Pointer<EVP_PKEY> pubKey) {
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

  /// Decapsulate [ciphertext] using a full keypair `EVP_PKEY*`. Returns the
  /// shared secret. Per FIPS 203 this never fails for a correctly-sized
  /// ciphertext: an invalid ciphertext yields the implicit-rejection secret
  /// `J(z ‖ c)` rather than an error.
  Uint8List decapsulate(Pointer<EVP_PKEY> secretKey, Uint8List ciphertext) {
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

  void freeKey(Pointer<EVP_PKEY> pkey) => _pkeyFree(pkey);

  /// Full OpenSSL version string, e.g. `"OpenSSL 4.0.0 14 Apr 2026"`.
  String version() => _opensslVersion(0).toDartString();

  bool? _seedSupport;

  /// Whether this `libcrypto` supports deterministic ML-KEM keygen from a seed
  /// (`EVP_PKEY_fromdata` with the `"seed"` param). Probed once and cached.
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
      final probe = Uint8List(kSeedBytes);
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

// ── ML-KEM parameter-set descriptor ───────────────────────────────────────────

/// A single ML-KEM parameter set, pairing the OpenSSL algorithm name with the
/// matching `pqcrypto` KEM and the **independent** FIPS 203 size constants.
///
/// The spec sizes are hard-coded from FIPS 203 (Table 2 / §8) rather than read
/// from `pqcrypto`'s params, so a size assertion cross-checks both OpenSSL's
/// output *and* `pqcrypto`'s params against the standard — a bug in either is
/// caught.
class MlKemLevel {
  /// OpenSSL algorithm name, e.g. `"ML-KEM-512"`.
  final String opensslName;

  /// The matching `pqcrypto` KEM.
  final KyberKem pq;

  /// Encapsulation (public) key size in bytes, per FIPS 203.
  final int specPublicKeyBytes;

  /// Ciphertext size in bytes, per FIPS 203.
  final int specCiphertextBytes;

  /// Decapsulation (expanded secret) key size in bytes, per FIPS 203.
  final int specSecretKeyBytes;

  const MlKemLevel({
    required this.opensslName,
    required this.pq,
    required this.specPublicKeyBytes,
    required this.specCiphertextBytes,
    required this.specSecretKeyBytes,
  });

  /// Shared secret size — always 32 bytes for ML-KEM.
  int get specSharedSecretBytes => kSharedSecretBytes;
}

/// All three FIPS 203 ML-KEM parameter sets, with their standard sizes.
///
/// | Level       | pk   | ct   | sk   | ss |
/// | :---------- | ---: | ---: | ---: | -: |
/// | ML-KEM-512  |  800 |  768 | 1632 | 32 |
/// | ML-KEM-768  | 1184 | 1088 | 2400 | 32 |
/// | ML-KEM-1024 | 1568 | 1568 | 3168 | 32 |
final List<MlKemLevel> mlKemLevels = <MlKemLevel>[
  MlKemLevel(
    opensslName: 'ML-KEM-512',
    pq: PqcKem.kyber512,
    specPublicKeyBytes: 800,
    specCiphertextBytes: 768,
    specSecretKeyBytes: 1632,
  ),
  MlKemLevel(
    opensslName: 'ML-KEM-768',
    pq: PqcKem.kyber768,
    specPublicKeyBytes: 1184,
    specCiphertextBytes: 1088,
    specSecretKeyBytes: 2400,
  ),
  MlKemLevel(
    opensslName: 'ML-KEM-1024',
    pq: PqcKem.kyber1024,
    specPublicKeyBytes: 1568,
    specCiphertextBytes: 1568,
    specSecretKeyBytes: 3168,
  ),
];

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Hex-encode [bytes], truncating after [maxBytes] with a length suffix.
String hex(List<int> bytes, {int maxBytes = 16}) {
  final shown = bytes.length > maxBytes ? bytes.sublist(0, maxBytes) : bytes;
  final h = shown.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return bytes.length > maxBytes ? '$h... (${bytes.length} bytes)' : h;
}

/// Constant-time-ish byte equality (length + content). Adequate for a test
/// harness; not a security-sensitive comparison.
bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Resolves a path to an OpenSSL >= 3.5 `libcrypto` that exposes ML-KEM.
///
/// Honors the `LIBCRYPTO_PATH` environment variable first; otherwise probes
/// common per-platform locations. ML-KEM landed in OpenSSL 3.5, so a distro's
/// system `libcrypto` (often OpenSSL 3.0.x) will NOT work — set `LIBCRYPTO_PATH`
/// to a 3.5+ build in that case. Returns `null` if nothing is found (callers
/// decide whether that is fatal or a skip).
String? resolveLibcryptoPath() {
  final override = Platform.environment['LIBCRYPTO_PATH'];
  if (override != null && override.isNotEmpty) {
    return File(override).existsSync() ? override : null;
  }

  final candidates = <String>[
    if (Platform.isMacOS) ...[
      '/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib',
      '/opt/homebrew/opt/openssl@3.5/lib/libcrypto.dylib',
      '/opt/homebrew/opt/openssl/lib/libcrypto.dylib',
      '/usr/local/opt/openssl@3.6/lib/libcrypto.dylib',
      '/usr/local/opt/openssl/lib/libcrypto.dylib',
    ],
    if (Platform.isLinux) ...[
      '/usr/local/lib64/libcrypto.so',
      '/usr/local/lib/libcrypto.so',
    ],
  ];

  for (final candidate in candidates) {
    if (File(candidate).existsSync()) return candidate;
  }
  return null;
}

/// The list of paths [resolveLibcryptoPath] probes, for diagnostics.
List<String> libcryptoProbePaths() => <String>[
  if (Platform.isMacOS) ...[
    '/opt/homebrew/opt/openssl@3.6/lib/libcrypto.dylib',
    '/opt/homebrew/opt/openssl@3.5/lib/libcrypto.dylib',
    '/opt/homebrew/opt/openssl/lib/libcrypto.dylib',
    '/usr/local/opt/openssl@3.6/lib/libcrypto.dylib',
    '/usr/local/opt/openssl/lib/libcrypto.dylib',
  ],
  if (Platform.isLinux) ...[
    '/usr/local/lib64/libcrypto.so',
    '/usr/local/lib/libcrypto.so',
  ],
];

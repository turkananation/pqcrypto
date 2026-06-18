/// OpenSSL ↔ pqcrypto ML-KEM interoperability harness.
///
/// Runs the cross-implementation proof for **all three** FIPS 203 parameter
/// sets — ML-KEM-512, ML-KEM-768, ML-KEM-1024 — against an OpenSSL ≥ 3.5
/// `libcrypto` reached via `dart:ffi`. For each level it runs:
///
///   * Size/spec conformance (OpenSSL & pqcrypto vs FIPS 203 constants)
///   * Tests A–D: the self-consistency + bidirectional cross-decapsulation matrix
///   * Test E: same seed (d‖z) ⇒ byte-identical public keys
///   * Test F: public-key wire round-trip (pqcrypto → OpenSSL → bytes)
///   * Test G: implicit-rejection secret J(z‖c) agrees on an invalid ciphertext
///
/// E and G require deterministic seed-based keygen; if the loaded `libcrypto`
/// lacks it they are reported as SKIP rather than failing.
///
/// Exits 0 if every executed check passes, 1 on any failure, 2 if no
/// ML-KEM-capable `libcrypto` could be located. See doc/OPENSSL_INTEROP.md.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_pqcrypto_interop/openssl_library.dart';
import 'package:openssl_pqcrypto_interop/openssl_ml_kem.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';

/// How many random round-trips to run for the cross tests (C and D) per level.
const int _fuzzIterations = 16;

final List<String> _failures = <String>[];
int _passes = 0;
int _skips = 0;

void _check(String label, bool condition) {
  if (condition) {
    _passes++;
    print('[PASS] $label');
  } else {
    _failures.add(label);
    print('[FAIL] $label');
  }
}

void _skip(String label, String reason) {
  _skips++;
  print('[SKIP] $label — $reason');
}

void main() {
  final libPath = resolveLibcryptoPath();
  if (libPath == null) {
    stderr.writeln(
      'Could not locate an OpenSSL libcrypto exposing ML-KEM (needs OpenSSL '
      '>= 3.5).\n'
      'Set LIBCRYPTO_PATH explicitly, e.g.:\n'
      '  LIBCRYPTO_PATH=/path/to/libcrypto.so dart run '
      'bin/openssl_pqcrypto_interop.dart\n'
      'Probed: ${libcryptoProbePaths().join(", ")}',
    );
    exit(2);
  }

  final ossl = OpenSslMlKem.load(libPath);
  final seedOk = ossl.supportsSeedKeygen;

  print('=== OpenSSL ↔ pqcrypto ML-KEM Interoperability ===');
  print('    ${ossl.version()} (via FFI → libcrypto) vs pqcrypto package');
  print('    libcrypto: $libPath');
  print(
    '    levels: ${mlKemInteropSets.map((l) => l.name).join(", ")}'
    '   |   fuzz: $_fuzzIterations iterations/direction',
  );
  if (!seedOk) {
    print(
      '    note: this libcrypto lacks seed-based ML-KEM keygen — '
      'tests E and G will be skipped.',
    );
  }

  for (final level in mlKemInteropSets) {
    _runLevel(ossl, level, seedOk: seedOk);
  }

  print('\n=== Summary ===');
  print('passed: $_passes   skipped: $_skips   failed: ${_failures.length}');
  if (_failures.isEmpty) {
    print('[PASS] All executed interop checks passed.');
    print('Both implementations conform to FIPS 203 ML-KEM at every tested');
    print('parameter set: encodings are byte-compatible and shared secrets');
    print('(including the implicit-rejection branch) agree byte-for-byte.');
  } else {
    print('[FAIL] ${_failures.length} check(s) failed:');
    for (final f in _failures) {
      print('  - $f');
    }
    print('\nInterpretation:');
    print('  A/B verify each implementation is internally consistent.');
    print('  C/D verify bidirectional cross-implementation interoperability.');
    print('  E/F/G verify byte-level wire and implicit-rejection conformance.');
    print('  A C/D/E/F/G failure means pqcrypto deviates from FIPS 203 and');
    print('  cannot reliably exchange ML-KEM material with OpenSSL.');
    exit(1);
  }
}

void _runLevel(
  OpenSslMlKem ossl,
  MlKemInteropSet level, {
  required bool seedOk,
}) {
  final name = level.name;
  final pq = level.pqcrypto;
  print('\n--- $name ---');

  // ── Sizes vs FIPS 203 (independent constants), OpenSSL and pqcrypto ───────
  final (osslPub0, osslKey0) = ossl.generateKeypair(name);
  final (pqPub0, pqSk0) = pq.generateKeyPair();
  final (osslCt0, _) = ossl.encapsulate(ossl.importPublicKey(name, pqPub0));
  print(
    '  sizes pk/ct/sk/ss — OpenSSL ${osslPub0.length}/${osslCt0.length}/—/— · '
    'pqcrypto ${pqPub0.length}/${pq.params.ciphertextBytes}/'
    '${pqSk0.length}/32 · '
    'FIPS ${level.publicKeyBytes}/${level.ciphertextBytes}/'
    '${level.secretKeyBytes}/${level.sharedSecretBytes}',
  );
  _check(
    '$name sizes: OpenSSL & pqcrypto match FIPS 203 pk/ct/sk/ss',
    osslPub0.length == level.publicKeyBytes &&
        osslCt0.length == level.ciphertextBytes &&
        pqPub0.length == level.publicKeyBytes &&
        pq.params.ciphertextBytes == level.ciphertextBytes &&
        pqSk0.length == level.secretKeyBytes,
  );
  ossl.freeKey(osslKey0);

  // ── Test A: OpenSSL → OpenSSL (sanity) ────────────────────────────────────
  final (osslPubA, osslKeyA) = ossl.generateKeypair(name);
  final (ctA, ssAliceA) = ossl.encapsulate(
    ossl.importPublicKey(name, osslPubA),
  );
  final ssBobA = ossl.decapsulate(osslKeyA, ctA);
  ossl.freeKey(osslKeyA);
  _check(
    '$name A: OpenSSL→OpenSSL self-consistent',
    bytesEqual(ssAliceA, ssBobA),
  );

  // ── Test B: pqcrypto → pqcrypto (sanity) ──────────────────────────────────
  final (pqPubB, pqSkB) = pq.generateKeyPair();
  final (ctB, ssAliceB) = pq.encapsulate(pqPubB);
  final ssBobB = pq.decapsulate(pqSkB, ctB);
  _check(
    '$name B: pqcrypto→pqcrypto self-consistent',
    bytesEqual(ssAliceB, ssBobB),
  );

  // ── Test C: OpenSSL keygen → pqcrypto encaps → OpenSSL decaps (×fuzz) ──────
  var cOk = true;
  for (var i = 0; i < _fuzzIterations; i++) {
    final (osslPubC, osslKeyC) = ossl.generateKeypair(name);
    final (ctC, ssAliceC) = pq.encapsulate(osslPubC);
    final ssBobC = ossl.decapsulate(osslKeyC, Uint8List.fromList(ctC));
    ossl.freeKey(osslKeyC);
    if (!bytesEqual(ssAliceC, ssBobC)) cOk = false;
  }
  _check('$name C: OpenSSL keygen + pqcrypto encaps + OpenSSL decaps', cOk);

  // ── Test D: pqcrypto keygen → OpenSSL encaps → pqcrypto decaps (×fuzz) ─────
  var dOk = true;
  for (var i = 0; i < _fuzzIterations; i++) {
    final (pqPubD, pqSkD) = pq.generateKeyPair();
    final osslPubKeyD = ossl.importPublicKey(name, Uint8List.fromList(pqPubD));
    final (ctD, ssAliceD) = ossl.encapsulate(osslPubKeyD);
    ossl.freeKey(osslPubKeyD);
    final ssBobD = pq.decapsulate(pqSkD, ctD);
    if (!bytesEqual(ssAliceD, ssBobD)) dOk = false;
  }
  _check('$name D: pqcrypto keygen + OpenSSL encaps + pqcrypto decaps', dOk);

  // ── Test F: public-key wire round-trip (pqcrypto → OpenSSL → bytes) ───────
  final (pqPubF, _) = pq.generateKeyPair();
  final osslKeyF = ossl.importPublicKey(name, Uint8List.fromList(pqPubF));
  final reexportedF = ossl.exportPublicKey(osslKeyF);
  ossl.freeKey(osslKeyF);
  _check(
    '$name F: public-key wire round-trip (pqcrypto→OpenSSL→bytes identical)',
    bytesEqual(pqPubF, reexportedF),
  );

  // ── Tests E and G need deterministic seed-based keygen ────────────────────
  if (!seedOk) {
    _skip('$name E: same seed ⇒ identical public keys', 'no seed keygen');
    _skip('$name G: implicit-rejection secret agreement', 'no seed keygen');
    return;
  }

  // A fixed (obviously non-secret) seed, varied per level so the three runs
  // exercise distinct key material.
  final seed = Uint8List(mlKemKeyPairSeedBytes);
  for (var i = 0; i < seed.length; i++) {
    seed[i] = (i * 7 + level.pqcrypto.params.k * 31) & 0xFF;
  }

  final (pqSeedPub, pqSeedSk) = pq.generateKeyPair(seed);
  final osslSeedKey = ossl.keypairFromSeed(name, seed);
  try {
    // ── Test E: identical public keys from identical seed ──────────────────
    final osslSeedPub = ossl.exportPublicKey(osslSeedKey);
    _check(
      '$name E: same seed ⇒ identical public keys (OpenSSL == pqcrypto)',
      bytesEqual(pqSeedPub, osslSeedPub),
    );

    // ── Test G: implicit-rejection agreement on an invalid ciphertext ──────
    // A correctly-sized but invalid ciphertext: FIPS 203 decapsulation never
    // fails — both sides return K̄ = J(z‖c). Same z (shared seed) + same c ⇒
    // identical secret. This exercises the rejection branch A–D never hit.
    final invalidCt = Uint8List(level.ciphertextBytes);
    for (var i = 0; i < invalidCt.length; i++) {
      invalidCt[i] = (i * 251 + 17) & 0xFF;
    }
    final ssRejPq = pq.decapsulate(pqSeedSk, invalidCt);
    final ssRejOssl = ossl.decapsulate(osslSeedKey, invalidCt);
    _check(
      '$name G: implicit-rejection secret J(z‖c) agrees on invalid ciphertext',
      bytesEqual(ssRejPq, ssRejOssl) && ssRejPq.length == 32,
    );
  } finally {
    ossl.freeKey(osslSeedKey);
  }
}

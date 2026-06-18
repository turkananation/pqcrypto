/// Rigorous OpenSSL ↔ pqcrypto ML-KEM interoperability tests, across all three
/// FIPS 203 parameter sets (ML-KEM-512/768/1024).
///
/// Run with an OpenSSL ≥ 3.5 `libcrypto`:
///
/// ```sh
/// LIBCRYPTO_PATH=/path/to/libcrypto.so dart test
/// ```
///
/// If no ML-KEM-capable `libcrypto` is found the whole suite is **skipped**
/// (reported, not failed), so a bare `dart test` on a machine without OpenSSL
/// ≥ 3.5 stays green. CI (interop.yml) provisions one and sets `LIBCRYPTO_PATH`,
/// so there the suite runs in full.
///
/// What each level proves:
///   * sizes      — OpenSSL & pqcrypto encodings match the FIPS 203 constants
///   * A / B      — each implementation is internally self-consistent
///   * C / D      — bidirectional cross-decapsulation (fuzzed over many keys)
///   * E          — same seed (d‖z) ⇒ byte-identical public keys
///   * E-exchange — the seed-derived keypair interoperates both directions
///   * F          — public-key wire round-trip is byte-identical
///   * G          — implicit-rejection secret J(z‖c) agrees on an invalid ct
///   * negative   — pqcrypto rejects a truncated OpenSSL-exported public key
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:openssl_pqcrypto_interop/openssl_ml_kem.dart';
import 'package:openssl_pqcrypto_interop/openssl_library.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';
import 'package:test/test.dart';

/// Cross-implementation fuzz depth for the C/D matrices (per level, per side).
const int _fuzzIterations = 24;

void main() {
  final libPath = resolveLibcryptoPath();

  if (libPath == null) {
    test(
      'OpenSSL ↔ pqcrypto ML-KEM interop',
      () {},
      skip:
          'No OpenSSL >= 3.5 libcrypto found. Set LIBCRYPTO_PATH to a '
          'ML-KEM-capable build. Probed: ${libcryptoProbePaths().join(", ")}',
    );
    return;
  }

  // Resolve at collection time (sync FFI): the `skip:` expressions below are
  // evaluated while the test tree is built, before any setUp hook runs.
  final ossl = OpenSslMlKem.load(libPath);
  final seedOk = ossl.supportsSeedKeygen;
  final ownedKeys = <Pointer<EvpPkey>>[];

  setUpAll(() {
    printOnFailure('libcrypto: $libPath — ${ossl.version()}');
  });

  // Track an EvpPkey for teardown so a failing expectation never leaks it.
  Pointer<EvpPkey> own(Pointer<EvpPkey> k) {
    ownedKeys.add(k);
    return k;
  }

  tearDown(() {
    for (final k in ownedKeys) {
      ossl.freeKey(k);
    }
    ownedKeys.clear();
  });

  for (final level in mlKemInteropSets) {
    final name = level.name;
    final pq = level.pqcrypto;

    group(name, () {
      test('sizes match FIPS 203 (OpenSSL & pqcrypto, pk/ct/sk/ss)', () {
        // pqcrypto params vs the independent spec constants.
        expect(
          pq.params.publicKeyBytes,
          level.publicKeyBytes,
          reason: 'pqcrypto public key size',
        );
        expect(
          pq.params.ciphertextBytes,
          level.ciphertextBytes,
          reason: 'pqcrypto ciphertext size',
        );
        expect(
          pq.params.secretKeyBytes,
          level.secretKeyBytes,
          reason: 'pqcrypto secret key size',
        );

        // Live OpenSSL output vs the same constants.
        final (osslPub, osslKey) = ossl.generateKeypair(name);
        own(osslKey);
        expect(
          osslPub,
          hasLength(level.publicKeyBytes),
          reason: 'OpenSSL public key size',
        );

        final (osslCt, osslSs) = ossl.encapsulate(
          own(ossl.importPublicKey(name, osslPub)),
        );
        expect(
          osslCt,
          hasLength(level.ciphertextBytes),
          reason: 'OpenSSL ciphertext size',
        );
        expect(
          osslSs,
          hasLength(level.sharedSecretBytes),
          reason: 'OpenSSL shared-secret size',
        );

        // pqcrypto output sizes.
        final (pqPub, pqSk) = pq.generateKeyPair();
        final (pqCt, pqSs) = pq.encapsulate(pqPub);
        expect(pqPub, hasLength(level.publicKeyBytes));
        expect(pqSk, hasLength(level.secretKeyBytes));
        expect(pqCt, hasLength(level.ciphertextBytes));
        expect(pqSs, hasLength(level.sharedSecretBytes));
      });

      test('A: OpenSSL → OpenSSL is self-consistent', () {
        final (pub, key) = ossl.generateKeypair(name);
        own(key);
        final (ct, ssAlice) = ossl.encapsulate(
          own(ossl.importPublicKey(name, pub)),
        );
        final ssBob = ossl.decapsulate(key, ct);
        expect(ssBob, equals(ssAlice));
      });

      test('B: pqcrypto → pqcrypto is self-consistent', () {
        final (pub, sk) = pq.generateKeyPair();
        final (ct, ssAlice) = pq.encapsulate(pub);
        final ssBob = pq.decapsulate(sk, ct);
        expect(ssBob, equals(ssAlice));
      });

      test(
        'C: OpenSSL keygen + pqcrypto encaps + OpenSSL decaps (×$_fuzzIterations)',
        () {
          for (var i = 0; i < _fuzzIterations; i++) {
            final (osslPub, osslKey) = ossl.generateKeypair(name);
            final (ct, ssAlice) = pq.encapsulate(osslPub);
            final ssBob = ossl.decapsulate(osslKey, Uint8List.fromList(ct));
            ossl.freeKey(osslKey);
            expect(ssBob, equals(ssAlice), reason: 'iteration $i');
            expect(ssAlice, hasLength(32));
          }
        },
      );

      test(
        'D: pqcrypto keygen + OpenSSL encaps + pqcrypto decaps (×$_fuzzIterations)',
        () {
          for (var i = 0; i < _fuzzIterations; i++) {
            final (pqPub, pqSk) = pq.generateKeyPair();
            final osslPubKey = ossl.importPublicKey(
              name,
              Uint8List.fromList(pqPub),
            );
            final (ct, ssAlice) = ossl.encapsulate(osslPubKey);
            ossl.freeKey(osslPubKey);
            final ssBob = pq.decapsulate(pqSk, ct);
            expect(ssBob, equals(ssAlice), reason: 'iteration $i');
            expect(ssAlice, hasLength(32));
          }
        },
      );

      test('F: public-key wire round-trip is byte-identical', () {
        // pqcrypto-generated public key → OpenSSL import → OpenSSL re-export
        // must reproduce the exact input bytes (identical raw encoding).
        for (var i = 0; i < 4; i++) {
          final (pqPub, _) = pq.generateKeyPair();
          final key = own(
            ossl.importPublicKey(name, Uint8List.fromList(pqPub)),
          );
          final reexported = ossl.exportPublicKey(key);
          expect(reexported, equals(pqPub), reason: 'iteration $i');
        }
      });

      test('negative: pqcrypto rejects a truncated OpenSSL public key', () {
        final (osslPub, osslKey) = ossl.generateKeypair(name);
        own(osslKey);
        final truncated = Uint8List.sublistView(osslPub, 0, osslPub.length - 1);
        expect(() => pq.encapsulate(truncated), throwsArgumentError);
      });

      group(
        'seed-based (deterministic) conformance',
        () {
          test('E: same seed ⇒ byte-identical public keys', () {
            for (var s = 0; s < 3; s++) {
              final seed = _seed(level, salt: s);
              final (pqPub, _) = pq.generateKeyPair(seed);
              final osslKey = own(ossl.keypairFromSeed(name, seed));
              final osslPub = ossl.exportPublicKey(osslKey);
              expect(
                osslPub,
                equals(pqPub),
                reason:
                    'seed salt $s: OpenSSL and pqcrypto derived different keys',
              );
            }
          });

          test(
            'E-exchange: seed-derived keypair interoperates both directions',
            () {
              final seed = _seed(level, salt: 42);
              final (pqPub, pqSk) = pq.generateKeyPair(seed);
              final osslKey = own(ossl.keypairFromSeed(name, seed));

              // pqcrypto encaps → OpenSSL (seed key) decaps.
              final (ct1, ss1Alice) = pq.encapsulate(pqPub);
              final ss1Bob = ossl.decapsulate(osslKey, Uint8List.fromList(ct1));
              expect(
                ss1Bob,
                equals(ss1Alice),
                reason: 'pq→ossl on seed keypair',
              );

              // OpenSSL (seed key) encaps → pqcrypto decaps.
              final (ct2, ss2Alice) = ossl.encapsulate(osslKey);
              final ss2Bob = pq.decapsulate(pqSk, ct2);
              expect(
                ss2Bob,
                equals(ss2Alice),
                reason: 'ossl→pq on seed keypair',
              );
            },
          );

          test('G: implicit-rejection secret J(z‖c) agrees on an invalid ct', () {
            final seed = _seed(level, salt: 7);
            final (pqPub, pqSk) = pq.generateKeyPair(seed);
            final osslKey = own(ossl.keypairFromSeed(name, seed));

            // A correctly-sized but invalid ciphertext. FIPS 203 decapsulation
            // never fails: both sides return K̄ = J(z‖c). Shared z + shared c ⇒
            // identical secret. This exercises the rejection branch A–D never hit.
            final invalidCt = Uint8List(level.ciphertextBytes);
            for (var i = 0; i < invalidCt.length; i++) {
              invalidCt[i] = (i * 251 + 17) & 0xFF;
            }

            final ssRejPq = pq.decapsulate(pqSk, invalidCt);
            final ssRejOssl = ossl.decapsulate(osslKey, invalidCt);

            expect(ssRejPq, hasLength(32));
            expect(
              ssRejOssl,
              equals(ssRejPq),
              reason: 'implicit-rejection secrets diverged',
            );

            // Sanity: the rejection secret must NOT equal a valid exchange secret
            // (confirms we really hit the J path, not a chance valid decrypt).
            final (_, ssValid) = pq.encapsulate(pqPub);
            expect(ssRejPq, isNot(equals(ssValid)));
          });
        },
        skip: seedOk ? null : 'libcrypto lacks seed-based ML-KEM keygen',
      );
    });
  }
}

/// A fixed, non-secret 64-byte seed `(d‖z)`, varied by level and [salt] so
/// distinct runs exercise distinct key material.
Uint8List _seed(MlKemInteropSet level, {required int salt}) {
  final seed = Uint8List(mlKemKeyPairSeedBytes);
  for (var i = 0; i < seed.length; i++) {
    seed[i] = (i * 7 + level.pqcrypto.params.k * 31 + salt * 101) & 0xFF;
  }
  return seed;
}

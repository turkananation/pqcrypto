@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:liboqs_pqcrypto_interop/liboqs.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';
import 'package:test/test.dart';

void main() {
  final path = resolveLiboqsPath();
  if (path == null) {
    test(
      'liboqs ML-KEM interop',
      () {},
      skip:
          'No liboqs shared library found. Set LIBOQS_PATH. '
          'Probed: ${liboqsProbePaths().join(", ")}',
    );
    return;
  }

  final liboqs = LiboqsInterop.load(path);
  setUpAll(() {
    printOnFailure('liboqs: $path - ${liboqs.version()}');
  });
  tearDownAll(liboqs.dispose);

  for (final set in mlKemInteropSets) {
    group(set.name, () {
      test('deterministic keygen and encapsulation are byte-exact', () {
        expect(liboqs.isKemEnabled(set.name), isTrue);
        final keySeed = sequence(0x10, mlKemKeyPairSeedBytes);
        final encapsulationSeed = sequence(0x90, mlKemEncapsulationSeedBytes);

        final (dartPublicKey, dartSecretKey) = set.pqcrypto.generateKeyPair(
          keySeed,
        );
        final (oqsPublicKey, oqsSecretKey) = liboqs.generateKemKeyPair(
          set.name,
          publicKeyBytes: set.publicKeyBytes,
          secretKeyBytes: set.secretKeyBytes,
          seed: keySeed,
        );
        expect(oqsPublicKey, equals(dartPublicKey));
        expect(oqsSecretKey, equals(dartSecretKey));

        final (dartCiphertext, dartSecret) = set.pqcrypto.encapsulate(
          dartPublicKey,
          encapsulationSeed,
        );
        final (oqsCiphertext, oqsSecret) = liboqs.encapsulate(
          set.name,
          oqsPublicKey,
          ciphertextBytes: set.ciphertextBytes,
          sharedSecretBytes: set.sharedSecretBytes,
          seed: encapsulationSeed,
        );
        expect(oqsCiphertext, equals(dartCiphertext));
        expect(oqsSecret, equals(dartSecret));
      });

      test('random exchanges interoperate in both directions', () {
        final (oqsPublicKey, oqsSecretKey) = liboqs.generateKemKeyPair(
          set.name,
          publicKeyBytes: set.publicKeyBytes,
          secretKeyBytes: set.secretKeyBytes,
        );
        final (dartCiphertext, dartSharedSecret) = set.pqcrypto.encapsulate(
          oqsPublicKey,
        );
        final oqsRecovered = liboqs.decapsulate(
          set.name,
          oqsSecretKey,
          dartCiphertext,
          sharedSecretBytes: set.sharedSecretBytes,
        );
        expect(oqsRecovered, equals(dartSharedSecret));

        final (dartPublicKey, dartSecretKey) = set.pqcrypto.generateKeyPair();
        final (oqsCiphertext, oqsSharedSecret) = liboqs.encapsulate(
          set.name,
          dartPublicKey,
          ciphertextBytes: set.ciphertextBytes,
          sharedSecretBytes: set.sharedSecretBytes,
        );
        final dartRecovered = set.pqcrypto.decapsulate(
          dartSecretKey,
          oqsCiphertext,
        );
        expect(dartRecovered, equals(oqsSharedSecret));
      });

      test('implicit rejection agrees for an invalid ciphertext', () {
        final keySeed = sequence(0x40, mlKemKeyPairSeedBytes);
        final (_, dartSecretKey) = set.pqcrypto.generateKeyPair(keySeed);
        final (_, oqsSecretKey) = liboqs.generateKemKeyPair(
          set.name,
          publicKeyBytes: set.publicKeyBytes,
          secretKeyBytes: set.secretKeyBytes,
          seed: keySeed,
        );
        final invalidCiphertext = Uint8List(set.ciphertextBytes);
        for (var i = 0; i < invalidCiphertext.length; i++) {
          invalidCiphertext[i] = (i * 251 + 17) & 0xff;
        }

        final dartRejected = set.pqcrypto.decapsulate(
          dartSecretKey,
          invalidCiphertext,
        );
        final oqsRejected = liboqs.decapsulate(
          set.name,
          oqsSecretKey,
          invalidCiphertext,
          sharedSecretBytes: set.sharedSecretBytes,
        );
        expect(oqsRejected, equals(dartRejected));
      });
    });
  }
}

@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:openssl_pqcrypto_interop/openssl_library.dart';
import 'package:openssl_pqcrypto_interop/openssl_signature.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';
import 'package:test/test.dart';

void main() {
  final path = resolveLibcryptoPath();
  if (path == null) {
    test(
      'OpenSSL ML-DSA interop',
      () {},
      skip:
          'No OpenSSL 3.5+ libcrypto found. Set LIBCRYPTO_PATH. '
          'Probed: ${libcryptoProbePaths().join(", ")}',
    );
    return;
  }

  final openssl = OpenSslSignatureInterop.load(path);
  final message = Uint8List.fromList(
    'pqcrypto OpenSSL ML-DSA interoperability'.codeUnits,
  );
  final context = Uint8List.fromList('pqcrypto-v0.4'.codeUnits);

  setUpAll(() {
    printOnFailure('libcrypto: $path - ${openssl.version()}');
  });

  for (final set in mlDsaInteropSets) {
    test('${set.name}: seeded keys and hedged signatures are byte-exact', () {
      final seed = sequence(0x20, mlDsaSeedBytes);
      final randomness = sequence(0x80, 32);
      final (dartPublicKey, dartSecretKey) = MlDsa.generateKeyPairSeeded(
        set.params,
        seed,
      );
      final (opensslPublicKey, opensslSecretKey) = openssl
          .generateKeyPairFromSeed(
            set.name,
            seed,
            publicKeyBytes: set.publicKeyBytes,
            secretKeyBytes: set.secretKeyBytes,
          );

      expect(opensslPublicKey, equals(dartPublicKey));
      expect(opensslSecretKey, equals(dartSecretKey));

      final dartSignature = MlDsa.sign(
        dartSecretKey,
        message,
        set.params,
        ctx: context,
        rnd: randomness,
      );
      final opensslSignature = openssl.signWithContext(
        set.name,
        opensslSecretKey,
        message,
        context,
        additionalRandomness: randomness,
      );

      expect(opensslSignature, hasLength(set.signatureBytes));
      expect(opensslSignature, equals(dartSignature));
      expect(
        openssl.verifyWithContext(
          set.name,
          dartPublicKey,
          message,
          dartSignature,
          context,
        ),
        isTrue,
      );
      expect(
        MlDsa.verify(
          opensslPublicKey,
          message,
          opensslSignature,
          set.params,
          ctx: context,
        ),
        isTrue,
      );
    });
  }
}

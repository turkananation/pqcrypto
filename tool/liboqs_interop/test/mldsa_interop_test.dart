@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:liboqs_pqcrypto_interop/liboqs.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';
import 'package:test/test.dart';

void main() {
  final path = resolveLiboqsPath();
  if (path == null) {
    test(
      'liboqs ML-DSA interop',
      () {},
      skip:
          'No liboqs shared library found. Set LIBOQS_PATH. '
          'Probed: ${liboqsProbePaths().join(", ")}',
    );
    return;
  }

  final liboqs = LiboqsInterop.load(path);
  final message = Uint8List.fromList(
    'pqcrypto liboqs ML-DSA interoperability'.codeUnits,
  );
  final context = Uint8List.fromList('pqcrypto-v0.4'.codeUnits);

  setUpAll(() {
    printOnFailure('liboqs: $path - ${liboqs.version()}');
  });
  tearDownAll(liboqs.dispose);

  for (final set in mlDsaInteropSets) {
    test('${set.name}: signatures verify bidirectionally', () {
      expect(liboqs.isSignatureEnabled(set.name), isTrue);
      expect(liboqs.signatureSupportsContext(set.name), isTrue);

      final (dartPublicKey, dartSecretKey) = MlDsa.generateKeyPair(set.params);
      final dartSignature = MlDsa.sign(
        dartSecretKey,
        message,
        set.params,
        ctx: context,
        rnd: sequence(0x60, 32),
      );
      expect(
        liboqs.verify(set.name, dartPublicKey, message, dartSignature, context),
        isTrue,
      );

      final (oqsPublicKey, oqsSecretKey) = liboqs.generateSignatureKeyPair(
        set.name,
        publicKeyBytes: set.publicKeyBytes,
        secretKeyBytes: set.secretKeyBytes,
      );
      final oqsSignature = liboqs.sign(
        set.name,
        oqsSecretKey,
        message,
        context,
        signatureBytes: set.signatureBytes,
      );
      expect(
        MlDsa.verify(
          oqsPublicKey,
          message,
          oqsSignature,
          set.params,
          ctx: context,
        ),
        isTrue,
      );

      final tampered = Uint8List.fromList(oqsSignature)..[0] ^= 1;
      expect(
        MlDsa.verify(oqsPublicKey, message, tampered, set.params, ctx: context),
        isFalse,
      );
    });
  }
}

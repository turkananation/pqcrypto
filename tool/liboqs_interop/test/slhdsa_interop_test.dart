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
      'liboqs SLH-DSA interop',
      () {},
      skip:
          'No liboqs shared library found. Set LIBOQS_PATH. '
          'Probed: ${liboqsProbePaths().join(", ")}',
    );
    return;
  }

  final liboqs = LiboqsInterop.load(path);
  final message = Uint8List.fromList(
    'pqcrypto liboqs SLH-DSA interoperability'.codeUnits,
  );
  final context = Uint8List.fromList('pqcrypto-v0.4'.codeUnits);

  setUpAll(() {
    print('liboqs interop: ${liboqs.version()}');
  });
  tearDownAll(liboqs.dispose);

  for (final set in slhDsaInteropSets) {
    test(
      '${set.liboqsName}: signatures verify bidirectionally',
      () {
        expect(liboqs.isSignatureEnabled(set.liboqsName), isTrue);
        expect(liboqs.signatureSupportsContext(set.liboqsName), isTrue);

        final params = set.params;
        final (dartPublicKey, dartSecretKey) = SlhDsa.generateKeyPair(params);
        final dartSignature = SlhDsa.sign(
          dartSecretKey,
          message,
          params,
          context: context,
          additionalRandomness: sequence(0x90, params.n),
          allowSlowSigning: true,
        );
        expect(
          liboqs.verify(
            set.liboqsName,
            dartPublicKey,
            message,
            dartSignature,
            context,
          ),
          isTrue,
        );

        final (oqsPublicKey, oqsSecretKey) = liboqs.generateSignatureKeyPair(
          set.liboqsName,
          publicKeyBytes: params.publicKeyBytes,
          secretKeyBytes: params.secretKeyBytes,
        );
        final oqsSignature = liboqs.sign(
          set.liboqsName,
          oqsSecretKey,
          message,
          context,
          signatureBytes: params.signatureBytes,
        );
        expect(
          SlhDsa.verify(
            oqsPublicKey,
            message,
            oqsSignature,
            params,
            context: context,
          ),
          isTrue,
        );
      },
      timeout: Timeout.none,
    );
  }
}

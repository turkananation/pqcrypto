@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:openssl_pqcrypto_interop/openssl_library.dart';
import 'package:openssl_pqcrypto_interop/openssl_signature.dart';
import 'package:pqcrypto/src/algos/slhdsa/slhdsa.dart';
import 'package:pqcrypto_interop_common/pqcrypto_interop_common.dart';
import 'package:test/test.dart';

void main() {
  final path = resolveLibcryptoPath();
  if (path == null) {
    test(
      'OpenSSL SLH-DSA interop',
      () {},
      skip:
          'No OpenSSL 3.5+ libcrypto found. Set LIBCRYPTO_PATH. '
          'Probed: ${libcryptoProbePaths().join(", ")}',
    );
    return;
  }

  final openssl = OpenSslSignatureInterop.load(path);
  final message = Uint8List.fromList(
    'pqcrypto OpenSSL SLH-DSA interoperability'.codeUnits,
  );
  final context = Uint8List.fromList('pqcrypto-v0.4'.codeUnits);

  setUpAll(() {
    print('OpenSSL interop: ${openssl.version()}');
  });

  for (final set in slhDsaInteropSets) {
    test(
      '${set.name}: seeded keygen and signatures are byte-exact',
      () {
        final params = set.params;
        final secretSeed = sequence(0x10, params.n);
        final secretPrf = sequence(0x30, params.n);
        final publicSeed = sequence(0x50, params.n);
        final seed = Uint8List(3 * params.n)
          ..setRange(0, params.n, secretSeed)
          ..setRange(params.n, 2 * params.n, secretPrf)
          ..setRange(2 * params.n, 3 * params.n, publicSeed);

        final (
          dartPublicKey,
          dartSecretKey,
        ) = SlhDsaInternal.generateKeyPairSeeded(
          params,
          secretSeed,
          secretPrf,
          publicSeed,
        );
        final (opensslPublicKey, opensslSecretKey) = openssl
            .generateKeyPairFromSeed(
              set.name,
              seed,
              publicKeyBytes: params.publicKeyBytes,
              secretKeyBytes: params.secretKeyBytes,
            );
        expect(opensslPublicKey, equals(dartPublicKey));
        expect(opensslSecretKey, equals(dartSecretKey));

        final additionalRandomness = sequence(0x70, params.n);
        final dartInternal = SlhDsaInternal.sign(
          dartSecretKey,
          message,
          params,
          additionalRandomness: additionalRandomness,
        );
        final opensslInternal = openssl.signRaw(
          set.name,
          opensslSecretKey,
          message,
          additionalRandomness: additionalRandomness,
        );
        expect(opensslInternal, equals(dartInternal));
        expect(
          openssl.verifyRaw(set.name, dartPublicKey, message, dartInternal),
          isTrue,
        );

        final dartExternal = SlhDsa.sign(
          dartSecretKey,
          message,
          params,
          context: context,
          additionalRandomness: additionalRandomness,
          allowSlowSigning: true,
        );
        final opensslExternal = openssl.signWithContext(
          set.name,
          opensslSecretKey,
          message,
          context,
          additionalRandomness: additionalRandomness,
        );
        expect(opensslExternal, equals(dartExternal));
        expect(
          openssl.verifyWithContext(
            set.name,
            dartPublicKey,
            message,
            dartExternal,
            context,
          ),
          isTrue,
        );
      },
      timeout: Timeout.none,
    );
  }
}

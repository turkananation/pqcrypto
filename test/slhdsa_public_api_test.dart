import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

void main() {
  test('package root exposes all 12 supported FIPS 205 sets', () {
    expect(
      SlhDsaParams.supportedValues.map((params) => params.name),
      equals(<String>[
        'SLH-DSA-SHA2-128s',
        'SLH-DSA-SHA2-128f',
        'SLH-DSA-SHA2-192s',
        'SLH-DSA-SHA2-192f',
        'SLH-DSA-SHA2-256s',
        'SLH-DSA-SHA2-256f',
        'SLH-DSA-SHAKE-128s',
        'SLH-DSA-SHAKE-128f',
        'SLH-DSA-SHAKE-192s',
        'SLH-DSA-SHAKE-192f',
        'SLH-DSA-SHAKE-256s',
        'SLH-DSA-SHAKE-256f',
      ]),
    );
    expect(
      SlhDsaParams.supportedValues.every((params) => params.isSupported),
      isTrue,
    );
  });

  test(
    'package root supports SHA-2 key generation and verification',
    () {
      final params = SlhDsaParams.get(SlhDsaParameter.sha2128f);
      expect(params.hashFamily, SlhDsaHashFamily.sha2);
      final (publicKey, secretKey) = SlhDsa.generateKeyPair(params);
      final message = Uint8List.fromList(<int>[1, 2, 3, 4]);
      final signature = SlhDsa.signDeterministic(secretKey, message, params);

      expect(SlhDsa.verify(publicKey, message, signature, params), isTrue);
    },
    timeout: Timeout.none,
  );
}

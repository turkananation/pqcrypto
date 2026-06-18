import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:pqcrypto/src/algos/slhdsa/slhdsa.dart';
import 'package:test/test.dart';

void main() {
  final params = SlhDsaParams.shake128f;
  final seed = Uint8List(params.n);
  final (publicKey, secretKey) = SlhDsaInternal.generateKeyPairSeeded(
    params,
    seed,
    Uint8List(params.n)..[0] = 1,
    Uint8List(params.n)..[0] = 2,
  );
  final message = Uint8List.fromList(<int>[1, 2, 3]);

  test('key generation validates all seed lengths', () {
    expect(
      () => SlhDsaInternal.generateKeyPairSeeded(
        params,
        Uint8List(params.n - 1),
        seed,
        seed,
      ),
      throwsArgumentError,
    );
    expect(
      () => SlhDsaInternal.generateKeyPairSeeded(
        params,
        seed,
        Uint8List(params.n + 1),
        seed,
      ),
      throwsArgumentError,
    );
    expect(
      () => SlhDsaInternal.generateKeyPairSeeded(
        params,
        seed,
        seed,
        Uint8List(params.n - 1),
      ),
      throwsArgumentError,
    );
  });

  test('external signing validates context and randomness lengths', () {
    expect(
      () => SlhDsa.sign(Uint8List(params.secretKeyBytes - 1), message, params),
      throwsArgumentError,
    );
    expect(
      () => SlhDsa.sign(secretKey, message, params, context: Uint8List(256)),
      throwsArgumentError,
    );
    expect(
      () => SlhDsa.sign(
        secretKey,
        message,
        params,
        additionalRandomness: Uint8List(params.n - 1),
      ),
      throwsArgumentError,
    );
  });

  test('slow parameter signing requires explicit opt-in', () {
    final slow = SlhDsaParams.shake128s;
    final slowSecretKey = Uint8List(slow.secretKeyBytes);
    expect(
      () => SlhDsa.signDeterministic(slowSecretKey, message, slow),
      throwsUnsupportedError,
    );
    expect(
      () => SlhDsa.hashSignDeterministic(
        slowSecretKey,
        message,
        SlhDsaPreHash.sha256,
        slow,
      ),
      throwsUnsupportedError,
    );
  });

  test('verification is total for malformed untrusted inputs', () {
    final signature = SlhDsa.signDeterministic(secretKey, message, params);

    expect(
      SlhDsa.verify(
        Uint8List(params.publicKeyBytes - 1),
        message,
        signature,
        params,
      ),
      isFalse,
    );
    expect(
      SlhDsa.verify(
        publicKey,
        message,
        Uint8List(params.signatureBytes - 1),
        params,
      ),
      isFalse,
    );
    expect(
      SlhDsa.verify(
        publicKey,
        message,
        signature,
        params,
        context: Uint8List(256),
      ),
      isFalse,
    );
    expect(
      SlhDsaInternal.verify(
        publicKey,
        message,
        Uint8List(params.signatureBytes + 1),
        params,
      ),
      isFalse,
    );
    expect(
      SlhDsa.hashVerify(
        Uint8List(params.publicKeyBytes - 1),
        message,
        signature,
        SlhDsaPreHash.sha256,
        params,
      ),
      isFalse,
    );
    expect(
      SlhDsa.hashVerify(
        publicKey,
        message,
        Uint8List(params.signatureBytes - 1),
        SlhDsaPreHash.sha256,
        params,
      ),
      isFalse,
    );
    expect(
      SlhDsa.hashVerify(
        publicKey,
        message,
        signature,
        SlhDsaPreHash.sha256,
        params,
        context: Uint8List(256),
      ),
      isFalse,
    );
  }, timeout: Timeout.none);

  test('SHA-2 verification is total for malformed untrusted inputs', () {
    final params = SlhDsaParams.sha2128f;
    expect(params.isSupported, isTrue);
    expect(
      SlhDsa.verify(
        Uint8List(params.publicKeyBytes),
        message,
        Uint8List(params.signatureBytes - 1),
        params,
      ),
      isFalse,
    );
  });
}

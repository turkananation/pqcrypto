import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

void main() {
  final levels = <String, KyberKem>{
    'ML-KEM-512': PqcKem.kyber512,
    'ML-KEM-768': PqcKem.kyber768,
    'ML-KEM-1024': PqcKem.kyber1024,
  };

  for (final entry in levels.entries) {
    group('${entry.key} input validation', () {
      final kem = entry.value;

      test('encapsulate rejects an invalid public key length', () {
        final (pk, _) = kem.generateKeyPair(_seed(64, 1));

        expect(
          () => kem.encapsulate(pk.sublist(0, pk.length - 1), _seed(32, 2)),
          throwsArgumentError,
        );
      });

      test(
        'encapsulate rejects public keys with non-canonical coefficients',
        () {
          final (pk, _) = kem.generateKeyPair(_seed(64, 3));
          final malformed = Uint8List.fromList(pk);

          // Set the first 12-bit coefficient to q, which is outside [0, q - 1].
          malformed[0] = 0x01;
          malformed[1] = (malformed[1] & 0xF0) | 0x0D;

          expect(
            () => kem.encapsulate(malformed, _seed(32, 4)),
            throwsArgumentError,
          );
        },
      );

      test('decapsulate rejects an invalid secret key length', () {
        final (_, sk) = kem.generateKeyPair(_seed(64, 5));
        final (ct, _) = kem.encapsulate(
          _publicKeyFromSecretKey(kem, sk),
          _seed(32, 6),
        );

        expect(
          () => kem.decapsulate(sk.sublist(0, sk.length - 1), ct),
          throwsArgumentError,
        );
      });

      test('decapsulate rejects a secret key with a bad public-key hash', () {
        final (_, sk) = kem.generateKeyPair(_seed(64, 7));
        final malformed = Uint8List.fromList(sk);
        final hOffset = 384 * kem.params.k + kem.params.publicKeyBytes;
        malformed[hOffset] ^= 0x01;
        final (ct, _) = kem.encapsulate(
          _publicKeyFromSecretKey(kem, sk),
          _seed(32, 8),
        );

        expect(() => kem.decapsulate(malformed, ct), throwsArgumentError);
      });

      test('decapsulate rejects an invalid ciphertext length', () {
        final (_, sk) = kem.generateKeyPair(_seed(64, 9));
        final (ct, _) = kem.encapsulate(
          _publicKeyFromSecretKey(kem, sk),
          _seed(32, 10),
        );

        expect(
          () => kem.decapsulate(sk, ct.sublist(0, ct.length - 1)),
          throwsArgumentError,
        );
      });
    });
  }
}

Uint8List _seed(int length, int start) {
  return Uint8List.fromList(List.generate(length, (i) => (start + i) & 0xFF));
}

Uint8List _publicKeyFromSecretKey(KyberKem kem, Uint8List sk) {
  final sBytes = 384 * kem.params.k;
  return sk.sublist(sBytes, sBytes + kem.params.publicKeyBytes);
}

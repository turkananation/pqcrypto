import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  group('NIST FIPS 203 Negative Testing (Implicit Rejection)', () {
    final variants = [
      ('Kyber-512', PqcKem.kyber512),
      ('Kyber-768', PqcKem.kyber768),
      ('Kyber-1024', PqcKem.kyber1024),
    ];

    for (final (name, kem) in variants) {
      test('$name implicitly rejects invalid ciphertext', () {
        final (pk, sk) = kem.generateKeyPair();
        final (ct, ss) = kem.encapsulate(pk);

        // 1. Decapsulate valid ciphertext -> success
        final ssRecov = kem.decapsulate(sk, ct);
        expect(ssRecov, equals(ss), reason: 'Valid ciphertext should succeed');

        // 2. Modify ciphertext (flip 1 bit)
        final ctInvalid = Uint8List.fromList(ct);
        ctInvalid[0] ^= 0x01;

        // 3. Decapsulate invalid ciphertext -> incorrect SS (but no crash)
        final ssInvalid = kem.decapsulate(sk, ctInvalid);
        expect(
          ssInvalid,
          isNot(equals(ss)),
          reason: 'Invalid ciphertext should not produce original SS',
        );
        expect(
          ssInvalid.length,
          equals(32),
          reason: 'Invalid SS should still be 32 bytes',
        );

        // 4. Consistency check (deterministic failure)
        final ssInvalid2 = kem.decapsulate(sk, ctInvalid);
        expect(
          ssInvalid2,
          equals(ssInvalid),
          reason: 'Implicit rejection should be deterministic',
        );

        // 5. Encapsulation check (re-running encrypt with same inputs)
        // We can't easily check derived ssInvalid match formula K_bar = J(z||c)
        // without exposing z or J. But standard behavior is handled by logic.
      });
    }
  });
}

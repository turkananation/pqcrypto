// test/kyber_test.dart
// test/kyber_test.dart
import 'package:test/test.dart';
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  group('Kyber KEM Round-Trip', () {
    final variants = [
      ('Kyber-512', PqcKem.kyber512),
      ('Kyber-768', PqcKem.kyber768),
      ('Kyber-1024', PqcKem.kyber1024),
    ];

    for (final (name, kem) in variants) {
      test('$name Encapsulate/Decapsulate matches', () {
        final (pk, sk) = kem.generateKeyPair();
        final (ct, ss1) = kem.encapsulate(pk);
        final ss2 = kem.decapsulate(sk, ct);

        expect(ss1, ss2);
        expect(ss1.length, 32); // 256-bit shared secret
      });
    }
  });
}

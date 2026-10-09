/// Reachability test for the public parameter tables.
///
/// ML-KEM's `KyberParams` and `KyberLevel` were not exported from
/// `package:pqcrypto/pqcrypto.dart`, while the ML-DSA and SLH-DSA equivalents
/// were. ML-KEM was therefore the only family whose derived sizes a caller could
/// not read, which forced anyone sizing an ML-KEM buffer to hardcode literals —
/// exactly the drift risk the exported tables exist to prevent.
///
/// This test fails to compile if the exports are removed, which is the
/// regression we care about.
library;

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

void main() {
  group('ML-KEM parameter tables are reachable from the barrel', () {
    test('KyberParams is constructible and derives FIPS 203 sizes', () {
      // FIPS 203 / Kyber reference sizes.
      const expectations = <KyberLevel, (int pk, int sk)>{
        KyberLevel.kem512: (800, 1632),
        KyberLevel.kem768: (1184, 2400),
        KyberLevel.kem1024: (1568, 3168),
      };

      for (final entry in expectations.entries) {
        final k = switch (entry.key) {
          KyberLevel.kem512 => 2,
          KyberLevel.kem768 => 3,
          KyberLevel.kem1024 => 4,
        };
        final params = KyberParams(
          k: k,
          eta1: 3,
          eta2: 2,
          du: switch (entry.key) {
            KyberLevel.kem512 => 10,
            KyberLevel.kem768 => 10,
            KyberLevel.kem1024 => 11,
          },
          dv: switch (entry.key) {
            KyberLevel.kem512 => 4,
            KyberLevel.kem768 => 4,
            KyberLevel.kem1024 => 5,
          },
        );

        expect(
          params.publicKeyBytes,
          entry.value.$1,
          reason: '${entry.key.name} publicKeyBytes',
        );
        expect(
          params.secretKeyBytes,
          entry.value.$2,
          reason: '${entry.key.name} secretKeyBytes',
        );
        expect(params.ciphertextBytes, greaterThan(0));
        expect(params.polyBytes, 384);
      }
    });

    test('the public tables agree with a real generated key', () {
      // Ties the declared sizes to actual output, so a parameters change that
      // is not reflected in the table fails here rather than in a downstream
      // buffer overflow.
      for (final kem in <KyberKem>[
        PqcKem.kyber512,
        PqcKem.kyber768,
        PqcKem.kyber1024,
      ]) {
        final (publicKey, secretKey) = kem.generateKeyPair();

        expect(
          publicKey.length,
          kem.params.publicKeyBytes,
          reason: '${kem.level.name} generated publicKey length',
        );
        expect(
          secretKey.length,
          kem.params.secretKeyBytes,
          reason: '${kem.level.name} generated secretKey length',
        );
      }
    });
  });

  group('all three families expose derived sizes from the barrel', () {
    test('ML-DSA, SLH-DSA and ML-KEM are all reachable', () {
      expect(
        DilithiumParams.get(DilithiumParameter.mlDsa65).publicKeyBytes,
        1952,
      );
      expect(SlhDsaParams.get(SlhDsaParameter.sha2128f).secretKeyBytes, 64);
      expect(
        KyberParams(k: 3, eta1: 3, eta2: 2, du: 10, dv: 4).publicKeyBytes,
        1184,
      );
    });
  });
}

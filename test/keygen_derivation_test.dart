import 'dart:typed_data';

import 'package:pointycastle/export.dart' show SHA3Digest;
import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqcrypto/src/algos/kyber/indcpa.dart';
import 'package:pqcrypto/src/common/shake.dart';
import 'package:test/test.dart';

/// Isolating unit tests for two ML-KEM keygen steps that were previously only
/// exercised transitively through the KAT corpus:
///
///  * E7: `(rho, sigma) = G(d || k)` — the parameter byte `k` is mixed into the
///    seed expansion (FIPS 203 domain separation, §5.1 / Algorithm 13).
///  * E8: matrix expansion uses `A[i][j] = SampleNTT(XOF(rho, col, row))` — i.e.
///    the XOF input after `rho` is `col` then `row`, and the matrix is therefore
///    not symmetric.
void main() {
  final levels = <KyberKem>[PqcKem.kyber512, PqcKem.kyber768, PqcKem.kyber1024];

  group('KeyGen seed expansion G(d || k) (E7)', () {
    test('rho equals the first 32 bytes of SHA3-512(d || k)', () {
      final d = _bytes(32, 1);
      for (final kem in levels) {
        // z occupies bytes 32..63 of the seed; it does not affect rho.
        final seed = Uint8List(64)..setAll(0, d);
        final (pk, _) = kem.generateKeyPair(seed);

        // rho is the trailing 32 bytes of the encoded public key.
        final rho = pk.sublist(pk.length - 32);

        final dk = Uint8List(33)
          ..setAll(0, d)
          ..[32] = kem.params.k;
        final expected = SHA3Digest(512).process(dk).sublist(0, 32);

        expect(rho, equals(expected), reason: 'k=${kem.params.k}');
      }
    });

    test('the domain-separation byte k makes rho differ across levels', () {
      // Same d for every level: rho can only differ because of the k byte.
      final d = _bytes(32, 7);
      final rhos = <Uint8List>[];
      for (final kem in levels) {
        final seed = Uint8List(64)..setAll(0, d);
        final (pk, _) = kem.generateKeyPair(seed);
        rhos.add(pk.sublist(pk.length - 32));
      }

      expect(rhos[0], isNot(equals(rhos[1])), reason: '512 vs 768');
      expect(rhos[1], isNot(equals(rhos[2])), reason: '768 vs 1024');
      expect(rhos[0], isNot(equals(rhos[2])), reason: '512 vs 1024');
    });
  });

  group('Matrix expansion XOF ordering (E8)', () {
    test('matrix entry XOF input is rho || col || row', () {
      final rho = _bytes(32, 0);
      const col = 1;
      const row = 2;

      final entry = Indcpa.genMatrixEntryForTest(rho, col, row);

      // Independently reconstruct the XOF input in col-then-row order.
      final input = Uint8List(34)
        ..setAll(0, rho)
        ..[32] = col
        ..[33] = row;
      final expected = Indcpa.sampleNttForTest(Shake128.shake(input, 672));

      expect(entry.coeffs, equals(expected.coeffs));
    });

    test('off-diagonal entries are order-sensitive (A is not symmetric)', () {
      final rho = _bytes(32, 0xA0);

      final a01 = Indcpa.genMatrixEntryForTest(rho, 0, 1);
      final a10 = Indcpa.genMatrixEntryForTest(rho, 1, 0);

      expect(a01.coeffs, isNot(equals(a10.coeffs)));
    });

    test('all sampled coefficients are reduced into [0, q-1]', () {
      final rho = _bytes(32, 0x5A);
      final entry = Indcpa.genMatrixEntryForTest(rho, 2, 3);
      for (final c in entry.coeffs) {
        expect(c, inInclusiveRange(0, 3328));
      }
    });
  });
}

/// Deterministic byte sequence `(start + i) & 0xFF`.
Uint8List _bytes(int length, int start) {
  return Uint8List.fromList(List.generate(length, (i) => (start + i) & 0xFF));
}

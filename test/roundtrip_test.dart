import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

/// End-to-end ML-KEM round-trips with **no `dart:io`**, so this runs under the
/// web compilers (`dart2js`/`dart2wasm`) as well as the VM.
///
/// The file-based KAT corpus ([test/kat_evaluator_test.dart]) is the strongest
/// conformance check, but it reads `.rsp` files and therefore only runs on the
/// VM. That left platform-specific arithmetic bugs in compression/serialization
/// invisible on the web — e.g. the dart2js 32-bit-shift defect in `Compress₁₀`
/// that corrupted ML-KEM-512/768 ciphertexts. This suite is the always-portable
/// gate that exercises keygen → encaps → decaps on every backend.
void main() {
  final levels = <String, KyberKem>{
    'ML-KEM-512': PqcKem.kyber512,
    'ML-KEM-768': PqcKem.kyber768,
    'ML-KEM-1024': PqcKem.kyber1024,
  };

  for (final entry in levels.entries) {
    final kem = entry.value;

    group(entry.key, () {
      test('keygen → encaps → decaps yields the same shared secret', () {
        for (var i = 0; i < 8; i++) {
          final seed = Uint8List(64);
          for (var j = 0; j < 64; j++) {
            seed[j] = (i * 64 + j) & 0xFF;
          }
          final (pk, sk) = kem.generateKeyPair(seed);
          final (ct, ssAlice) = kem.encapsulate(pk);
          final ssBob = kem.decapsulate(sk, ct);
          expect(ssBob, equals(ssAlice), reason: '${entry.key} iteration $i');
          expect(ssAlice, hasLength(32));
        }
      });

      test('tampered ciphertext implicitly rejects (no crash, differs)', () {
        final (pk, sk) = kem.generateKeyPair();
        final (ct, ssAlice) = kem.encapsulate(pk);
        final tampered = Uint8List.fromList(ct);
        tampered[0] ^= 0xFF;
        final ssReject = kem.decapsulate(sk, tampered);
        expect(ssReject, hasLength(32));
        expect(ssReject, isNot(equals(ssAlice)));
      });
    });
  }
}

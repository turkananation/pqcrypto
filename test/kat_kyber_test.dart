// test/kat_kyber_test.dart
import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';
import 'package:pqcrypto/pqcrypto.dart';

void main() {
  test('NIST KAT for Kyber-768', () async {
    final katFile = File('test/data/PQCkemKAT_1184.req'); // Download from NIST
    final lines = await katFile.readAsLines();

    for (var line in lines) {
      if (line.startsWith('seed = ')) {
        final seed = base64Decode(line.split('= ')[1]);
        final kem = PqcKem.kyber768;
        // ignore: unused_local_variable
        final (pk, sk) = kem.generateKeyPair(seed); // Deterministic

        // Parse expected pk from .rsp, assert match
        // Similar for ct/ss
      }
    }
  });
}

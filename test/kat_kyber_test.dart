// test/kat_kyber_test.dart
// Note: Comprehensive KAT testing is done in kat_evaluator.dart
// This test just verifies the KAT files are present
import 'dart:io';
import 'package:test/test.dart';

void main() {
  test('NIST KAT files exist', () {
    final files = [
      'test/data/PQCkemKAT_1184.rsp', // Kyber-768 (old format)
      'test/data/kat_MLKEM_512.rsp', // ML-KEM-512
      'test/data/kat_MLKEM_768.rsp', // ML-KEM-768
      'test/data/kat_MLKEM_1024.rsp', // ML-KEM-1024
    ];

    for (final file in files) {
      expect(
        File(file).existsSync(),
        isTrue,
        reason: '$file should exist for KAT testing',
      );
    }
  });
}

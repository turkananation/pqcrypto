@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/keccak.dart';
import 'package:test/test.dart';

const _corpusPath = 'test/data/FIPS202/byte_aligned_vectors.json';

Uint8List _hexToBytes(String value) {
  if (value.isEmpty) return Uint8List(0);
  if (value.length.isOdd) throw FormatException('odd-length hex');
  return Uint8List.fromList(<int>[
    for (var i = 0; i < value.length; i += 2)
      int.parse(value.substring(i, i + 2), radix: 16),
  ]);
}

Uint8List _evaluate(String function, Uint8List message, int outputLength) =>
    switch (function) {
      'SHA3-224' => sha3224(message),
      'SHA3-256' => sha3256(message),
      'SHA3-384' => sha3384(message),
      'SHA3-512' => sha3512(message),
      'SHAKE128' => shake128(message, outputLength),
      'SHAKE256' => shake256(message, outputLength),
      _ => throw FormatException('unknown FIPS 202 function: $function'),
    };

void main() {
  final corpus =
      jsonDecode(File(_corpusPath).readAsStringSync()) as Map<String, dynamic>;
  final vectors = corpus['vectors']! as List<dynamic>;

  test('corpus metadata and provenance are complete', () {
    expect(corpus['schema'], 'pqcrypto-fips202-byte-v1');
    expect(corpus['source'], 'NIST FIPS 202 example values');
    expect(corpus['retrieved'], matches(RegExp(r'^\d{4}-\d{2}-\d{2}$')));
    expect(vectors, hasLength(12));

    for (final raw in vectors) {
      final vector = raw as Map<String, dynamic>;
      expect(
        vector['sourcePdf'],
        startsWith('https://csrc.nist.gov/'),
        reason: vector['function'] as String,
      );
      expect(
        vector['sourceSha256'],
        matches(RegExp(r'^[0-9a-f]{64}$')),
        reason: vector['function'] as String,
      );
    }
  });

  for (final raw in vectors) {
    final vector = raw as Map<String, dynamic>;
    final function = vector['function']! as String;
    final messageHex = vector['messageHex']! as String;
    final messageRepeats = vector['messageRepeats'] as int? ?? 1;
    final expected = _hexToBytes(vector['outputHex']! as String);

    test('$function message $messageHex x $messageRepeats', () {
      final unit = _hexToBytes(messageHex);
      final message = Uint8List(unit.length * messageRepeats);
      for (var i = 0; i < messageRepeats; i++) {
        message.setRange(i * unit.length, (i + 1) * unit.length, unit);
      }
      expect(_evaluate(function, message, expected.length), equals(expected));
    });
  }
}

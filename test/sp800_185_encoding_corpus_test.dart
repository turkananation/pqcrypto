@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

void main() {
  final corpus =
      jsonDecode(File('test/data/SP800185/examples.json').readAsStringSync())
          as Map<String, dynamic>;
  final manifest =
      jsonDecode(File('test/data/SP800185/manifest.json').readAsStringSync())
          as Map<String, dynamic>;
  final samples = corpus['samples']! as List<dynamic>;

  Uint8List hex(String value) {
    if (value.isEmpty) return Uint8List(0);
    return Uint8List.fromList(<int>[
      for (var i = 0; i < value.length; i += 2)
        int.parse(value.substring(i, i + 2), radix: 16),
    ]);
  }

  Uint8List concat(Uint8List left, Uint8List right) {
    final out = Uint8List(left.length + right.length);
    out.setRange(0, left.length, left);
    out.setRange(left.length, out.length, right);
    return out;
  }

  Uint8List functionName(String function) => switch (function) {
    'cSHAKE' => Uint8List(0),
    'KMAC' || 'KMACXOF' => Uint8List.fromList('KMAC'.codeUnits),
    'TupleHash' || 'TupleHashXOF' => Uint8List.fromList('TupleHash'.codeUnits),
    'ParallelHash' ||
    'ParallelHashXOF' => Uint8List.fromList('ParallelHash'.codeUnits),
    _ => throw FormatException(function),
  };

  test('the SP 800-185 manifest covers the official sample PDFs', () {
    final files = manifest['files']! as List<dynamic>;
    expect(files, hasLength(7));
    expect(samples, hasLength(40));
    final digests = <String, String>{
      for (final raw in files)
        (raw as Map<String, dynamic>)['file']! as String:
            raw['sha256']! as String,
    };
    expect(
      digests.keys,
      containsAll(<String>[
        'cSHAKE_samples.pdf',
        'KMAC_samples.pdf',
        'KMACXOF_samples.pdf',
        'TupleHash_samples.pdf',
        'TupleHashXOF_samples.pdf',
        'ParallelHash_samples.pdf',
        'ParallelHashXOF_samples.pdf',
      ]),
    );
    for (final raw in samples) {
      final sample = raw as Map<String, dynamic>;
      final source = sample['sourcePdf']! as String;
      final name = source.split('/').last;
      expect(digests[name], sample['sourceSha256']);
      expect(sample['sourceSha256'], matches(RegExp(r'^[0-9a-f]{64}$')));
    }
  });

  for (final raw in samples) {
    final sample = raw as Map<String, dynamic>;
    final function = sample['function']! as String;
    final number = sample['sample']! as int;
    final security = sample['securityBits']! as int;

    test('$function sample $number at $security bits', () {
      final rate = sample['rateBytes']! as int;
      expect(rate, security == 128 ? 168 : 136);
      final customization = Uint8List.fromList(
        (sample['customization']! as String).codeUnits,
      );
      final encodedName = encodeString(functionName(function));
      final encodedCustomization = encodeString(customization);
      expect(encodedName, hex(sample['encodedNHex']! as String));
      expect(encodedCustomization, hex(sample['encodedSHex']! as String));
      expect(
        bytepad(concat(encodedName, encodedCustomization), rate),
        hex(sample['bytepadHex']! as String),
      );

      final keyHex = sample['keyHex'] as String?;
      if (keyHex != null) {
        final key = hex(keyHex);
        expect(encodeString(key), hex(sample['encodedKHex']! as String));
        expect(
          bytepad(encodeString(key), rate),
          hex(sample['keyBytepadHex']! as String),
        );
      }

      final rightHex = sample['rightEncodedOutputLengthHex'] as String?;
      if (rightHex != null) {
        final length = function.endsWith('XOF')
            ? 0
            : sample['outputBitLength']! as int;
        expect(rightEncode(length), hex(rightHex));
      }

      final encodedOutput = sample['encodedOutputLengthHex'] as String?;
      if (encodedOutput != null) {
        final length = function.endsWith('XOF')
            ? 0
            : sample['outputBitLength']! as int;
        expect(rightEncode(length), hex(encodedOutput));
      }

      final blockSize = sample['blockSize'] as int?;
      if (blockSize != null) {
        expect(leftEncode(blockSize), hex(sample['encodedBHex']! as String));
        final dataBytes = (sample['dataBitLength']! as int) ~/ 8;
        final blocks = (dataBytes + blockSize - 1) ~/ blockSize;
        expect(
          rightEncode(blocks),
          hex(sample['encodedBlockCountHex']! as String),
        );
      }

      final tuples = sample['tuplesHex'] as List<dynamic>?;
      if (tuples != null) {
        final encoded = sample['encodedTuplesHex']! as List<dynamic>;
        expect(encoded, hasLength(tuples.length));
        for (var i = 0; i < tuples.length; i++) {
          expect(
            encodeString(hex(tuples[i]! as String)),
            hex(encoded[i]! as String),
          );
        }
      }
    });
  }
}

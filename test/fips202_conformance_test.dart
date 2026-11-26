@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/keccak.dart';
import 'package:test/test.dart';

void main() {
  const sha3Suffix = <int>[0, 1];
  const shakeSuffix = <int>[1, 1, 1, 1];

  final examples =
      jsonDecode(File('test/data/FIPS202/all_examples.json').readAsStringSync())
          as Map<String, dynamic>;
  final truncation =
      jsonDecode(
            File('test/data/FIPS202/shake_truncation.json').readAsStringSync(),
          )
          as Map<String, dynamic>;
  final manifest =
      jsonDecode(File('test/data/FIPS202/manifest.json').readAsStringSync())
          as Map<String, dynamic>;
  final vectors = examples['vectors']! as List<dynamic>;
  final truncated = truncation['vectors']! as List<dynamic>;

  Uint8List hex(String value) {
    if (value.isEmpty) return Uint8List(0);
    return Uint8List.fromList(<int>[
      for (var i = 0; i < value.length; i += 2)
        int.parse(value.substring(i, i + 2), radix: 16),
    ]);
  }

  List<int> messageBits(String bits) => <int>[
    for (final unit in bits.codeUnits)
      switch (unit) {
        0x30 => 0,
        0x31 => 1,
        _ => throw FormatException('message bit is not 0 or 1'),
      },
  ];

  ({int rateBytes, List<int> suffix, int? digestBytes}) profile(
    String function,
  ) => switch (function) {
    'SHA3-224' => (rateBytes: 144, suffix: sha3Suffix, digestBytes: 28),
    'SHA3-256' => (rateBytes: 136, suffix: sha3Suffix, digestBytes: 32),
    'SHA3-384' => (rateBytes: 104, suffix: sha3Suffix, digestBytes: 48),
    'SHA3-512' => (rateBytes: 72, suffix: sha3Suffix, digestBytes: 64),
    'SHAKE128' => (rateBytes: 168, suffix: shakeSuffix, digestBytes: null),
    'SHAKE256' => (rateBytes: 136, suffix: shakeSuffix, digestBytes: null),
    _ => throw FormatException(function),
  };

  Uint8List evaluateBytes(
    String function,
    Uint8List message,
    int outputBytes,
  ) => switch (function) {
    'SHA3-224' => sha3224(message),
    'SHA3-256' => sha3256(message),
    'SHA3-384' => sha3384(message),
    'SHA3-512' => sha3512(message),
    'SHAKE128' => shake128(message, outputBytes),
    'SHAKE256' => shake256(message, outputBytes),
    _ => throw FormatException(function),
  };

  test('manifest provenance covers every official message length', () {
    final files = manifest['files']! as List<dynamic>;
    expect(files, hasLength(37));
    expect(vectors, hasLength(36));
    expect(truncated, hasLength(9));
    final digests = <String, String>{
      for (final raw in files)
        (raw as Map<String, dynamic>)['file']! as String:
            raw['sha256']! as String,
    };
    final covered = <String, Set<int>>{};
    for (final raw in vectors) {
      final vector = raw as Map<String, dynamic>;
      final function = vector['function']! as String;
      final length = vector['messageBitLength']! as int;
      covered.putIfAbsent(function, () => <int>{}).add(length);
      final source = vector['sourcePdf']! as String;
      expect(digests[source.split('/').last], vector['sourceSha256']);
      expect(
        (vector['messageBits']! as String).length,
        length,
        reason: '$function $length',
      );
    }
    for (final function in <String>[
      'SHA3-224',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'SHAKE128',
      'SHAKE256',
    ]) {
      expect(covered[function], <int>{0, 5, 30, 1600, 1605, 1630});
    }
  });

  for (final raw in vectors) {
    final vector = raw as Map<String, dynamic>;
    final function = vector['function']! as String;
    final length = vector['messageBitLength']! as int;
    test('$function $length-bit NIST example', () {
      final parameters = profile(function);
      final expected = hex(vector['outputHex']! as String);
      final bits = messageBits(vector['messageBits']! as String);
      expect(bits.where((bit) => bit != 0 && bit != 1), isEmpty);
      final actual = fips202AbsorbBits(
        messageBits: bits,
        rateBytes: parameters.rateBytes,
        suffixBits: parameters.suffix,
        outputBytes: expected.length,
      );
      expect(actual, expected);

      if (length % 8 == 0) {
        final message = Uint8List(length >> 3);
        for (var i = 0; i < bits.length; i++) {
          if (bits[i] != 0) message[i >> 3] |= 1 << (i & 7);
        }
        expect(
          evaluateBytes(function, message, expected.length),
          expected.sublist(0, parameters.digestBytes ?? expected.length),
        );
      }
    });
  }

  test('SHAKE128 empty-message truncation matches the NIST hex form', () {
    final stream = shake128(Uint8List(0), 512);
    expect(
      fips202AbsorbBits(
        messageBits: const <int>[],
        rateBytes: 168,
        suffixBits: shakeSuffix,
        outputBytes: 512,
      ),
      stream,
    );
    for (final raw in truncated) {
      final vector = raw as Map<String, dynamic>;
      final bitLength = vector['outputBitLength']! as int;
      final byteLength = (bitLength + 7) >> 3;
      final presented = Uint8List.sublistView(stream, 0, byteLength);
      final out = Uint8List.fromList(presented);
      final remainder = bitLength & 7;
      if (remainder != 0) {
        out[byteLength - 1] &= (1 << remainder) - 1;
      }
      expect(
        out,
        hex(vector['outputHex']! as String),
        reason: '$bitLength bits',
      );
    }
  });
}

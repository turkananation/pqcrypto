import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqcrypto/src/common/keccak.dart' show fips202AbsorbBits;
import 'package:test/test.dart';

import 'fips202_bit_string.dart';

const _sha3Suffix = <int>[0, 1];
const _shakeSuffix = <int>[1, 1, 1, 1];

const _functions = <String>[
  'SHA3-224',
  'SHA3-256',
  'SHA3-384',
  'SHA3-512',
  'SHAKE128',
  'SHAKE256',
];

const _messageBitLengths = <int>[0, 5, 30, 1600, 1605, 1630];

/// Registers the full official FIPS 202 example corpus.
///
/// [examplesJson] is `all_examples.json`. [truncationJson] is
/// `shake_truncation.json`. Callers pass the decoded checked-in objects.
/// The same cases run from a file on the VM and from the generated library
/// constants on Chrome and dart2wasm.
void registerFips202OfficialCorpus({
  required Map<String, dynamic> examplesJson,
  required Map<String, dynamic> truncationJson,
}) {
  final vectors = examplesJson['vectors']! as List<dynamic>;
  final truncated = truncationJson['vectors']! as List<dynamic>;

  test('official corpus covers every function and message length', () {
    expect(examplesJson['schema'], 'pqcrypto-fips202-examples-v1');
    expect(examplesJson['source'], 'NIST FIPS 202 example values');
    expect(truncationJson['schema'], 'pqcrypto-fips202-shake-truncation-v1');
    expect(vectors, hasLength(_functions.length * _messageBitLengths.length));
    expect(truncated, hasLength(9));

    final seen = <String>{};
    for (final raw in vectors) {
      final vector = raw as Map<String, dynamic>;
      final function = vector['function']! as String;
      final length = vector['messageBitLength']! as int;
      expect(_functions, contains(function), reason: function);
      expect(_messageBitLengths, contains(length), reason: function);
      expect(
        (vector['messageBits']! as String).length,
        length,
        reason: '$function $length',
      );
      expect(
        seen.add('$function:$length'),
        isTrue,
        reason: 'duplicate $function $length',
      );
      expect(vector['sourcePdf'], startsWith('https://csrc.nist.gov/'));
      expect(vector['sourceSha256'], matches(RegExp(r'^[0-9a-f]{64}$')));
    }
    expect(seen, hasLength(36));

    final outputLengths = <int>[];
    for (final raw in truncated) {
      final vector = raw as Map<String, dynamic>;
      expect(vector['function'], 'SHAKE128');
      expect(vector['messageBitLength'], 0);
      expect(vector['messageBits'], isEmpty);
      outputLengths.add(vector['outputBitLength']! as int);
      expect(vector['sourcePdf'], endsWith('/ShakeTruncation.pdf'));
      expect(
        vector['sourceSha256'],
        'f9a906d5942892990e1ea39e2f8ef589cf8d7d1e27b4d74af807f2f8a75db93a',
      );
    }
    expect(outputLengths, <int>[
      4096,
      4095,
      4094,
      4093,
      4092,
      4091,
      4090,
      4089,
      4088,
    ]);
  });

  for (final raw in vectors) {
    final vector = raw as Map<String, dynamic>;
    final function = vector['function']! as String;
    final length = vector['messageBitLength']! as int;
    test('$function $length-bit NIST example', () {
      final parameters = _profile(function);
      final expected = _hexToBytes(vector['outputHex']! as String);
      final message = BitString.fromAbsorptionBits(
        vector['messageBits']! as String,
      );
      expect(message.bitLength, length);
      expect(message.absorptionBits(), hasLength(length));

      if (length == 1600) {
        expect(message.bytes, hasLength(200));
        expect(message.bytes, everyElement(0xa3));
      }

      final actual = fips202AbsorbBits(
        messageBits: message.absorptionBits(),
        rateBytes: parameters.rateBytes,
        suffixBits: parameters.suffix,
        outputBytes: expected.length,
      );
      expect(actual, expected);

      if (length % 8 == 0) {
        if (parameters.digestBytes != null) {
          expect(expected.length, parameters.digestBytes);
        }
        expect(
          _evaluateBytes(function, message.bytes, expected.length),
          expected,
        );
      }
    });
  }

  test('SHAKE128 empty-message truncation matches the NIST hex form', () {
    final empty = BitString.fromAbsorptionBits('');
    expect(empty.bitLength, 0);
    expect(empty.bytes, isEmpty);
    final stream = shake128(empty.bytes, 512);
    expect(
      fips202AbsorbBits(
        messageBits: empty.absorptionBits(),
        rateBytes: 168,
        suffixBits: _shakeSuffix,
        outputBytes: 512,
      ),
      stream,
    );
    for (final raw in truncated) {
      final vector = raw as Map<String, dynamic>;
      final bitLength = vector['outputBitLength']! as int;
      final byteLength = (bitLength + 7) >> 3;
      final masked = Uint8List.fromList(
        Uint8List.sublistView(stream, 0, byteLength),
      );
      final remainder = bitLength & 7;
      if (remainder != 0) {
        masked[byteLength - 1] &= (1 << remainder) - 1;
      }
      final presented = BitString(masked, bitLength);
      expect(presented.bitLength, bitLength);
      expect(
        presented.bytes,
        _hexToBytes(vector['outputHex']! as String),
        reason: '$bitLength bits',
      );
    }
  });
}

({int rateBytes, List<int> suffix, int? digestBytes}) _profile(
  String function,
) => switch (function) {
  'SHA3-224' => (rateBytes: 144, suffix: _sha3Suffix, digestBytes: 28),
  'SHA3-256' => (rateBytes: 136, suffix: _sha3Suffix, digestBytes: 32),
  'SHA3-384' => (rateBytes: 104, suffix: _sha3Suffix, digestBytes: 48),
  'SHA3-512' => (rateBytes: 72, suffix: _sha3Suffix, digestBytes: 64),
  'SHAKE128' => (rateBytes: 168, suffix: _shakeSuffix, digestBytes: null),
  'SHAKE256' => (rateBytes: 136, suffix: _shakeSuffix, digestBytes: null),
  _ => throw FormatException(function),
};

Uint8List _evaluateBytes(String function, Uint8List message, int outputBytes) =>
    switch (function) {
      'SHA3-224' => sha3224(message),
      'SHA3-256' => sha3256(message),
      'SHA3-384' => sha3384(message),
      'SHA3-512' => sha3512(message),
      'SHAKE128' => shake128(message, outputBytes),
      'SHAKE256' => shake256(message, outputBytes),
      _ => throw FormatException(function),
    };

Uint8List _hexToBytes(String value) {
  if (value.isEmpty) return Uint8List(0);
  if (value.length.isOdd) throw FormatException('odd-length hex');
  return Uint8List.fromList(<int>[
    for (var i = 0; i < value.length; i += 2)
      int.parse(value.substring(i, i + 2), radix: 16),
  ]);
}

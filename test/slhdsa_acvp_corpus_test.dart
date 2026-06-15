@TestOn('vm') // Reads the checked-in ACVP JSON corpus with dart:io.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/sha2.dart';
import 'package:test/test.dart';

const String _corpusRoot = 'test/data/SLHDSA';

const Map<String, String> _expectedSha256 = <String, String>{
  'SLH-DSA-keyGen-FIPS205/prompt.json':
      'bce170976f257ee3dfc8c54ea46722ccb553539847daa6d8048f0216cc28b51c',
  'SLH-DSA-keyGen-FIPS205/expectedResults.json':
      'f35f74b6676d6b369c87e88c36698f28c14d5929d31e507d910288c69258afee',
  'SLH-DSA-sigGen-FIPS205/prompt.json':
      'afa673eacdf0aec53512a159159b7632684adfcd0d88f8640a7f6f5796aacdc8',
  'SLH-DSA-sigGen-FIPS205/expectedResults.json':
      '71e8e0f7e4b0cfd1747314299204d9d4d50968d200a4ae873921eaa7aabeaad1',
  'SLH-DSA-sigVer-FIPS205/prompt.json':
      '4e7beb1233e47baa0acdd36417c66c45811aa40a4e32ffdb1a35d93b13b289fb',
  'SLH-DSA-sigVer-FIPS205/expectedResults.json':
      '259f5e2a0665de0adc0fefa45b5db3a2a6ed13c3c44d14bdaf64a80aee12c687',
};

const Map<String, ({int groups, int tests})> _expectedCounts =
    <String, ({int groups, int tests})>{
      'keyGen': (groups: 12, tests: 120),
      'sigGen': (groups: 72, tests: 624),
      'sigVer': (groups: 36, tests: 504),
    };

const Set<String> _expectedParameterSets = <String>{
  'SLH-DSA-SHA2-128s',
  'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHA2-192s',
  'SLH-DSA-SHA2-192f',
  'SLH-DSA-SHA2-256s',
  'SLH-DSA-SHA2-256f',
  'SLH-DSA-SHAKE-128s',
  'SLH-DSA-SHAKE-128f',
  'SLH-DSA-SHAKE-192s',
  'SLH-DSA-SHAKE-192f',
  'SLH-DSA-SHAKE-256s',
  'SLH-DSA-SHAKE-256f',
};

Map<String, dynamic> _load(String relativePath) {
  final file = File('$_corpusRoot/$relativePath');
  return jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
}

List<Map<String, dynamic>> _groups(Map<String, dynamic> vectorSet) {
  return (vectorSet['testGroups'] as List<dynamic>)
      .cast<Map<String, dynamic>>();
}

List<Map<String, dynamic>> _tests(Map<String, dynamic> group) {
  return (group['tests'] as List<dynamic>).cast<Map<String, dynamic>>();
}

String _hex(Uint8List bytes) {
  final output = StringBuffer();
  for (final byte in bytes) {
    output.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return output.toString();
}

void main() {
  test('official ACVP files match the pinned NIST SHA-256 digests', () {
    for (final entry in _expectedSha256.entries) {
      final file = File('$_corpusRoot/${entry.key}');
      expect(file.existsSync(), isTrue, reason: entry.key);
      expect(
        _hex(sha256(file.readAsBytesSync())),
        entry.value,
        reason: entry.key,
      );
    }
  });

  for (final mode in _expectedCounts.keys) {
    final directory = 'SLH-DSA-$mode-FIPS205';

    test('$mode prompt and results have complete paired ACVP structure', () {
      final prompt = _load('$directory/prompt.json');
      final results = _load('$directory/expectedResults.json');
      final promptGroups = _groups(prompt);
      final resultGroups = _groups(results);
      final expected = _expectedCounts[mode]!;

      for (final vectorSet in <Map<String, dynamic>>[prompt, results]) {
        expect(vectorSet['algorithm'], 'SLH-DSA');
        expect(vectorSet['mode'], mode);
        expect(vectorSet['revision'], 'FIPS205');
        expect(vectorSet['isSample'], isTrue);
      }

      expect(promptGroups, hasLength(expected.groups));
      expect(resultGroups, hasLength(expected.groups));
      expect(
        promptGroups.fold<int>(0, (sum, group) => sum + _tests(group).length),
        expected.tests,
      );
      expect(
        resultGroups.fold<int>(0, (sum, group) => sum + _tests(group).length),
        expected.tests,
      );

      final parameterSets = <String>{
        for (final group in promptGroups) group['parameterSet'] as String,
      };
      expect(parameterSets, _expectedParameterSets);

      for (var groupIndex = 0; groupIndex < promptGroups.length; groupIndex++) {
        final promptGroup = promptGroups[groupIndex];
        final resultGroup = resultGroups[groupIndex];
        expect(resultGroup['tgId'], promptGroup['tgId']);
        expect(
          _tests(resultGroup).map((test) => test['tcId']),
          orderedEquals(_tests(promptGroup).map((test) => test['tcId'])),
          reason: '$mode tgId ${promptGroup['tgId']}',
        );
      }
    });
  }

  test('sigGen covers internal, external pure/preHash, and both modes', () {
    final groups = _groups(_load('SLH-DSA-sigGen-FIPS205/prompt.json'));

    expect(groups.map((group) => group['signatureInterface']).toSet(), <String>{
      'internal',
      'external',
    });
    expect(
      groups
          .where((group) => group['signatureInterface'] == 'external')
          .map((group) => group['preHash'])
          .toSet(),
      <String>{'pure', 'preHash'},
    );
    expect(groups.map((group) => group['deterministic']).toSet(), <bool>{
      true,
      false,
    });
  });

  test('sigVer contains positive and negative expected results', () {
    final groups = _groups(
      _load('SLH-DSA-sigVer-FIPS205/expectedResults.json'),
    );
    final outcomes = <bool>{
      for (final group in groups)
        for (final test in _tests(group)) test['testPassed'] as bool,
    };
    expect(outcomes, <bool>{true, false});
  });
}

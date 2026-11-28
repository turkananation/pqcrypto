/// Byte integrity and prompt/result pairing for the ACVP files under
/// `test/data/ACVP`. Does not execute the algorithms.
@TestOn('vm') // Reads the checked-in ACVP JSON corpus with dart:io.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/sha2.dart';
import 'package:test/test.dart';

const String _corpusRoot = 'test/data/ACVP';

const Map<String, String> _expectedSha256 = <String, String>{
  'cSHAKE-128-1.0/prompt.json':
      '602505b60b9ddeae518887f925c527947af1712a12c37cfc6a4d014a36f78e03',
  'cSHAKE-128-1.0/expectedResults.json':
      'be71953163ecfae0519ac84bc1851b4f474dd1cff2b587c0bde7c98fae2f5405',
  'cSHAKE-256-1.0/prompt.json':
      'cf49b691b462032bff9c517f17981b3ec1f8eb5d70872cc5c14182930b4bab34',
  'cSHAKE-256-1.0/expectedResults.json':
      'decd4148c906a9a8b4084f7c1f1a06f27330535ebb7a7f13282c95a4134c35e1',
  'KMAC-128-1.0/prompt.json':
      'd7e4edd54d534c51a162eae940213a3d47cf58ad61a1db6b080b03c482273d33',
  'KMAC-128-1.0/expectedResults.json':
      '06e1be237f92995054c475c35b5b11c5637df699563997154c17e4b92f7696bd',
  'KMAC-256-1.0/prompt.json':
      '5b4b3c21edac5aae5a52dffe49ddba5576e90fb584c0e23fdedda5e51ec11548',
  'KMAC-256-1.0/expectedResults.json':
      '7a54cc6e3899453156acbd73887262d5b1adb97939eba68ede3d44876da87881',
  'TupleHash-128-1.0/prompt.json':
      'a8f4d53d02a17eccca75a04123a65d129fdf84ea4c25552cd5ceac456f021dfe',
  'TupleHash-128-1.0/expectedResults.json':
      'c50486f527888605973d747f59399a14562d11c2513a377510a9791ace459a86',
  'TupleHash-256-1.0/prompt.json':
      '64ff03ca1e8465c7e6538bd905d9fedb12b391a9bb2a54b8e6db79ed5d1ddd1d',
  'TupleHash-256-1.0/expectedResults.json':
      '6fb188e85333ec3a2e292b8c521a0b9b793c6e27b126710adfd6121ccb26c5b1',
  'ParallelHash-128-1.0/prompt.json':
      '9e65ae062d1ab03d9a349c060d0088d517308cd3859ad180b50f0e86639d2a03',
  'ParallelHash-128-1.0/expectedResults.json':
      '7587f20c11b4f3287fb875d19b804e39561c11a480e9ce2932d30410987125ee',
  'ParallelHash-256-1.0/prompt.json':
      '4b3d70f60ea62fe575e64fd85bdcc9dbe2b3d811eb9fd93fc9a511b3f304015d',
  'ParallelHash-256-1.0/expectedResults.json':
      'fa30a42f67143f275c45e4b4ea541e6bab5975727a0857192f40a8948cb56bc6',
  'ML-KEM-keyGen-FIPS203/prompt.json':
      '3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523',
  'ML-KEM-keyGen-FIPS203/expectedResults.json':
      'a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4',
  'ML-KEM-encapDecap-FIPS203/prompt.json':
      '998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91',
  'ML-KEM-encapDecap-FIPS203/expectedResults.json':
      '9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf',
  'ML-DSA-keyGen-FIPS204/prompt.json':
      '43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef',
  'ML-DSA-keyGen-FIPS204/expectedResults.json':
      '361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df',
  'ML-DSA-sigGen-FIPS204/prompt.json':
      '447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d',
  'ML-DSA-sigGen-FIPS204/expectedResults.json':
      '228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb',
  'ML-DSA-sigVer-FIPS204/prompt.json':
      'e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e',
  'ML-DSA-sigVer-FIPS204/expectedResults.json':
      'e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6',
};

const List<_Set> _sets = <_Set>[
  _Set(
    directory: 'cSHAKE-128-1.0',
    algorithm: 'cSHAKE-128',
    revision: '1.0',
    mode: null,
    isSample: true,
    vsId: 0,
    groups: 2,
    tests: 101,
  ),
  _Set(
    directory: 'cSHAKE-256-1.0',
    algorithm: 'cSHAKE-256',
    revision: '1.0',
    mode: null,
    isSample: true,
    vsId: 0,
    groups: 2,
    tests: 101,
  ),
  _Set(
    directory: 'KMAC-128-1.0',
    algorithm: 'KMAC-128',
    revision: '1.0',
    mode: null,
    isSample: false,
    vsId: 0,
    groups: 8,
    tests: 800,
  ),
  _Set(
    directory: 'KMAC-256-1.0',
    algorithm: 'KMAC-256',
    revision: '1.0',
    mode: null,
    isSample: false,
    vsId: 0,
    groups: 8,
    tests: 800,
  ),
  _Set(
    directory: 'TupleHash-128-1.0',
    algorithm: 'TupleHash-128',
    revision: '1.0',
    mode: null,
    isSample: true,
    vsId: 0,
    groups: 4,
    tests: 202,
  ),
  _Set(
    directory: 'TupleHash-256-1.0',
    algorithm: 'TupleHash-256',
    revision: '1.0',
    mode: null,
    isSample: true,
    vsId: 0,
    groups: 4,
    tests: 202,
  ),
  _Set(
    directory: 'ParallelHash-128-1.0',
    algorithm: 'ParallelHash-128',
    revision: '1.0',
    mode: null,
    isSample: true,
    vsId: 0,
    groups: 4,
    tests: 202,
  ),
  _Set(
    directory: 'ParallelHash-256-1.0',
    algorithm: 'ParallelHash-256',
    revision: '1.0',
    mode: null,
    isSample: true,
    vsId: 0,
    groups: 4,
    tests: 202,
  ),
  _Set(
    directory: 'ML-KEM-keyGen-FIPS203',
    algorithm: 'ML-KEM',
    revision: 'FIPS203',
    mode: 'keyGen',
    isSample: false,
    vsId: 42,
    groups: 3,
    tests: 75,
  ),
  _Set(
    directory: 'ML-KEM-encapDecap-FIPS203',
    algorithm: 'ML-KEM',
    revision: 'FIPS203',
    mode: 'encapDecap',
    isSample: true,
    vsId: 42,
    groups: 12,
    tests: 165,
  ),
  _Set(
    directory: 'ML-DSA-keyGen-FIPS204',
    algorithm: 'ML-DSA',
    revision: 'FIPS204',
    mode: 'keyGen',
    isSample: false,
    vsId: 42,
    groups: 3,
    tests: 75,
  ),
  _Set(
    directory: 'ML-DSA-sigGen-FIPS204',
    algorithm: 'ML-DSA',
    revision: 'FIPS204',
    mode: 'sigGen',
    isSample: false,
    vsId: 42,
    groups: 24,
    tests: 360,
  ),
  _Set(
    directory: 'ML-DSA-sigVer-FIPS204',
    algorithm: 'ML-DSA',
    revision: 'FIPS204',
    mode: 'sigVer',
    isSample: false,
    vsId: 42,
    groups: 12,
    tests: 180,
  ),
];

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
    expect(_expectedSha256, hasLength(26));
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

  for (final spec in _sets) {
    test('${spec.directory} prompt and results stay paired', () {
      final prompt = _load('${spec.directory}/prompt.json');
      final results = _load('${spec.directory}/expectedResults.json');
      for (final vectorSet in <Map<String, dynamic>>[prompt, results]) {
        expect(vectorSet['algorithm'], spec.algorithm);
        expect(vectorSet['revision'], spec.revision);
        expect(vectorSet['mode'], spec.mode);
        expect(vectorSet['isSample'], spec.isSample);
        expect(vectorSet['vsId'], spec.vsId);
      }
      final promptGroups = _groups(prompt);
      final resultGroups = _groups(results);
      expect(promptGroups, hasLength(spec.groups));
      expect(resultGroups, hasLength(spec.groups));
      expect(
        promptGroups.fold<int>(0, (sum, group) => sum + _tests(group).length),
        spec.tests,
      );
      expect(
        resultGroups.fold<int>(0, (sum, group) => sum + _tests(group).length),
        spec.tests,
      );
      for (var i = 0; i < promptGroups.length; i++) {
        expect(resultGroups[i]['tgId'], promptGroups[i]['tgId']);
        expect(
          _tests(resultGroups[i]).map((test) => test['tcId']),
          orderedEquals(_tests(promptGroups[i]).map((test) => test['tcId'])),
          reason: '${spec.directory} tgId ${promptGroups[i]['tgId']}',
        );
      }
    });
  }
}

class _Set {
  const _Set({
    required this.directory,
    required this.algorithm,
    required this.revision,
    required this.mode,
    required this.isSample,
    required this.vsId,
    required this.groups,
    required this.tests,
  });

  final String directory;
  final String algorithm;
  final String revision;
  final String? mode;
  final bool isSample;
  final int vsId;
  final int groups;
  final int tests;
}

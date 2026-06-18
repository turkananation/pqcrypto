@TestOn('vm') // Reads the checked-in ACVP JSON corpus with dart:io.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/src/algos/slhdsa/params.dart';
import 'package:pqcrypto/src/algos/slhdsa/slhdsa.dart';
import 'package:test/test.dart';

const String _corpusRoot = 'test/data/SLHDSA';

final String? _parameterFilter = Platform.environment['SLHDSA_KAT_PARAMETER'];
final String? _operationFilter = Platform.environment['SLHDSA_KAT_OPERATION'];
final int _caseLimit =
    int.tryParse(Platform.environment['SLHDSA_KAT_LIMIT'] ?? '') ?? 0;

const Map<String, SlhDsaParams> _parameters = <String, SlhDsaParams>{
  'SLH-DSA-SHA2-128s': SlhDsaParams.sha2128s,
  'SLH-DSA-SHA2-128f': SlhDsaParams.sha2128f,
  'SLH-DSA-SHA2-192s': SlhDsaParams.sha2192s,
  'SLH-DSA-SHA2-192f': SlhDsaParams.sha2192f,
  'SLH-DSA-SHA2-256s': SlhDsaParams.sha2256s,
  'SLH-DSA-SHA2-256f': SlhDsaParams.sha2256f,
  'SLH-DSA-SHAKE-128s': SlhDsaParams.shake128s,
  'SLH-DSA-SHAKE-128f': SlhDsaParams.shake128f,
  'SLH-DSA-SHAKE-192s': SlhDsaParams.shake192s,
  'SLH-DSA-SHAKE-192f': SlhDsaParams.shake192f,
  'SLH-DSA-SHAKE-256s': SlhDsaParams.shake256s,
  'SLH-DSA-SHAKE-256f': SlhDsaParams.shake256f,
};

const Map<String, SlhDsaPreHash> _preHashes = <String, SlhDsaPreHash>{
  'SHA2-224': SlhDsaPreHash.sha224,
  'SHA2-256': SlhDsaPreHash.sha256,
  'SHA2-384': SlhDsaPreHash.sha384,
  'SHA2-512': SlhDsaPreHash.sha512,
  'SHA2-512/224': SlhDsaPreHash.sha512224,
  'SHA2-512/256': SlhDsaPreHash.sha512256,
  'SHA3-224': SlhDsaPreHash.sha3224,
  'SHA3-256': SlhDsaPreHash.sha3256,
  'SHA3-384': SlhDsaPreHash.sha3384,
  'SHA3-512': SlhDsaPreHash.sha3512,
  'SHAKE-128': SlhDsaPreHash.shake128,
  'SHAKE-256': SlhDsaPreHash.shake256,
};

Map<String, dynamic> _load(String operation, String fileName) {
  final file = File('$_corpusRoot/SLH-DSA-$operation-FIPS205/$fileName');
  return jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
}

List<Map<String, dynamic>> _groups(Map<String, dynamic> vectorSet) =>
    (vectorSet['testGroups'] as List<dynamic>).cast<Map<String, dynamic>>();

List<Map<String, dynamic>> _tests(Map<String, dynamic> group) =>
    (group['tests'] as List<dynamic>).cast<Map<String, dynamic>>();

Map<int, Map<String, dynamic>> _groupsById(Map<String, dynamic> vectorSet) =>
    <int, Map<String, dynamic>>{
      for (final group in _groups(vectorSet)) group['tgId'] as int: group,
    };

Map<int, Map<String, dynamic>> _testsById(Map<String, dynamic> group) =>
    <int, Map<String, dynamic>>{
      for (final test in _tests(group)) test['tcId'] as int: test,
    };

Uint8List _decodeHex(String value) {
  if (value.length.isOdd) {
    throw FormatException('Odd-length hexadecimal input');
  }
  final output = Uint8List(value.length ~/ 2);
  for (var i = 0; i < output.length; i++) {
    output[i] = int.parse(value.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return output;
}

String _encodeHex(Uint8List value) {
  final output = StringBuffer();
  for (final byte in value) {
    output.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return output.toString().toUpperCase();
}

Iterable<Map<String, dynamic>> _selectedGroups(
  Map<String, dynamic> prompt,
  String parameterName,
) => _groups(prompt).where((group) => group['parameterSet'] == parameterName);

Iterable<Map<String, dynamic>> _limited(Iterable<Map<String, dynamic>> tests) =>
    _caseLimit > 0 ? tests.take(_caseLimit) : tests;

void main() {
  final keyGenPrompt = _load('keyGen', 'prompt.json');
  final keyGenResults = _groupsById(_load('keyGen', 'expectedResults.json'));
  final sigGenPrompt = _load('sigGen', 'prompt.json');
  final sigGenResults = _groupsById(_load('sigGen', 'expectedResults.json'));
  final sigVerPrompt = _load('sigVer', 'prompt.json');
  final sigVerResults = _groupsById(_load('sigVer', 'expectedResults.json'));

  for (final parameterEntry in _parameters.entries) {
    final parameterName = parameterEntry.key;
    final params = parameterEntry.value;
    if (_parameterFilter != null && _parameterFilter != parameterName) {
      continue;
    }

    group(parameterName, () {
      if (_operationFilter == null || _operationFilter == 'keyGen') {
        test('ACVP keyGen is byte-exact', () {
          for (final promptGroup in _selectedGroups(
            keyGenPrompt,
            parameterName,
          )) {
            final resultTests = _testsById(keyGenResults[promptGroup['tgId']]!);
            for (final promptTest in _limited(_tests(promptGroup))) {
              final tcId = promptTest['tcId'] as int;
              final (
                publicKey,
                secretKey,
              ) = SlhDsaInternal.generateKeyPairSeeded(
                params,
                _decodeHex(promptTest['skSeed'] as String),
                _decodeHex(promptTest['skPrf'] as String),
                _decodeHex(promptTest['pkSeed'] as String),
              );
              final expected = resultTests[tcId]!;
              expect(
                _encodeHex(publicKey),
                expected['pk'],
                reason: 'keyGen tcId $tcId public key',
              );
              expect(
                _encodeHex(secretKey),
                expected['sk'],
                reason: 'keyGen tcId $tcId secret key',
              );
            }
          }
        }, timeout: Timeout.none);
      }

      if (_operationFilter == null || _operationFilter == 'sigGen') {
        test('ACVP sigGen is byte-exact', () {
          final promptGroups = _selectedGroups(
            sigGenPrompt,
            parameterName,
          ).toList();
          final totalCases = promptGroups.fold<int>(
            0,
            (total, group) => total + _limited(_tests(group)).length,
          );
          final progressWatch = Stopwatch()..start();
          var completedCases = 0;

          for (final promptGroup in promptGroups) {
            final resultTests = _testsById(sigGenResults[promptGroup['tgId']]!);
            final signatureInterface =
                promptGroup['signatureInterface'] as String;
            final preHash = promptGroup['preHash'] as String?;
            final deterministic = promptGroup['deterministic'] as bool;

            for (final promptTest in _limited(_tests(promptGroup))) {
              final tcId = promptTest['tcId'] as int;
              final secretKey = _decodeHex(promptTest['sk'] as String);
              final message = _decodeHex(promptTest['message'] as String);
              final additionalRandomness = deterministic
                  ? null
                  : _decodeHex(promptTest['additionalRandomness'] as String);
              final Uint8List signature;

              if (signatureInterface == 'internal') {
                signature = SlhDsaInternal.sign(
                  secretKey,
                  message,
                  params,
                  additionalRandomness: additionalRandomness,
                );
              } else {
                final context = _decodeHex(promptTest['context'] as String);
                if (preHash == 'preHash') {
                  final hash = _preHashes[promptTest['hashAlg']]!;
                  signature = deterministic
                      ? SlhDsa.hashSignDeterministic(
                          secretKey,
                          message,
                          hash,
                          params,
                          context: context,
                          allowSlowSigning: true,
                        )
                      : SlhDsa.hashSign(
                          secretKey,
                          message,
                          hash,
                          params,
                          context: context,
                          additionalRandomness: additionalRandomness,
                          allowSlowSigning: true,
                        );
                } else {
                  signature = deterministic
                      ? SlhDsa.signDeterministic(
                          secretKey,
                          message,
                          params,
                          context: context,
                          allowSlowSigning: true,
                        )
                      : SlhDsa.sign(
                          secretKey,
                          message,
                          params,
                          context: context,
                          additionalRandomness: additionalRandomness,
                          allowSlowSigning: true,
                        );
                }
              }

              expect(
                _encodeHex(signature),
                resultTests[tcId]!['signature'],
                reason: 'sigGen tcId $tcId',
              );
              completedCases++;
              if (!params.isFast ||
                  completedCases % 5 == 0 ||
                  completedCases == totalCases) {
                stdout.writeln(
                  '[SLH-DSA ACVP] $parameterName sigGen '
                  '$completedCases/$totalCases '
                  'elapsed=${progressWatch.elapsed}',
                );
              }
            }
          }
        }, timeout: Timeout.none);
      }

      if (_operationFilter == null || _operationFilter == 'sigVer') {
        test('ACVP sigVer accepts and rejects exactly', () {
          for (final promptGroup in _selectedGroups(
            sigVerPrompt,
            parameterName,
          )) {
            final resultTests = _testsById(sigVerResults[promptGroup['tgId']]!);
            final signatureInterface =
                promptGroup['signatureInterface'] as String;
            final preHash = promptGroup['preHash'] as String?;

            for (final promptTest in _limited(_tests(promptGroup))) {
              final tcId = promptTest['tcId'] as int;
              final publicKey = _decodeHex(promptTest['pk'] as String);
              final message = _decodeHex(promptTest['message'] as String);
              final signature = _decodeHex(promptTest['signature'] as String);
              final bool actual;

              if (signatureInterface == 'internal') {
                actual = SlhDsaInternal.verify(
                  publicKey,
                  message,
                  signature,
                  params,
                );
              } else {
                final context = _decodeHex(promptTest['context'] as String);
                if (preHash == 'preHash') {
                  actual = SlhDsa.hashVerify(
                    publicKey,
                    message,
                    signature,
                    _preHashes[promptTest['hashAlg']]!,
                    params,
                    context: context,
                  );
                } else {
                  actual = SlhDsa.verify(
                    publicKey,
                    message,
                    signature,
                    params,
                    context: context,
                  );
                }
              }

              expect(
                actual,
                resultTests[tcId]!['testPassed'],
                reason: 'sigVer tcId $tcId',
              );
            }
          }
        }, timeout: Timeout.none);
      }
    });
  }
}

@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqcrypto/src/common/sha2.dart';
import 'package:test/test.dart';

import 'fips202_corpus.dart';
import 'fips202_corpus_cases.dart';

void main() {
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

  String hex(Uint8List bytes) {
    final out = StringBuffer();
    for (final byte in bytes) {
      out.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return out.toString();
  }

  test('normalized JSON SHA-256 matches the manifest and the embed', () {
    final normalized = manifest['normalized']! as List<dynamic>;
    expect(
      manifest['normalizedNote'],
      'SHA-256 of the normalized JSON file bytes.',
    );
    final digests = <String, String>{
      for (final raw in normalized)
        (raw as Map<String, dynamic>)['file']! as String:
            raw['sha256']! as String,
    };
    expect(digests.keys, <String>[
      'all_examples.json',
      'shake_truncation.json',
      'byte_aligned_vectors.json',
    ]);
    for (final name in digests.keys) {
      final bytes = File('test/data/FIPS202/$name').readAsBytesSync();
      expect(hex(sha256(bytes)), digests[name], reason: name);
    }
    expect(
      utf8.decode(
        File('test/data/FIPS202/all_examples.json').readAsBytesSync(),
      ),
      fips202AllExamplesJson,
    );
    expect(
      utf8.decode(
        File('test/data/FIPS202/shake_truncation.json').readAsBytesSync(),
      ),
      fips202ShakeTruncationJson,
    );
    expect(fips202AllExamplesSha256, digests['all_examples.json']);
    expect(fips202ShakeTruncationSha256, digests['shake_truncation.json']);
    expect(
      hex(sha256(utf8.encode(fips202AllExamplesJson))),
      digests['all_examples.json'],
    );
    expect(
      hex(sha256(utf8.encode(fips202ShakeTruncationJson))),
      digests['shake_truncation.json'],
    );
  });

  test('manifest provenance covers every official message length', () {
    final files = manifest['files']! as List<dynamic>;
    expect(files, hasLength(37));
    expect(
      files.map((raw) => (raw as Map<String, dynamic>)['file'] as String),
      everyElement(endsWith('.pdf')),
    );
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
      expect((vector['messageBits']! as String).length, length);
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

  test('the public library does not export the bit-string helper', () {
    final library = File('lib/pqcrypto.dart').readAsStringSync();
    expect(library, isNot(contains('BitString')));
    expect(library, contains('hide fips202AbsorbBits'));
  });

  registerFips202OfficialCorpus(
    examplesJson: examples,
    truncationJson: truncation,
  );
}

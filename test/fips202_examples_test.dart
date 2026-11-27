import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

import 'fips202_corpus.dart';
import 'fips202_corpus_cases.dart';

/// Discovered runner for the full official FIPS 202 example corpus.
///
/// The JSON text lives in [fips202AllExamplesJson] and
/// [fips202ShakeTruncationJson], generated from the checked-in files, so this
/// test does not read the filesystem. Chrome and dart2wasm run the same
/// vectors as the VM.
void main() {
  test('embedded corpus text matches the generated SHA-256 pins', () {
    expect(
      _hex(sha256(utf8.encode(fips202AllExamplesJson))),
      fips202AllExamplesSha256,
    );
    expect(
      _hex(sha256(utf8.encode(fips202ShakeTruncationJson))),
      fips202ShakeTruncationSha256,
    );
  });

  registerFips202OfficialCorpus(
    examplesJson: jsonDecode(fips202AllExamplesJson) as Map<String, dynamic>,
    truncationJson:
        jsonDecode(fips202ShakeTruncationJson) as Map<String, dynamic>,
  );
}

String _hex(Uint8List bytes) {
  final hex = StringBuffer();
  for (final byte in bytes) {
    hex.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return hex.toString();
}

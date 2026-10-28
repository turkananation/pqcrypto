@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

// Only the public barrel: SlhDsa.generateKeyPairSeeded must be exported.
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';

const _keyGenDir = 'test/data/SLHDSA/SLH-DSA-keyGen-FIPS205';

Uint8List _hex(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);

Map<String, dynamic> _load(String name) =>
    jsonDecode(File('$_keyGenDir/$name').readAsStringSync())
        as Map<String, dynamic>;

/// The fast (`f`) parameter sets, keyed by their ACVP names.
final _fastSets = <String, SlhDsaParams>{
  'SLH-DSA-SHA2-128f': SlhDsaParams.sha2128f,
  'SLH-DSA-SHAKE-128f': SlhDsaParams.shake128f,
  'SLH-DSA-SHA2-192f': SlhDsaParams.sha2192f,
  'SLH-DSA-SHAKE-192f': SlhDsaParams.shake192f,
  'SLH-DSA-SHA2-256f': SlhDsaParams.sha2256f,
  'SLH-DSA-SHAKE-256f': SlhDsaParams.shake256f,
};

void main() {
  final prompt = _load('prompt.json');
  final expected = {
    for (final g
        in (_load('expectedResults.json')['testGroups'] as List)
            .cast<Map<String, dynamic>>())
      g['tgId']: {
        for (final t in (g['tests'] as List).cast<Map<String, dynamic>>())
          t['tcId']: t,
      },
  };

  group('SlhDsa.generateKeyPairSeeded (public, FIPS 205 Algorithm 18)', () {
    for (final g
        in (prompt['testGroups'] as List).cast<Map<String, dynamic>>()) {
      final params = _fastSets[g['parameterSet']];
      if (params == null) continue; // `s` sets: covered by slhdsa_kat_test
      test('${g['parameterSet']} reproduces the first ACVP keyGen case', () {
        final t = (g['tests'] as List).first as Map<String, dynamic>;
        final want = expected[g['tgId']]![t['tcId']]!;
        final (pk, sk) = SlhDsa.generateKeyPairSeeded(
          params,
          _hex(t['skSeed'] as String),
          _hex(t['skPrf'] as String),
          _hex(t['pkSeed'] as String),
        );
        expect(pk, _hex(want['pk'] as String));
        expect(sk, _hex(want['sk'] as String));
      });
    }

    test('recomputing PK.root detects an inconsistent secret key', () {
      final params = SlhDsaParams.shake128f;
      final n = params.n;
      final (_, sk) = SlhDsa.generateKeyPair(params);

      // sk = SK.seed || SK.prf || PK.seed || PK.root
      bool consistent(Uint8List key) {
        final (_, recomputed) = SlhDsa.generateKeyPairSeeded(
          params,
          Uint8List.sublistView(key, 0, n),
          Uint8List.sublistView(key, n, 2 * n),
          Uint8List.sublistView(key, 2 * n, 3 * n),
        );
        var diff = 0;
        for (var i = 3 * n; i < 4 * n; i++) {
          diff |= recomputed[i] ^ key[i];
        }
        return diff == 0;
      }

      expect(consistent(sk), isTrue);
      expect(consistent(Uint8List.fromList(sk)..[3 * n] ^= 1), isFalse);
      expect(consistent(Uint8List.fromList(sk)..[0] ^= 1), isFalse);
    });

    test('rejects seeds of the wrong length', () {
      final params = SlhDsaParams.shake128f;
      final ok = Uint8List(params.n);
      expect(
        () => SlhDsa.generateKeyPairSeeded(
          params,
          Uint8List(params.n - 1),
          ok,
          ok,
        ),
        throwsArgumentError,
      );
    });
  });
}

@TestOn('vm') // Reads the .rsp KAT corpus from disk (dart:io); VM-only.
library;

import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

/// Discovered, repo-local ML-DSA (FIPS 204) known-answer-test runner.
///
/// Validates byte-exact conformance against the official KAT corpus in
/// `test/data/MLDSA`, covering the full matrix:
///   {ML-DSA-44, 65, 87} x {deterministic, hedged} x {raw, pure, hashed}
/// where
///   raw    = internal functions (Algorithms 6/7/8), M' = M
///   pure   = external ML-DSA (Algorithms 1/2/3), 16-byte context
///   hashed = HashML-DSA (Algorithms 1/4/5), SHA-256/384/512 pre-hash
///
/// See `test/data/MLDSA/README.md` for the corpus format.
const String _katDir = 'test/data/MLDSA';

/// Records-per-file cap. Override with `-D MLDSA_KAT_LIMIT=<n>` (default: all).
const int _limit = int.fromEnvironment('MLDSA_KAT_LIMIT', defaultValue: 100);

Uint8List _fromHex(String s) {
  s = s.replaceAll(RegExp(r'\s+'), '');
  if (s.length.isOdd) throw FormatException('odd-length hex');
  final r = Uint8List(s.length ~/ 2);
  for (int i = 0; i < s.length; i += 2) {
    r[i ~/ 2] = int.parse(s.substring(i, i + 2), radix: 16);
  }
  return r;
}

List<Map<String, String>> _parse(File f) {
  final recs = <Map<String, String>>[];
  Map<String, String>? cur;
  for (var line in f.readAsLinesSync()) {
    line = line.trim();
    if (line.isEmpty || line.startsWith('#')) continue;
    final eq = line.indexOf('=');
    if (eq < 0) continue;
    final key = line.substring(0, eq).trim();
    final val = line.substring(eq + 1).trim();
    if (key == 'count') {
      cur = <String, String>{};
      recs.add(cur);
    }
    cur?[key] = val;
  }
  return recs;
}

DilithiumParams _paramsFor(String level) => switch (level) {
  '44' => DilithiumParams.mlDsa44,
  '65' => DilithiumParams.mlDsa65,
  '87' => DilithiumParams.mlDsa87,
  _ => throw ArgumentError('unknown level $level'),
};

void main() {
  final dir = Directory(_katDir);
  if (!dir.existsSync()) {
    test('ML-DSA KAT corpus present', () {
      fail('KAT directory not found: $_katDir');
    });
    return;
  }

  final files =
      dir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.endsWith('.rsp'))
          .toList()
        ..sort((a, b) => a.path.compareTo(b.path));

  test('all 18 ML-DSA KAT files are present', () {
    expect(
      files.length,
      18,
      reason: 'expected 3 levels x 2 modes x 3 flavours',
    );
  });

  final re = RegExp(r'kat_MLDSA_(\d+)_(det|hedged)_(raw|pure|hashed)\.rsp$');

  for (final file in files) {
    final m = re.firstMatch(file.path);
    if (m == null) continue;
    final level = m.group(1)!, mode = m.group(2)!, flavour = m.group(3)!;
    final params = _paramsFor(level);
    final deterministic = mode == 'det';

    group('ML-DSA-$level $mode/$flavour', () {
      final recs = _parse(file);
      final count = recs.length < _limit ? recs.length : _limit;

      test('$count vectors byte-exact (keygen/sign/verify)', () {
        expect(recs.length, 100, reason: 'each KAT file has 100 vectors');

        for (int i = 0; i < count; i++) {
          final v = recs[i];
          final xi = _fromHex(v['xi']!);
          final pkE = _fromHex(v['pk']!);
          final skE = _fromHex(v['sk']!);
          final msg = _fromHex(v['msg']!);
          final smlen = int.parse(v['smlen']!);
          final mlen = int.parse(v['mlen']!);
          final sigE = _fromHex(v['sm']!).sublist(0, smlen - mlen);
          final rnd = deterministic ? Uint8List(32) : _fromHex(v['rng']!);
          final ctx = v.containsKey('ctx') ? _fromHex(v['ctx']!) : Uint8List(0);

          // KeyGen byte-exactness (validated on the canonical raw/det files;
          // the same keys recur across flavours).
          if (flavour == 'raw' && deterministic) {
            final (pk, sk) = MlDsa.generateKeyPairSeeded(params, xi);
            expect(pk, equals(pkE), reason: 'vec $i: pk mismatch');
            expect(sk, equals(skE), reason: 'vec $i: sk mismatch');
          }

          final Uint8List sig;
          final bool ok;
          switch (flavour) {
            case 'raw':
              sig = MlDsa.signInternal(skE, msg, params, rnd: rnd);
              ok = MlDsa.verifyInternal(pkE, msg, sig, params);
            case 'pure':
              sig = MlDsa.sign(skE, msg, params, ctx: ctx, rnd: rnd);
              ok = MlDsa.verify(pkE, msg, sig, params, ctx: ctx);
            default: // hashed
              sig = MlDsa.hashSign(skE, msg, params, ctx: ctx, rnd: rnd);
              ok = MlDsa.hashVerify(pkE, msg, sig, params, ctx: ctx);
          }
          expect(sig, equals(sigE), reason: 'vec $i: signature mismatch');
          expect(ok, isTrue, reason: 'vec $i: verification failed');
        }
      });
    });
  }
}

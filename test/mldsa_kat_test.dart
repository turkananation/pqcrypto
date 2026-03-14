// ignore_for_file: avoid_print

import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

Uint8List fromHex(String s) {
  s = s.replaceAll(RegExp(r'\s+'), '');
  if (s.length % 2 != 0) throw FormatException('Invalid hex length');
  final result = Uint8List(s.length ~/ 2);
  for (int i = 0; i < s.length; i += 2) {
    result[i ~/ 2] = int.parse(s.substring(i, i + 2), radix: 16);
  }
  return result;
}

String toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');

/// Parse a det_raw KAT .rsp file into test vectors.
/// Fields: count, xi, seed, pk, sk, msg, mlen, sm, smlen
List<Map<String, String>> parseKatFile(String path) {
  final lines = File(path).readAsLinesSync();
  final vectors = <Map<String, String>>[];
  var current = <String, String>{};

  for (var line in lines) {
    line = line.trim();
    if (line.isEmpty || line.startsWith('#')) continue;

    final eqIdx = line.indexOf('=');
    if (eqIdx < 0) continue;
    final key = line.substring(0, eqIdx).trim();
    final val = line.substring(eqIdx + 1).trim();
    current[key] = val;

    // smlen is the last field in det_raw vectors
    if (key == 'smlen') {
      vectors.add(current);
      current = <String, String>{};
    }
  }
  return vectors;
}

void main() {
  const katDir = r'C:\Dev\Research\KAT\MLDSA';

  final testCases = [
    ('kat_MLDSA_44_det_raw.rsp', DilithiumParams.mlDsa44, 2420),
    ('kat_MLDSA_65_det_raw.rsp', DilithiumParams.mlDsa65, 3309),
    ('kat_MLDSA_87_det_raw.rsp', DilithiumParams.mlDsa87, 4627),
  ];

  for (final (filename, params, sigLen) in testCases) {
    group('${params.name} det_raw KAT', () {
      final path = '$katDir${Platform.pathSeparator}$filename';
      if (!File(path).existsSync()) {
        test('SKIPPED - KAT file not found: $path', () {
          print('KAT file not found: $path');
        });
        return;
      }

      final vectors = parseKatFile(path);

      // Test first vector in detail for debugging
      test('Vector 0 - KeyGen', () {
        final v = vectors[0];
        final xi = fromHex(v['xi']!);
        final pkExpected = fromHex(v['pk']!);
        final skExpected = fromHex(v['sk']!);

        final (pk, sk) = MlDsa.generateKeyPair(params, xi);

        expect(pk.length, pkExpected.length,
            reason: 'PK length mismatch: got ${pk.length}, expected ${pkExpected.length}');
        expect(sk.length, skExpected.length,
            reason: 'SK length mismatch: got ${sk.length}, expected ${skExpected.length}');

        // Find first byte mismatch for debugging
        for (int i = 0; i < pk.length; i++) {
          if (pk[i] != pkExpected[i]) {
            fail('PK mismatch at byte $i: got 0x${pk[i].toRadixString(16)}, '
                'expected 0x${pkExpected[i].toRadixString(16)}');
          }
        }
        for (int i = 0; i < sk.length; i++) {
          if (sk[i] != skExpected[i]) {
            fail('SK mismatch at byte $i: got 0x${sk[i].toRadixString(16)}, '
                'expected 0x${skExpected[i].toRadixString(16)}');
          }
        }
      });

      test('Vector 0 - Sign', () {
        final v = vectors[0];
        final skExpected = fromHex(v['sk']!);
        final msg = fromHex(v['msg']!);
        final sm = fromHex(v['sm']!);
        final smlen = int.parse(v['smlen']!);

        // sm = sig || msg, so sig = sm[0 : smlen - mlen]
        final mlen = int.parse(v['mlen']!);
        final sigExpected = sm.sublist(0, smlen - mlen);

        expect(sigExpected.length, sigLen,
            reason: 'Expected sig length $sigLen, got ${sigExpected.length}');

        final sig = MlDsa.sign(skExpected, msg, params);

        expect(sig.length, sigLen, reason: 'Sig length mismatch');

        for (int i = 0; i < sig.length; i++) {
          if (sig[i] != sigExpected[i]) {
            fail('Sig mismatch at byte $i: got 0x${sig[i].toRadixString(16)}, '
                'expected 0x${sigExpected[i].toRadixString(16)}');
          }
        }
      });

      test('Vector 0 - Verify', () {
        final v = vectors[0];
        final pkExpected = fromHex(v['pk']!);
        final msg = fromHex(v['msg']!);
        final sm = fromHex(v['sm']!);
        final smlen = int.parse(v['smlen']!);
        final mlen = int.parse(v['mlen']!);
        final sig = sm.sublist(0, smlen - mlen);

        final valid = MlDsa.verify(pkExpected, msg, sig, params);
        expect(valid, isTrue, reason: 'Verification of KAT signature failed');
      });

      // Test all 100 vectors
      test('All 100 vectors - KeyGen + Sign + Verify', () {
        expect(vectors.length, 100, reason: 'Expected 100 KAT vectors');

        for (int idx = 0; idx < vectors.length; idx++) {
          final v = vectors[idx];
          final xi = fromHex(v['xi']!);
          final pkExpected = fromHex(v['pk']!);
          final skExpected = fromHex(v['sk']!);
          final msg = fromHex(v['msg']!);
          final sm = fromHex(v['sm']!);
          final smlen = int.parse(v['smlen']!);
          final mlen = int.parse(v['mlen']!);
          final sigExpected = sm.sublist(0, smlen - mlen);

          // KeyGen
          final (pk, sk) = MlDsa.generateKeyPair(params, xi);
          expect(pk, equals(pkExpected),
              reason: 'Vector $idx: PK mismatch');
          expect(sk, equals(skExpected),
              reason: 'Vector $idx: SK mismatch');

          // Sign (deterministic)
          final sig = MlDsa.sign(sk, msg, params);
          expect(sig, equals(sigExpected),
              reason: 'Vector $idx: Signature mismatch');

          // Verify
          final valid = MlDsa.verify(pk, msg, sig, params);
          expect(valid, isTrue,
              reason: 'Vector $idx: Verification failed');
        }
        print('${params.name}: 100/100 KAT vectors PASSED');
      });
    });
  }
}

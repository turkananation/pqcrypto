// ignore_for_file: avoid_print
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/dilithium/dsa.dart';
import 'package:pqcrypto/src/algos/dilithium/params.dart';

Uint8List fromHex(String s) {
  s = s.replaceAll(RegExp(r'\s+'), '');
  final result = Uint8List(s.length ~/ 2);
  for (int i = 0; i < s.length; i += 2) {
    result[i ~/ 2] = int.parse(s.substring(i, i + 2), radix: 16);
  }
  return result;
}

String toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');

void main() {
  test('ML-DSA-44 KeyGen Debug', () {
    // First vector from kat_MLDSA_44_det_raw.rsp
    final lines = File(r'C:\Dev\Research\KAT\MLDSA\kat_MLDSA_44_det_raw.rsp')
        .readAsLinesSync();
    final fields = <String, String>{};
    for (var line in lines) {
      line = line.trim();
      if (line.isEmpty) continue;
      final eq = line.indexOf('=');
      if (eq < 0) continue;
      fields[line.substring(0, eq).trim()] = line.substring(eq + 1).trim();
      if (line.startsWith('smlen')) break; // stop after first vector
    }

    final xi = fromHex(fields['xi']!);
    final pkExp = fromHex(fields['pk']!);
    final skExp = fromHex(fields['sk']!);
    final params = DilithiumParams.mlDsa44;

    final (pk, sk) = MlDsa.generateKeyPair(params, xi);

    // Check SK sections: rho(32) + K(32) + tr(64) + s1 + s2 + t0
    print('=== SK comparison ===');
    print('SK length: got ${sk.length}, expected ${skExp.length}');

    // rho (first 32 bytes of SK)
    bool rhoMatch = true;
    for (int i = 0; i < 32; i++) {
      if (sk[i] != skExp[i]) { rhoMatch = false; break; }
    }
    print('SK rho (0-31): ${rhoMatch ? "MATCH" : "MISMATCH"}');

    // K (bytes 32-63 of SK)
    bool kMatch = true;
    for (int i = 32; i < 64; i++) {
      if (sk[i] != skExp[i]) { kMatch = false; break; }
    }
    print('SK K (32-63): ${kMatch ? "MATCH" : "MISMATCH"}');

    // tr (bytes 64-127 of SK)
    bool trMatch = true;
    int trMismatchAt = -1;
    for (int i = 64; i < 128; i++) {
      if (sk[i] != skExp[i]) {
        trMatch = false;
        trMismatchAt = i;
        break;
      }
    }
    print('SK tr (64-127): ${trMatch ? "MATCH" : "MISMATCH at byte $trMismatchAt"}');

    // s1 section: starts at 128, each poly is 32*3=96 bytes for eta=2, l=4 polys
    int s1Offset = 128;
    int s1PolySize = 32 * 3; // eta=2 → 3 bits
    int s1TotalSize = params.l * s1PolySize;
    bool s1Match = true;
    int s1MismatchAt = -1;
    for (int i = 0; i < s1TotalSize; i++) {
      if (sk[s1Offset + i] != skExp[s1Offset + i]) {
        s1Match = false;
        s1MismatchAt = i;
        break;
      }
    }
    print('SK s1 ($s1Offset-${s1Offset + s1TotalSize - 1}): ${s1Match ? "MATCH" : "MISMATCH at relative byte $s1MismatchAt"}');

    // s2 section
    int s2Offset = s1Offset + s1TotalSize;
    int s2PolySize = 32 * 3;
    int s2TotalSize = params.k * s2PolySize;
    bool s2Match = true;
    int s2MismatchAt = -1;
    for (int i = 0; i < s2TotalSize; i++) {
      if (sk[s2Offset + i] != skExp[s2Offset + i]) {
        s2Match = false;
        s2MismatchAt = i;
        break;
      }
    }
    print('SK s2 ($s2Offset-${s2Offset + s2TotalSize - 1}): ${s2Match ? "MATCH" : "MISMATCH at relative byte $s2MismatchAt"}');

    // t0 section
    int t0Offset = s2Offset + s2TotalSize;
    int t0PolySize = 32 * 13; // 416 bytes
    int t0TotalSize = params.k * t0PolySize;
    bool t0Match = true;
    int t0MismatchAt = -1;
    for (int i = 0; i < t0TotalSize; i++) {
      if (sk[t0Offset + i] != skExp[t0Offset + i]) {
        t0Match = false;
        t0MismatchAt = i;
        break;
      }
    }
    print('SK t0 ($t0Offset-${t0Offset + t0TotalSize - 1}): ${t0Match ? "MATCH" : "MISMATCH at relative byte $t0MismatchAt"}');

    // PK comparison
    print('\n=== PK comparison ===');
    print('PK length: got ${pk.length}, expected ${pkExp.length}');
    bool pkRhoMatch = true;
    for (int i = 0; i < 32; i++) {
      if (pk[i] != pkExp[i]) { pkRhoMatch = false; break; }
    }
    print('PK rho (0-31): ${pkRhoMatch ? "MATCH" : "MISMATCH"}');

    int pkMismatchAt = -1;
    for (int i = 32; i < pk.length; i++) {
      if (pk[i] != pkExp[i]) { pkMismatchAt = i; break; }
    }
    if (pkMismatchAt >= 0) {
      print('PK t1 first mismatch at byte $pkMismatchAt');
      print('  Got:      ${toHex(pk.sublist(pkMismatchAt, pkMismatchAt + 16))}');
      print('  Expected: ${toHex(pkExp.sublist(pkMismatchAt, pkMismatchAt + 16))}');
    } else {
      print('PK t1: MATCH');
    }
  });
}

// ignore_for_file: avoid_print

@TestOn('vm') // Reads the .rsp KAT corpus from disk (dart:io); VM-only.
library;

import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/pqcrypto.dart';

const _katDir = 'test/data/MLKEM';

// Helper to parse hex strings
Uint8List fromHex(String s) {
  // Remove any whitespace
  s = s.replaceAll(RegExp(r'\s+'), '');
  if (s.length % 2 != 0) {
    throw FormatException('Invalid hex string length');
  }
  final result = Uint8List(s.length ~/ 2);
  for (int i = 0; i < s.length; i += 2) {
    final byte = int.parse(s.substring(i, i + 2), radix: 16);
    result[i ~/ 2] = byte;
  }
  return result;
}

void main() {
  test('NIST KAT Runner', () async {
    final dataDir = Directory(_katDir);
    if (!await dataDir.exists()) {
      throw TestFailure('KAT directory not found: $_katDir');
    }

    final files = await dataDir
        .list()
        .where((entity) => entity is File && entity.path.endsWith('.rsp'))
        .cast<File>()
        .toList();
    files.sort((a, b) => a.path.compareTo(b.path));

    var vectorsRun = 0;
    for (final file in files) {
      print('Running KAT file: ${file.path}');
      vectorsRun += await _runKATFile(file);
    }

    expect(vectorsRun, greaterThan(0), reason: 'No KAT vectors were run.');
  });
}

Future<int> _runKATFile(File file) async {
  final lines = await file.readAsLines();
  KyberKem? kem;

  // Determine scheme from filename or header?
  // Filename usually "PQCkemKAT_1632.rsp" (pk+sk+ct sum?) or "PQCkemKAT_Kyber512.rsp"
  // We'll rely on heuristic or explicit mapping if filename is standard.
  // For now, let's try to deduce from byte lengths or assume single file per test.

  final filename = file.uri.pathSegments.last;
  if (filename.contains('1184') || filename.contains('768')) {
    kem = PqcKem.kyber768;
  } else if (filename.contains('800') || filename.contains('512')) {
    kem = PqcKem.kyber512;
  } else if (filename.contains('1568') || filename.contains('1024')) {
    kem = PqcKem.kyber1024;
  } else {
    print('Unknown scheme for file $filename, skipping.');
    return 0;
  }

  final vectors = <_KatVector>[];
  _KatVector? vector;

  for (var line in lines) {
    line = line.trim();
    if (line.isEmpty || line.startsWith('#')) continue;

    final parts = line.split('=');
    if (parts.length != 2) continue;

    final key = parts[0].trim();
    final val = parts[1].trim();

    if (key == 'count') {
      if (vector != null) vectors.add(vector);
      vector = _KatVector(int.parse(val));
    } else if (vector == null) {
      continue;
    } else if (key == 'z') {
      vector.z = fromHex(val);
    } else if (key == 'd') {
      vector.d = fromHex(val);
    } else if (key == 'msg') {
      vector.msg = fromHex(val);
    } else if (key == 'seed') {
      vector.seed = fromHex(val);
    } else if (key == 'pk') {
      vector.pk = fromHex(val);
    } else if (key == 'sk') {
      vector.sk = fromHex(val);
    } else if (key == 'ct') {
      vector.ct = fromHex(val);
    } else if (key == 'ss') {
      vector.ss = fromHex(val);
    } else if (key == 'ct_n') {
      vector.ctN = fromHex(val);
    } else if (key == 'ss_n') {
      vector.ssN = fromHex(val);
    }
  }

  if (vector != null) vectors.add(vector);

  for (final kat in vectors) {
    _verifyVector(kem, kat);
  }

  print('Completed ${vectors.length} vectors from ${file.path}');
  return vectors.length;
}

void _verifyVector(KyberKem kem, _KatVector vector) {
  final pkExp = _required(vector.pk, vector, 'pk');
  final skExp = _required(vector.sk, vector, 'sk');

  if (vector.d != null && vector.z != null) {
    final keygenSeed = _concat(vector.d!, vector.z!);
    final (pk, sk) = kem.generateKeyPair(keygenSeed);
    _expectBytes(pk, pkExp, vector, 'KeyGen public key');
    _expectBytes(sk, skExp, vector, 'KeyGen secret key');
  } else if (vector.seed != null && vector.seed!.length != 48) {
    final (pk, sk) = kem.generateKeyPair(vector.seed);
    _expectBytes(pk, pkExp, vector, 'KeyGen public key');
    _expectBytes(sk, skExp, vector, 'KeyGen secret key');
  }

  if (vector.msg != null && vector.ct != null && vector.ss != null) {
    final (ct, ss) = kem.encapsulate(pkExp, vector.msg);
    _expectBytes(ct, vector.ct!, vector, 'Encaps ciphertext');
    _expectBytes(ss, vector.ss!, vector, 'Encaps shared secret');
  }

  if (vector.ct != null && vector.ss != null) {
    final ssRecov = kem.decapsulate(skExp, vector.ct!);
    _expectBytes(ssRecov, vector.ss!, vector, 'Decaps shared secret');
  }

  if (vector.ctN != null && vector.ssN != null) {
    final ssRecov = kem.decapsulate(skExp, vector.ctN!);
    _expectBytes(ssRecov, vector.ssN!, vector, 'Invalid Decaps shared secret');
  }
}

String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}

Uint8List _concat(Uint8List first, Uint8List second) {
  final result = Uint8List(first.length + second.length);
  result.setAll(0, first);
  result.setAll(first.length, second);
  return result;
}

Uint8List _required(Uint8List? value, _KatVector vector, String field) {
  if (value == null) {
    throw TestFailure('Vector ${vector.count}: missing $field');
  }
  return value;
}

void _expectBytes(
  Uint8List actual,
  Uint8List expected,
  _KatVector vector,
  String label,
) {
  if (_listEquals(actual, expected)) return;

  final expectedPrefix = _toHex(expected.sublist(0, 16));
  final actualPrefix = _toHex(actual.sublist(0, 16));
  throw TestFailure(
    'Vector ${vector.count}: $label mismatch\n'
    '  Expected: $expectedPrefix...\n'
    '  Got:      $actualPrefix...',
  );
}

bool _listEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

class _KatVector {
  _KatVector(this.count);

  final int count;
  Uint8List? z;
  Uint8List? d;
  Uint8List? msg;
  Uint8List? seed;
  Uint8List? pk;
  Uint8List? sk;
  Uint8List? ct;
  Uint8List? ss;
  Uint8List? ctN;
  Uint8List? ssN;
}

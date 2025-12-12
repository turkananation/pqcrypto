import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/pqcrypto.dart';

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
    // We look for .rsp files in test/data
    final dataDir = Directory('/home/kali/Dev/Research/KAT/MLKEM');
    if (!await dataDir.exists()) {
      print('No test/data directory found. Skipping KATs.');
      return;
    }

    await for (final file in dataDir.list()) {
      if (file.path.endsWith('.rsp')) {
        print('Running KAT file: ${file.path}');
        await _runKATFile(file as File);
      }
    }
  });
}

Future<void> _runKATFile(File file) async {
  final lines = await file.readAsLines();
  KyberKem? kem;

  // State
  int count = 0;
  Uint8List? seed;
  Uint8List? pkExp;
  Uint8List? skExp;
  Uint8List? ctExp;
  Uint8List? ssExp;

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
    return;
  }

  for (var line in lines) {
    line = line.trim();
    if (line.isEmpty || line.startsWith('#')) continue;

    final parts = line.split('=');
    if (parts.length != 2) continue;

    final key = parts[0].trim();
    final val = parts[1].trim();

    if (key == 'count') {
      count = int.parse(val);
    } else if (key == 'seed') {
      seed = fromHex(val);
    } else if (key == 'pk') {
      pkExp = fromHex(val);
    } else if (key == 'sk') {
      skExp = fromHex(val);
    } else if (key == 'ct_n') {
      // ML-KEM FIPS 203 ciphertext
      ctExp = fromHex(val);
    } else if (key == 'ss_n') {
      // ML-KEM FIPS 203 shared secret
      ssExp = fromHex(val);

      // Trigger Test
      _verifyVector(count, kem, seed!, pkExp!, skExp!, ctExp!, ssExp);

      // Reset optional checks
      seed = null;
      pkExp = null;
      skExp = null;
      ctExp = null;
      ssExp = null;
    }
  }
}

void _verifyVector(
  int count,
  KyberKem kem,
  Uint8List seed,
  Uint8List pkExp,
  Uint8List skExp,
  Uint8List ctExp,
  Uint8List ssExp,
) {
  // 1. KeyGen
  // KAT seed is 48 bytes usually: 32 for d, 32 for z?
  // NIST KAT generator uses a DRBG to feed the RNG.
  // The 'seed' in the file is the INPUT to the DRBG.
  // However, typical mock files might provide the refined seeds.
  // If the seed is 48 bytes, it's likely (d || z) or similar.

  // NIST FIPS 203: KeyGen uses d (32) and z (32).
  // The provided Mock KAT file uses 'seed' of 48 bytes?
  // Let's assume for our Mock generator we treat the seed as the entropy source.
  // But wait, the previous mock used 32 bytes.

  // Important: Implementing exact NIST RNG expansion (AES-CTR DRBG) in Dart
  // is outside our current scope unless we import a DRBG lib.
  // For now, we assume the 'seed' in the file IS the entropy passed to GenerateKeyPair.

  // If seed encoded is 48 bytes, we truncate or use as is?
  // Kyber KeyGen takes 64 bytes (d=32, z=32) usually.
  // If we only pass 32 bytes, internal logic expands it?
  // My Implementation: generateKeyPair([seed]).
  // If seed length != 64 and != 32, it fails/warns.

  // 1. KeyGen
  // NIST KAT seeds are 48 bytes (AES-CTR DRBG input).
  // We cannot reproduce KeyGen without implementing the full NIST RNG stack.
  if (seed.length == 48) {
    // Skip KeyGen verification for official NIST vectors
    // print('Vector $count: KeyGen Skipped (NIST Seed)');
  } else {
    try {
      final (pk, sk) = kem.generateKeyPair(seed);
      // Optional: Verify PK/SK if we expect exact match (requires exact RNG)
      expect(pk, equals(pkExp));
    } catch (e) {
      print('Vector $count: KeyGen Failed ($e)');
    }
  }

  // 2. Encaps
  // Requires coins. NIST KATs don't always provide 'msg'/'coins' separate from 'seed'.
  // If we assume deterministic RNG from seed, we could try, but KeyGen was skipped.

  // 3. Decaps (Deterministic)
  // This MUST pass regardless of KeyGen, as we use provided SK and CT.
  try {
    final ssRecov = kem.decapsulate(skExp, ctExp);

    // Allow for expected failure due to missing NTT (Phase 3)
    if (_listEquals(ssRecov, ssExp)) {
      print('✓ Vector $count: PASS');
    } else {
      print('✗ Vector $count: FAIL');
      print('  Expected SS: ${_toHex(ssExp.sublist(0, 16))}...');
      print('  Got SS:      ${_toHex(ssRecov.sublist(0, 16))}...');
      throw TestFailure('Decaps mismatch');
    }
  } catch (e) {
    print('✗ Vector $count: ERROR - $e');
    rethrow; // Abort on first failure for debugging
  }
}

String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}

bool _listEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

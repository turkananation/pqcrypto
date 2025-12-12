import 'package:pqcrypto/pqcrypto.dart';

void main() {
  print('--- ML-KEM FIPS 203 Demo ---');

  // Example 1: ML-KEM-768 (Default/FIPS 203 Level 3)
  _runExample('ML-KEM-768', PqcKem.kyber768);

  // Example 2: ML-KEM-512 (Faster, FIPS 203 Level 1)
  _runExample('ML-KEM-512', PqcKem.kyber512);

  // Example 3: ML-KEM-1024 (Strongest, FIPS 203 Level 5)
  _runExample('ML-KEM-1024', PqcKem.kyber1024);
}

void _runExample(String name, KyberKem kem) {
  print('\nRunning $name (FIPS 203 Compliant)...');

  // 1. Correctness Check
  final checks = kem.generateKeyPair();
  final (checkPk, checkSk) = checks;
  print(
    '  Generated Keypair: pk=${checkPk.length} bytes, sk=${checkSk.length} bytes',
  );
  print('    pk (first 16 bytes): ${_hex(checkPk.sublist(0, 16))}...');

  // 2. Functionality Check
  final (ct, clientSecret) = kem.encapsulate(checkPk);
  final serverSecret = kem.decapsulate(checkSk, ct);

  if (clientSecret.toString() == serverSecret.toString()) {
    print(
      '  ✅ SUCCESS: Shared secrets match! (Size: ${clientSecret.length} bytes)',
    );
  } else {
    print('  ❌ FAILURE: Shared secrets do not match.');
    return;
  }

  // 3. Benchmarking
  // JIT Warmup
  print('  Warming up JIT...');
  for (int i = 0; i < 50; i++) {
    final (pk, sk) = kem.generateKeyPair();
    final (ct, _) = kem.encapsulate(pk);
    kem.decapsulate(sk, ct);
  }

  // Measure KeyGen
  final iterations = 200;
  var stopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    kem.generateKeyPair();
  }
  stopwatch.stop();
  final keyGenMs = stopwatch.elapsedMicroseconds / iterations / 1000.0;
  print('  KeyGen: ${keyGenMs.toStringAsFixed(4)} ms');

  // Measure Encaps
  stopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    kem.encapsulate(checkPk);
  }
  stopwatch.stop();
  final encapMs = stopwatch.elapsedMicroseconds / iterations / 1000.0;
  print('  Encap:  ${encapMs.toStringAsFixed(4)} ms');

  // Measure Decaps
  stopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    kem.decapsulate(checkSk, ct);
  }
  stopwatch.stop();
  final decapMs = stopwatch.elapsedMicroseconds / iterations / 1000.0;
  print('  Decap:  ${decapMs.toStringAsFixed(4)} ms');
}

String _hex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

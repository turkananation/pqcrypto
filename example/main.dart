import 'package:pqcrypto/pqcrypto.dart';

void main() {
  print('--- Kyber Logic Demo ---');

  // Example 1: Kyber-768 (Default/Standard)
  _runExample('Kyber-768', PqcKem.kyber768);

  // Example 2: Kyber-512 (Faster, Level 1 Security)
  _runExample('Kyber-512', PqcKem.kyber512);

  // Example 3: Kyber-1024 (Stronger, Level 5 Security)
  _runExample('Kyber-1024', PqcKem.kyber1024);
}

void _runExample(String name, KyberKem kem) {
  print('\nRunning $name...');

  // 1. Correctness Check
  final checks = kem.generateKeyPair();
  final (checkPk, checkSk) = checks;
  print(
    '  Generated Keypair (Sample): pk=${checkPk.length} bytes, sk=${checkSk.length} bytes',
  );
  print('    pk (first 16 bytes): ${_hex(checkPk.sublist(0, 16))}...');

  // 2. Diligent Benchmarking (KeyGen)
  // JIT Warmup
  print('  Warming up JIT...');
  for (int i = 0; i < 100; i++) {
    kem.generateKeyPair();
  }

  // Measurement
  final iterations = 1000;
  print('  Benchmarking Key Gen ($iterations iterations)...');
  final stopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    kem.generateKeyPair();
  }
  stopwatch.stop();
  final avgMs = stopwatch.elapsedMicroseconds / iterations / 1000.0;

  print('  Average Key Generation: ${avgMs.toStringAsFixed(4)} ms');

  // 3. Encapsulate (Client Side)
  // Uses the Server's Public Key to generate a Shared Secret and Ciphertext
  final (ct, clientSecret) = kem.encapsulate(checkPk);
  print('  Encapsulated: ct=${ct.length} bytes');

  // 4. Decapsulate (Server Side)
  // Server uses Secret Key and Ciphertext to recover the same Shared Secret
  final serverSecret = kem.decapsulate(checkSk, ct);

  // 5. Verify
  if (clientSecret.toString() == serverSecret.toString()) {
    print('  SUCCESS: Shared secrets match!');
  } else {
    print('  FAILURE: Shared secrets do not match.');
  }
}

String _hex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

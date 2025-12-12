import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:pqcrypto/src/algos/kyber/indcpa.dart';
import 'package:pqcrypto/src/algos/kyber/params.dart';

void main() {
  test('CBD Statistical Distribution (eta=2)', () {
    final params = const KyberParams(
      k: 3,
      eta1: 2,
      eta2: 2,
      du: 10,
      dv: 4,
    ); // Kyber-768
    final counts = <int, int>{
      0: 0,
      1: 0,
      2: 0,
      3328: 0, // -1
      3327: 0, // -2
    };

    // We expect:
    // 0: ~37.5%
    // 1 / -1: ~25.0%
    // 2 / -2: ~6.25%

    const iterations = 1000;
    const coeffsPerPoly = 256;
    const totalSamples = iterations * coeffsPerPoly;

    final rng = Random.secure();

    for (int i = 0; i < iterations; i++) {
      final seed = Uint8List.fromList(
        List.generate(32, (_) => rng.nextInt(256)),
      );
      // Use sampleInBall to access CBD logic (eta=2)
      final p = Indcpa.sampleInBall(seed, params, nonce: 0);

      for (final c in p.coeffs) {
        if (counts.containsKey(c)) {
          counts[c] = counts[c]! + 1;
        }
      }
    }

    // Verify probabilities
    final p0 = counts[0]! / totalSamples;
    final p1 = counts[1]! / totalSamples;
    final pMinus1 = counts[3328]! / totalSamples;
    final p2 = counts[2]! / totalSamples;
    final pMinus2 = counts[3327]! / totalSamples;

    print('P(0): $p0 (Exp: 0.375)');
    print('P(1): $p1 (Exp: 0.25)');
    print('P(-1): $pMinus1 (Exp: 0.25)');
    print('P(2): $p2 (Exp: 0.0625)');
    print('P(-2): $pMinus2 (Exp: 0.0625)');

    expect(p0, closeTo(0.375, 0.005));
    expect(p1, closeTo(0.25, 0.005));
    expect(pMinus1, closeTo(0.25, 0.005));
    expect(p2, closeTo(0.0625, 0.005));
    expect(pMinus2, closeTo(0.0625, 0.005));
  });
}
// Note: We need access to internal _cbd. Ideally verified via public API or by exposing it for testing.
// Since Indcpa is internal, we might need to put this test in `test/src/` or make _cbd visible.
// Accessing private members in Dart libraries from test/ requires imports of src/ directly?
// Or we can assume Indcpa is accessible if we import 'package:pqcrypto/src/algos/kyber/indcpa.dart'
// But _cbd is private static.
// We can't easily test private static _cbd without reflection or changing visibility.
// Review: Indcpa.dart _cbd is private.
// However, we can test "Poly.getNoise" effectively.
// But we don't have a direct "getNoise" API.
// We can use KeyGen to get error vectors, but that's indirect.

// Alternative: We will rely on our code review of CBD logic which was "schoolbook" correct.
// Or we use reflection to access it? No.
// We can duplicate the logic here to verify expected distribution if we had the same input.
// But that tests the COPY, not the code.

// Let's modify Indcpa to expose `cbd` as logical public @visibleForTesting
// or just skip this if it requires invasive changes.
// The user "Approved" the plan.
// Let's TRY to access it via library import of src.
// If it's private `_cbd`, we can't.
// Let's check `indcpa.dart` visibility.

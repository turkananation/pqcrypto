import 'package:test/test.dart';
import 'package:pqcrypto/src/common/poly.dart';

void main() {
  test('NTT/InvNTT Round Trip', () {
    // Create a simple polynomial
    final original = Poly(List.generate(256, (i) => (i * 7) % 3329));

    // Transform to NTT domain and back
    final nttDomain = Poly.ntt(original);
    final recovered = Poly.invNtt(nttDomain);

    // Check if we get back the original (with some tolerance for Montgomery domain shifts)
    for (int i = 0; i < 256; i++) {
      expect(
        recovered.coeffs[i],
        equals(original.coeffs[i]),
        reason:
            'Coefficient $i mismatch: got ${recovered.coeffs[i]}, expected ${original.coeffs[i]}',
      );
    }
  });

  test('NTT preserves zero polynomial', () {
    final zero = Poly(List.filled(256, 0));
    final nttZero = Poly.ntt(zero);
    final recovered = Poly.invNtt(nttZero);

    for (int i = 0; i < 256; i++) {
      expect(recovered.coeffs[i], equals(0));
    }
  });
}

import 'package:test/test.dart';
import 'package:pqcrypto/src/common/poly.dart';

void main() {
  test('Montgomery reduction correctness', () {
    // Test: montgomeryReduce(a * R) should return a
    // where R = 2^16 = 65536
    const int R = 65536;
    const int q = 3329;

    // Test with small values
    for (int a = 0; a < 100; a++) {
      int aR = (a * R) % q;
      int result = Poly.montgomeryReduce(aR);
      // After montgomery reduction, we should get back 'a'
      // But the result might be negative or need reduction
      result = result % q;
      if (result < 0) result += q;

      expect(
        result,
        equals(a),
        reason: 'Montgomery reduce of $a * R should give $a, got $result',
      );
    }
  });

  test('Montgomery multiplication', () {
    // Test: mont(a) * mont(b) |> montReduce => mont(a*b)
    const int R = 65536;
    const int q = 3329;

    int a = 7;
    int b = 5;

    // Expected: a * b = 35
    int expected = (a * b) % q;

    // Montgomery forms
    int aR = (a * R) % q;
    int bR = (b * R) % q;

    // Multiply and reduce
    int abR = Poly.montgomeryReduce(aR * bR);
    abR = abR % q;
    if (abR < 0) abR += q;

    // This should give us (a*b) in Montgomery form, not normal form
    // To get normal form, we need another reduction
    int result = Poly.montgomeryReduce(abR);
    result = result % q;
    if (result < 0) result += q;

    print('a=$a, b=$b, expected a*b=$expected');
    print('aR=$aR, bR=$bR');
    print('abR (after first reduce)=$abR');
    print('result (after second reduce)=$result');
  });
}

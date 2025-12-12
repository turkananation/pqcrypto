void main() {
  const int q = 3329;
  const int mont = -1044; // MONT from reference (2^16 mod q as signed)
  const int n = 128; // Reference comment says "mont^2/128" not 256!

  // Calculate mont^2/n mod q
  int mont2 = (mont * mont) % q;
  print('mont^2 mod q = $mont2');

  // Find n^-1 mod q
  int nInv = modInverse(n, q);
  print('n^-1 mod q = $nInv');

  // f = mont^2 * n^-1 mod q
  int f = (mont2 * nInv) % q;
  if (f < 0) f += q;
  print('f = mont^2 / n mod q = $f');
  print('Reference uses f = 1441');
  print('Match: ${f == 1441}');

  // Also verify: -1044 ≡ 2285 (mod 3329)?
  int montUnsigned = (-1044 + 3329) % q;
  print('\\n-1044 mod 3329 = $montUnsigned (should be 2285)');
}

int modInverse(int a, int m) {
  int m0 = m, x0 = 0, x1 = 1;
  if (m == 1) return 0;
  a = a % m;
  if (a < 0) a += m;
  while (a > 1) {
    int quot = a ~/ m;
    int t = m;
    m = a % m;
    a = t;
    t = x0;
    x0 = x1 - quot * x0;
    x1 = t;
  }
  if (x1 < 0) x1 += m0;
  return x1;
}

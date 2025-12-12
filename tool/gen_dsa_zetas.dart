void main() {
  const q = 8380417;
  const root = 1753;
  const n = 256;

  int power(int base, int exp) {
    int res = 1;
    base %= q;
    while (exp > 0) {
      if (exp % 2 == 1) res = (res * base) % q;
      base = (base * base) % q;
      exp ~/= 2;
    }
    return res;
  }

  int bitRev8(int n) {
    int res = 0;
    for (int i = 0; i < 8; i++) {
      if ((n & (1 << i)) != 0) {
        res |= (1 << (7 - i));
      }
    }
    return res;
  }

  // Generate table
  final zetas = List<int>.filled(n, 0);
  // zetas[k] = root ^ bitRev7(k)
  // But wait, check FIPS 204 exactly.
  // "The array zetas is defined by zetas[i] = 1753^BitRev7(i) mod q"

  // Implementation usually computes per index k used in the loops?
  // Let's generate the array exactly as needed.

  final buffer = StringBuffer();
  buffer.writeln('static const List<int> zetas = [');

  // Create simple list to verify
  for (int i = 0; i < n; i++) {
    final exp = bitRev8(i);
    final val = power(root, exp);
    zetas[i] = val;
    buffer.write('  $val,');
    if ((i + 1) % 8 == 0) buffer.writeln();
  }

  buffer.writeln('];');
  print(buffer.toString());
}

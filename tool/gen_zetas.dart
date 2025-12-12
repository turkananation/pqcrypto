void main() {
  const int q = 3329;
  const int root = 17; // Primitive root of unity for q=3329

  // We need n-th roots of unity (actually 2n-th for full negacyclic, but standard defines zetas for N=256)
  // FIPS 203: zetas[i] = root ^ (BitRev(i)) mod q.
  // Actually, standard Kyber uses bit-reversed order.

  // Let's generate the table as per reference implementation.

  // k goes from 0 to 127?
  // Reference impl (ref/poly.c):
  // zetas[0] not used?
  // Loop logic usually:
  /*
    k=1;
    for(len=128; len>=2; len>>=1)
      for(start=0; start<256; start+=2*len)
         zeta = zetas[k++];
  */

  // FIPS 203 Spec (Algorithm 8, NTT):
  // Uses specific ordering.
  // Let's rely on calculating powers of 17 and bit-reversing index?
  // Or just iterative generation?

  // Standard iterative generation for Kyber NTT bits:
  for (int i = 0; i < 128; i++) {
    // This is tricky to get right without reference logic.
    // Let's compute iteratively:
    // zetas[i] = modular_exponentiation(17, bit_reverse_7bit(i) + 1 ? )
    // Reference: https://github.com/pq-crystals/kyber/blob/master/ref/ntt.c
    // Better: emulate the init logic.
  }

  // Let's implement the `gen_zetas` logic from a reliable source or pre-calculate:
  // zetas[i] = montgomery(root ^ bitrev(i)) ?

  // Wait, I can just copy the table from the official specificiation or reference C code?
  // This script is to VERIFY or GENERATE if I prefer.
  // Let's write the generator based on bit-reversal of 17^i.

  List<int> table = [];
  // Bit reversal of 7 bits (0..127)
  int bitRev7(int x) {
    int r = 0;
    for (int i = 0; i < 7; i++) {
      if ((x & (1 << i)) != 0) r |= (1 << (6 - i));
    }
    return r;
  }

  // montgomery factor R = 2^16 ? No, Kyber uses 16-bit montgomery?
  // Poly.dart uses montgomery.
  // Let's just output raw values in [0, q-1]

  for (int i = 0; i < 128; i++) {
    // In FIPS 203, zetas are used in specific order.
    // The array 'zetas' corresponds to: 17^bitrev(i) ?
    // Actually index 0 is not used in loop, index 1..127.
    // Let's check the loop usage again.
    // k starts at 1.
    // So we need 128 items (0..127), item 0 is usually related to something else or ignored.

    int br = bitRev7(i);
    int val = modPow(root, br, q);
    // Use Raw values for standard modular arithmetic
    table.add(val);
  }
  // Append negated zetas for 128..255
  for (int i = 0; i < 128; i++) {
    int val = table[i];
    int neg = (q - val) % q;
    table.add(neg);
  }

  print('// Generated Zetas (256 entries: BitRev7 and Negated):');
  print('static const List<int> _zetas = [');
  for (int i = 0; i < 256; i += 8) {
    String row = table.sublist(i, i + 8 < 256 ? i + 8 : 256).join(', ');
    print('  $row,');
  }
  print('];');
}

int modPow(int base, int exp, int mod) {
  int res = 1;
  while (exp > 0) {
    if (exp % 2 == 1) res = (res * base) % mod;
    base = (base * base) % mod;
    exp ~/= 2;
  }
  return res;
}

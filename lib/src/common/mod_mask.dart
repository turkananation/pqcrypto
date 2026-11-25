/// Single ±q corrections whose inputs fit in a signed 32-bit word.
///
/// `>> 31` is the sign test. On the VM and dart2wasm a negative int32 yields
/// `-1`. On dart2js the same shift yields the unsigned all-ones value
/// `2^32-1`. Both select `q` under `&` because `q` fits in 32 bits. A mask is
/// not a constant-time guarantee on any of those backends.
///
/// [csubq] is exact for `r` in `[0, 2q)`. [caddq] is exact for `r` in `(-q, q)`.
library;

/// `r - q` when `r >= q`, otherwise `r`.
int csubq(int r, int q) {
  final sn = r - q;
  return r - (q & ~(sn >> 31));
}

/// `r + q` when `r < 0`, otherwise `r`.
int caddq(int r, int q) => r + (q & (r >> 31));

import 'dart:typed_data';

/// Self-contained FIPS 202 Keccak: SHA3-256, SHA3-512, SHAKE128, SHAKE256.
///
/// This replaces the previous dependency on `package:pointycastle` — `pqcrypto`
/// uses only these four Keccak-f[1600] sponge functions, so vendoring them makes
/// the library zero-dependency without touching its public API.
///
/// ## Portability (VM, dart2wasm, dart2js)
///
/// `pqcrypto` targets the web, where `dart2js` represents `int` as a 53-bit IEEE
/// double and bitwise operators act on 32-bit values. Keccak's natural unit is a
/// 64-bit lane, so every lane here is held as two 32-bit halves and all lane
/// arithmetic is done on those halves:
///
///  * State/scratch are `Uint32List`s, so every store truncates to 32 bits
///    natively on all backends (including `dart2js`, where they are real
///    `Uint32Array`s).
///  * Left shifts use the dart2js-safe idiom `((x & (0xFFFFFFFF >> n)) << n)`:
///    the high `n` bits are masked off *before* the shift so the result never
///    exceeds 32 bits (and so is exact as a double). This is the technique used
///    by pointycastle's `ufixnum` (MIT, Legion of the Bouncy Castle), the
///    dependency this file removes; correctness is pinned by the FIPS 202
///    known-answer tests in `test/keccak_test.dart` and the 3000-vector ML-KEM
///    KAT corpus, run on both the VM and the web compilers in CI.
///
/// Keccak is structurally constant-time (a fixed 24 rounds with no
/// secret-dependent branch or memory index); this implementation preserves that
/// property. It is not a side-channel-hardened or CMVP-validated module — see
/// `doc/MLKEM_TESTING.md` for the claim boundary.
///
/// References: FIPS 202 <https://csrc.nist.gov/pubs/fips/202/final>.

const int _mask32 = 0xFFFFFFFF;

/// Iota round constants, as (low 32 bits, high 32 bits) of each 64-bit RC.
final Uint32List _rcLo = Uint32List.fromList(<int>[
  0x00000001,
  0x00008082,
  0x0000808a,
  0x80008000,
  0x0000808b,
  0x80000001,
  0x80008081,
  0x00008009,
  0x0000008a,
  0x00000088,
  0x80008009,
  0x8000000a,
  0x8000808b,
  0x0000008b,
  0x00008089,
  0x00008003,
  0x00008002,
  0x00000080,
  0x0000800a,
  0x8000000a,
  0x80008081,
  0x00008080,
  0x80000001,
  0x80008008,
]);
final Uint32List _rcHi = Uint32List.fromList(<int>[
  0x00000000,
  0x00000000,
  0x80000000,
  0x80000000,
  0x00000000,
  0x00000000,
  0x80000000,
  0x80000000,
  0x00000000,
  0x00000000,
  0x00000000,
  0x00000000,
  0x00000000,
  0x80000000,
  0x80000000,
  0x80000000,
  0x80000000,
  0x80000000,
  0x00000000,
  0x80000000,
  0x80000000,
  0x80000000,
  0x00000000,
  0x80000000,
]);

/// Rho rotation offsets, indexed by lane `x + 5*y` (FIPS 202 Table 2).
const List<int> _rho = <int>[
  0, 1, 62, 28, 27, //
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

/// dart2js-safe 32-bit left shift: pre-mask the high `n` bits so `x << n` stays
/// within 32 bits. Requires `0 <= n < 32` and `0 <= x <= 0xFFFFFFFF`.
int _shl32(int x, int n) => ((x & (_mask32 >> n)) << n) & _mask32;

/// One Keccak-f[1600] permutation, in place on `a` (50 words = 25 lanes × 2).
/// `b`, `c`, `d` are caller-provided scratch (reused across rounds/calls).
void _permute(Uint32List a, Uint32List b, Uint32List c, Uint32List d) {
  for (var round = 0; round < 24; round++) {
    // θ — column parities.
    for (var x = 0; x < 5; x++) {
      var lo = a[2 * x], hi = a[2 * x + 1];
      for (var y = 1; y < 5; y++) {
        final i = x + 5 * y;
        lo ^= a[2 * i];
        hi ^= a[2 * i + 1];
      }
      c[2 * x] = lo;
      c[2 * x + 1] = hi;
    }
    for (var x = 0; x < 5; x++) {
      final x1 = (x + 1) % 5, x4 = (x + 4) % 5;
      final clo = c[2 * x1], chi = c[2 * x1 + 1];
      // D[x] = C[x-1] ^ ROL64(C[x+1], 1)
      d[2 * x] = c[2 * x4] ^ (_shl32(clo, 1) | (chi >> 31));
      d[2 * x + 1] = c[2 * x4 + 1] ^ (_shl32(chi, 1) | (clo >> 31));
    }
    for (var i = 0; i < 25; i++) {
      final dx = (i % 5);
      a[2 * i] ^= d[2 * dx];
      a[2 * i + 1] ^= d[2 * dx + 1];
    }

    // ρ (rotate) + π (permute) → b.
    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        final src = x + 5 * y;
        final dst = y + 5 * ((2 * x + 3 * y) % 5);
        var lo = a[2 * src], hi = a[2 * src + 1];
        var n = _rho[src];
        if (n >= 32) {
          final t = lo;
          lo = hi;
          hi = t;
          n -= 32;
        }
        if (n == 0) {
          b[2 * dst] = lo;
          b[2 * dst + 1] = hi;
        } else {
          b[2 * dst] = _shl32(lo, n) | (hi >> (32 - n));
          b[2 * dst + 1] = _shl32(hi, n) | (lo >> (32 - n));
        }
      }
    }

    // χ — nonlinear row mixing, b → a.
    for (var y = 0; y < 5; y++) {
      final r = 5 * y;
      for (var x = 0; x < 5; x++) {
        final i = r + x;
        final i1 = r + (x + 1) % 5;
        final i2 = r + (x + 2) % 5;
        a[2 * i] = b[2 * i] ^ ((b[2 * i1] ^ _mask32) & b[2 * i2]);
        a[2 * i + 1] =
            b[2 * i + 1] ^ ((b[2 * i1 + 1] ^ _mask32) & b[2 * i2 + 1]);
      }
    }

    // ι — break symmetry with the round constant.
    a[0] ^= _rcLo[round];
    a[1] ^= _rcHi[round];
  }
}

/// XOR a `rateBytes`-aligned block (length a multiple of 8) into the state as
/// little-endian 64-bit lanes. Stores into `Uint32List` truncate to 32 bits.
void _xorBlock(Uint32List a, Uint8List data, int off, int len) {
  var w = 0;
  for (var i = 0; i < len; i += 8) {
    final p = off + i;
    a[2 * w] ^=
        data[p] |
        (data[p + 1] << 8) |
        (data[p + 2] << 16) |
        (data[p + 3] << 24);
    a[2 * w + 1] ^=
        data[p + 4] |
        (data[p + 5] << 8) |
        (data[p + 6] << 16) |
        (data[p + 7] << 24);
    w++;
  }
}

/// Squeeze `len` bytes (little-endian) from the first lanes of the state.
/// Handles arbitrary `len` (not necessarily a multiple of 8).
void _extractBlock(Uint32List a, Uint8List out, int off, int len) {
  for (var i = 0; i < len; i++) {
    final word = ((i & 7) < 4) ? a[2 * (i >> 3)] : a[2 * (i >> 3) + 1];
    out[off + i] = (word >> ((i & 3) * 8)) & 0xFF;
  }
}

/// Core sponge: absorb `input`, apply pad10*1 with `domain`, squeeze `outLen`.
Uint8List _keccak(Uint8List input, int rateBytes, int domain, int outLen) {
  final a = Uint32List(50);
  final b = Uint32List(50);
  final c = Uint32List(10);
  final d = Uint32List(10);

  // Absorb full blocks.
  var offset = 0;
  final n = input.length;
  while (n - offset >= rateBytes) {
    _xorBlock(a, input, offset, rateBytes);
    _permute(a, b, c, d);
    offset += rateBytes;
  }

  // Final block: remaining bytes ‖ domain ‖ pad10*1.
  final block = Uint8List(rateBytes);
  final rem = n - offset;
  block.setRange(0, rem, input, offset);
  block[rem] = domain;
  block[rateBytes - 1] ^= 0x80;
  _xorBlock(a, block, 0, rateBytes);
  _permute(a, b, c, d);

  // Squeeze.
  final out = Uint8List(outLen);
  var got = 0;
  while (got < outLen) {
    final take = (outLen - got) < rateBytes ? (outLen - got) : rateBytes;
    _extractBlock(a, out, got, take);
    got += take;
    if (got < outLen) _permute(a, b, c, d);
  }
  return out;
}

/// SHA3-256 (FIPS 202): 32-byte digest, rate 136 bytes, domain `0x06`.
Uint8List sha3256(Uint8List input) => _keccak(input, 136, 0x06, 32);

/// SHA3-512 (FIPS 202): 64-byte digest, rate 72 bytes, domain `0x06`.
Uint8List sha3512(Uint8List input) => _keccak(input, 72, 0x06, 64);

/// SHAKE128 (FIPS 202): XOF, rate 168 bytes, domain `0x1F`.
Uint8List shake128(Uint8List input, int outLen) =>
    _keccak(input, 168, 0x1F, outLen);

/// SHAKE256 (FIPS 202): XOF, rate 136 bytes, domain `0x1F`.
Uint8List shake256(Uint8List input, int outLen) =>
    _keccak(input, 136, 0x1F, outLen);

import 'dart:typed_data';

import 'keccak_parameters.dart';
import 'zeroize.dart';

/// Self-contained FIPS 202 SHA3-224/256/384/512 and SHAKE128/256.
///
/// This replaces the previous dependency on `package:pointycastle` — `pqcrypto`
/// Vendoring the Keccak-f[1600] sponge keeps the library zero-dependency
/// without exposing these package-internal primitives through `pqcrypto.dart`.
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
/// Keccak-f[1600] executes a fixed 24-round permutation. This implementation is
/// not a side-channel-hardened or CMVP-validated module; see
/// `doc/FIPS_140_BOUNDARY.md` for the claim boundary.
///
/// References: FIPS 202 <https://csrc.nist.gov/pubs/fips/202/final>.

const int _mask32 = 0xFFFFFFFF;

/// dart2js-safe 32-bit left shift: pre-mask the high `n` bits so `x << n` stays
/// within 32 bits. Requires `0 <= n < 32` and `0 <= x <= 0xFFFFFFFF`.
int _shl32(int x, int n) => ((x & (_mask32 >> n)) << n) & _mask32;

/// One Keccak-f[1600] permutation, in place on `a` (50 words = 25 lanes × 2).
/// `b`, `c`, `d` are caller-provided scratch (reused across rounds/calls).
void _permute(Uint32List a, Uint32List b, Uint32List c, Uint32List d) {
  for (var round = 0; round < KeccakF1600Parameters.rounds; round++) {
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
        var n = KeccakF1600Parameters.rhoOffsets[src];
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
    a[0] ^= KeccakF1600Parameters.roundConstantsLow32[round];
    a[1] ^= KeccakF1600Parameters.roundConstantsHigh32[round];
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
  _validateSpongeArguments(rateBytes, domain);
  _validateOutputLength(outLen);

  final a = Uint32List(50);
  final b = Uint32List(50);
  final c = Uint32List(10);
  final d = Uint32List(10);
  final block = Uint8List(rateBytes);
  try {
    // Absorb full blocks.
    var offset = 0;
    final n = input.length;
    while (n - offset >= rateBytes) {
      _xorBlock(a, input, offset, rateBytes);
      _permute(a, b, c, d);
      offset += rateBytes;
    }

    // Final block: remaining bytes ‖ domain ‖ pad10*1.
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
  } finally {
    secureZeroUint32(a);
    secureZeroUint32(b);
    secureZeroUint32(c);
    secureZeroUint32(d);
    secureZero(block);
  }
}

/// Incremental Keccak sponge in XOF (squeeze) mode.
///
/// Absorbs the whole input and pads once at construction, then yields output
/// bytes on demand via [squeeze]/[squeezeByte]. The byte stream is identical to
/// the one-shot [_keccak] for the same input/rate/domain, so it is a drop-in
/// for rejection samplers that must never exhaust a fixed buffer (FIPS 204
/// `H.Squeeze`). Structurally constant-time like [_keccak].
class KeccakXof {
  final Uint32List _a = Uint32List(50);
  final Uint32List _b = Uint32List(50);
  final Uint32List _c = Uint32List(10);
  final Uint32List _d = Uint32List(10);
  final int _rate;
  final Uint8List _buf;
  int _pos = 0;

  factory KeccakXof(Uint8List input, int rateBytes, int domain) {
    _validateSpongeArguments(rateBytes, domain);
    return KeccakXof._validated(input, rateBytes, domain);
  }

  KeccakXof._validated(Uint8List input, int rateBytes, int domain)
    : _rate = rateBytes,
      _buf = Uint8List(rateBytes) {
    var offset = 0;
    final n = input.length;
    while (n - offset >= rateBytes) {
      _xorBlock(_a, input, offset, rateBytes);
      _permute(_a, _b, _c, _d);
      offset += rateBytes;
    }
    final block = Uint8List(rateBytes);
    try {
      final rem = n - offset;
      block.setRange(0, rem, input, offset);
      block[rem] = domain;
      block[rateBytes - 1] ^= 0x80;
      _xorBlock(_a, block, 0, rateBytes);
      _permute(_a, _b, _c, _d);
    } finally {
      secureZero(block);
    }
    _extractBlock(_a, _buf, 0, rateBytes);
  }

  void _refill() {
    _permute(_a, _b, _c, _d);
    _extractBlock(_a, _buf, 0, _rate);
    _pos = 0;
  }

  /// Squeeze the next [len] output bytes.
  Uint8List squeeze(int len) {
    _validateOutputLength(len);
    final out = Uint8List(len);
    var got = 0;
    while (got < len) {
      if (_pos == _rate) _refill();
      final avail = _rate - _pos;
      final take = (len - got) < avail ? (len - got) : avail;
      out.setRange(got, got + take, _buf, _pos);
      got += take;
      _pos += take;
    }
    return out;
  }

  /// Squeeze a single output byte.
  int squeezeByte() {
    if (_pos == _rate) _refill();
    return _buf[_pos++];
  }
}

void _validateSpongeArguments(int rateBytes, int domain) {
  if (rateBytes <= 0 ||
      rateBytes >= KeccakF1600Parameters.stateBits ~/ 8 ||
      rateBytes % 8 != 0) {
    throw ArgumentError.value(
      rateBytes,
      'rateBytes',
      'must be a positive multiple of 8 smaller than 200',
    );
  }
  if (domain <= 0 || domain >= 0x80) {
    throw ArgumentError.value(
      domain,
      'domain',
      'must be a non-zero delimited suffix smaller than 0x80',
    );
  }
}

void _validateOutputLength(int outLen) {
  if (outLen < 0) {
    throw RangeError.range(outLen, 0, null, 'outLen');
  }
}

/// SHAKE128 incremental XOF (rate 168 bytes, domain `0x1F`).
KeccakXof shake128Xof(Uint8List input) => KeccakXof(
  input,
  Fips202Parameters.shake128.rateBytes,
  Fips202Parameters.shake128.domain,
);

/// SHAKE256 incremental XOF (rate 136 bytes, domain `0x1F`).
KeccakXof shake256Xof(Uint8List input) => KeccakXof(
  input,
  Fips202Parameters.shake256.rateBytes,
  Fips202Parameters.shake256.domain,
);

/// SHA3-224 (FIPS 202): 28-byte digest.
Uint8List sha3224(Uint8List input) =>
    _fixedDigest(input, Fips202Parameters.sha3224);

/// SHA3-256 (FIPS 202): 32-byte digest.
Uint8List sha3256(Uint8List input) =>
    _fixedDigest(input, Fips202Parameters.sha3256);

/// SHA3-384 (FIPS 202): 48-byte digest.
Uint8List sha3384(Uint8List input) =>
    _fixedDigest(input, Fips202Parameters.sha3384);

/// SHA3-512 (FIPS 202): 64-byte digest.
Uint8List sha3512(Uint8List input) =>
    _fixedDigest(input, Fips202Parameters.sha3512);

/// SHAKE128 (FIPS 202): XOF, rate 168 bytes, domain `0x1F`.
Uint8List shake128(Uint8List input, int outLen) =>
    _xof(input, Fips202Parameters.shake128, outLen);

/// SHAKE256 (FIPS 202): XOF, rate 136 bytes, domain `0x1F`.
Uint8List shake256(Uint8List input, int outLen) =>
    _xof(input, Fips202Parameters.shake256, outLen);

Uint8List _fixedDigest(Uint8List input, Fips202Parameters parameters) =>
    _keccak(
      input,
      parameters.rateBytes,
      parameters.domain,
      parameters.digestBytes!,
    );

Uint8List _xof(Uint8List input, Fips202Parameters parameters, int outLen) =>
    _keccak(input, parameters.rateBytes, parameters.domain, outLen);

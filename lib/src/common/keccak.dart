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

/// Keccak-f[1600], in place on [a]. [b] is scratch.
///
/// Lanes stay two 32-bit halves. Rho offsets are baked in, so a round does
/// not branch on the rotation count. Indexes are constants.
void _permute(Uint32List a, Uint32List b) {
  for (var round = 0; round < KeccakF1600Parameters.rounds; round++) {
    final c0Lo = a[0] ^ a[10] ^ a[20] ^ a[30] ^ a[40];
    final c0Hi = a[1] ^ a[11] ^ a[21] ^ a[31] ^ a[41];
    final c1Lo = a[2] ^ a[12] ^ a[22] ^ a[32] ^ a[42];
    final c1Hi = a[3] ^ a[13] ^ a[23] ^ a[33] ^ a[43];
    final c2Lo = a[4] ^ a[14] ^ a[24] ^ a[34] ^ a[44];
    final c2Hi = a[5] ^ a[15] ^ a[25] ^ a[35] ^ a[45];
    final c3Lo = a[6] ^ a[16] ^ a[26] ^ a[36] ^ a[46];
    final c3Hi = a[7] ^ a[17] ^ a[27] ^ a[37] ^ a[47];
    final c4Lo = a[8] ^ a[18] ^ a[28] ^ a[38] ^ a[48];
    final c4Hi = a[9] ^ a[19] ^ a[29] ^ a[39] ^ a[49];
    // D[x] = C[x - 1] ^ ROL64(C[x + 1], 1).
    final d0Lo = c4Lo ^ (_shl32(c1Lo, 1) | (c1Hi >> 31));
    final d0Hi = c4Hi ^ (_shl32(c1Hi, 1) | (c1Lo >> 31));
    final d1Lo = c0Lo ^ (_shl32(c2Lo, 1) | (c2Hi >> 31));
    final d1Hi = c0Hi ^ (_shl32(c2Hi, 1) | (c2Lo >> 31));
    final d2Lo = c1Lo ^ (_shl32(c3Lo, 1) | (c3Hi >> 31));
    final d2Hi = c1Hi ^ (_shl32(c3Hi, 1) | (c3Lo >> 31));
    final d3Lo = c2Lo ^ (_shl32(c4Lo, 1) | (c4Hi >> 31));
    final d3Hi = c2Hi ^ (_shl32(c4Hi, 1) | (c4Lo >> 31));
    final d4Lo = c3Lo ^ (_shl32(c0Lo, 1) | (c0Hi >> 31));
    final d4Hi = c3Hi ^ (_shl32(c0Hi, 1) | (c0Lo >> 31));
    a[0] ^= d0Lo;
    a[1] ^= d0Hi;
    a[2] ^= d1Lo;
    a[3] ^= d1Hi;
    a[4] ^= d2Lo;
    a[5] ^= d2Hi;
    a[6] ^= d3Lo;
    a[7] ^= d3Hi;
    a[8] ^= d4Lo;
    a[9] ^= d4Hi;
    a[10] ^= d0Lo;
    a[11] ^= d0Hi;
    a[12] ^= d1Lo;
    a[13] ^= d1Hi;
    a[14] ^= d2Lo;
    a[15] ^= d2Hi;
    a[16] ^= d3Lo;
    a[17] ^= d3Hi;
    a[18] ^= d4Lo;
    a[19] ^= d4Hi;
    a[20] ^= d0Lo;
    a[21] ^= d0Hi;
    a[22] ^= d1Lo;
    a[23] ^= d1Hi;
    a[24] ^= d2Lo;
    a[25] ^= d2Hi;
    a[26] ^= d3Lo;
    a[27] ^= d3Hi;
    a[28] ^= d4Lo;
    a[29] ^= d4Hi;
    a[30] ^= d0Lo;
    a[31] ^= d0Hi;
    a[32] ^= d1Lo;
    a[33] ^= d1Hi;
    a[34] ^= d2Lo;
    a[35] ^= d2Hi;
    a[36] ^= d3Lo;
    a[37] ^= d3Hi;
    a[38] ^= d4Lo;
    a[39] ^= d4Hi;
    a[40] ^= d0Lo;
    a[41] ^= d0Hi;
    a[42] ^= d1Lo;
    a[43] ^= d1Hi;
    a[44] ^= d2Lo;
    a[45] ^= d2Hi;
    a[46] ^= d3Lo;
    a[47] ^= d3Hi;
    a[48] ^= d4Lo;
    a[49] ^= d4Hi;

    b[0] = a[0];
    b[1] = a[1];
    b[20] = _shl32(a[2], 1) | (a[3] >> 31);
    b[21] = _shl32(a[3], 1) | (a[2] >> 31);
    b[40] = _shl32(a[5], 30) | (a[4] >> 2);
    b[41] = _shl32(a[4], 30) | (a[5] >> 2);
    b[10] = _shl32(a[6], 28) | (a[7] >> 4);
    b[11] = _shl32(a[7], 28) | (a[6] >> 4);
    b[30] = _shl32(a[8], 27) | (a[9] >> 5);
    b[31] = _shl32(a[9], 27) | (a[8] >> 5);
    b[32] = _shl32(a[11], 4) | (a[10] >> 28);
    b[33] = _shl32(a[10], 4) | (a[11] >> 28);
    b[2] = _shl32(a[13], 12) | (a[12] >> 20);
    b[3] = _shl32(a[12], 12) | (a[13] >> 20);
    b[22] = _shl32(a[14], 6) | (a[15] >> 26);
    b[23] = _shl32(a[15], 6) | (a[14] >> 26);
    b[42] = _shl32(a[17], 23) | (a[16] >> 9);
    b[43] = _shl32(a[16], 23) | (a[17] >> 9);
    b[12] = _shl32(a[18], 20) | (a[19] >> 12);
    b[13] = _shl32(a[19], 20) | (a[18] >> 12);
    b[14] = _shl32(a[20], 3) | (a[21] >> 29);
    b[15] = _shl32(a[21], 3) | (a[20] >> 29);
    b[34] = _shl32(a[22], 10) | (a[23] >> 22);
    b[35] = _shl32(a[23], 10) | (a[22] >> 22);
    b[4] = _shl32(a[25], 11) | (a[24] >> 21);
    b[5] = _shl32(a[24], 11) | (a[25] >> 21);
    b[24] = _shl32(a[26], 25) | (a[27] >> 7);
    b[25] = _shl32(a[27], 25) | (a[26] >> 7);
    b[44] = _shl32(a[29], 7) | (a[28] >> 25);
    b[45] = _shl32(a[28], 7) | (a[29] >> 25);
    b[46] = _shl32(a[31], 9) | (a[30] >> 23);
    b[47] = _shl32(a[30], 9) | (a[31] >> 23);
    b[16] = _shl32(a[33], 13) | (a[32] >> 19);
    b[17] = _shl32(a[32], 13) | (a[33] >> 19);
    b[36] = _shl32(a[34], 15) | (a[35] >> 17);
    b[37] = _shl32(a[35], 15) | (a[34] >> 17);
    b[6] = _shl32(a[36], 21) | (a[37] >> 11);
    b[7] = _shl32(a[37], 21) | (a[36] >> 11);
    b[26] = _shl32(a[38], 8) | (a[39] >> 24);
    b[27] = _shl32(a[39], 8) | (a[38] >> 24);
    b[28] = _shl32(a[40], 18) | (a[41] >> 14);
    b[29] = _shl32(a[41], 18) | (a[40] >> 14);
    b[48] = _shl32(a[42], 2) | (a[43] >> 30);
    b[49] = _shl32(a[43], 2) | (a[42] >> 30);
    b[18] = _shl32(a[45], 29) | (a[44] >> 3);
    b[19] = _shl32(a[44], 29) | (a[45] >> 3);
    b[38] = _shl32(a[47], 24) | (a[46] >> 8);
    b[39] = _shl32(a[46], 24) | (a[47] >> 8);
    b[8] = _shl32(a[48], 14) | (a[49] >> 18);
    b[9] = _shl32(a[49], 14) | (a[48] >> 18);

    a[0] = b[0] ^ ((b[2] ^ _mask32) & b[4]);
    a[1] = b[1] ^ ((b[3] ^ _mask32) & b[5]);
    a[2] = b[2] ^ ((b[4] ^ _mask32) & b[6]);
    a[3] = b[3] ^ ((b[5] ^ _mask32) & b[7]);
    a[4] = b[4] ^ ((b[6] ^ _mask32) & b[8]);
    a[5] = b[5] ^ ((b[7] ^ _mask32) & b[9]);
    a[6] = b[6] ^ ((b[8] ^ _mask32) & b[0]);
    a[7] = b[7] ^ ((b[9] ^ _mask32) & b[1]);
    a[8] = b[8] ^ ((b[0] ^ _mask32) & b[2]);
    a[9] = b[9] ^ ((b[1] ^ _mask32) & b[3]);
    a[10] = b[10] ^ ((b[12] ^ _mask32) & b[14]);
    a[11] = b[11] ^ ((b[13] ^ _mask32) & b[15]);
    a[12] = b[12] ^ ((b[14] ^ _mask32) & b[16]);
    a[13] = b[13] ^ ((b[15] ^ _mask32) & b[17]);
    a[14] = b[14] ^ ((b[16] ^ _mask32) & b[18]);
    a[15] = b[15] ^ ((b[17] ^ _mask32) & b[19]);
    a[16] = b[16] ^ ((b[18] ^ _mask32) & b[10]);
    a[17] = b[17] ^ ((b[19] ^ _mask32) & b[11]);
    a[18] = b[18] ^ ((b[10] ^ _mask32) & b[12]);
    a[19] = b[19] ^ ((b[11] ^ _mask32) & b[13]);
    a[20] = b[20] ^ ((b[22] ^ _mask32) & b[24]);
    a[21] = b[21] ^ ((b[23] ^ _mask32) & b[25]);
    a[22] = b[22] ^ ((b[24] ^ _mask32) & b[26]);
    a[23] = b[23] ^ ((b[25] ^ _mask32) & b[27]);
    a[24] = b[24] ^ ((b[26] ^ _mask32) & b[28]);
    a[25] = b[25] ^ ((b[27] ^ _mask32) & b[29]);
    a[26] = b[26] ^ ((b[28] ^ _mask32) & b[20]);
    a[27] = b[27] ^ ((b[29] ^ _mask32) & b[21]);
    a[28] = b[28] ^ ((b[20] ^ _mask32) & b[22]);
    a[29] = b[29] ^ ((b[21] ^ _mask32) & b[23]);
    a[30] = b[30] ^ ((b[32] ^ _mask32) & b[34]);
    a[31] = b[31] ^ ((b[33] ^ _mask32) & b[35]);
    a[32] = b[32] ^ ((b[34] ^ _mask32) & b[36]);
    a[33] = b[33] ^ ((b[35] ^ _mask32) & b[37]);
    a[34] = b[34] ^ ((b[36] ^ _mask32) & b[38]);
    a[35] = b[35] ^ ((b[37] ^ _mask32) & b[39]);
    a[36] = b[36] ^ ((b[38] ^ _mask32) & b[30]);
    a[37] = b[37] ^ ((b[39] ^ _mask32) & b[31]);
    a[38] = b[38] ^ ((b[30] ^ _mask32) & b[32]);
    a[39] = b[39] ^ ((b[31] ^ _mask32) & b[33]);
    a[40] = b[40] ^ ((b[42] ^ _mask32) & b[44]);
    a[41] = b[41] ^ ((b[43] ^ _mask32) & b[45]);
    a[42] = b[42] ^ ((b[44] ^ _mask32) & b[46]);
    a[43] = b[43] ^ ((b[45] ^ _mask32) & b[47]);
    a[44] = b[44] ^ ((b[46] ^ _mask32) & b[48]);
    a[45] = b[45] ^ ((b[47] ^ _mask32) & b[49]);
    a[46] = b[46] ^ ((b[48] ^ _mask32) & b[40]);
    a[47] = b[47] ^ ((b[49] ^ _mask32) & b[41]);
    a[48] = b[48] ^ ((b[40] ^ _mask32) & b[42]);
    a[49] = b[49] ^ ((b[41] ^ _mask32) & b[43]);
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

  final scratch = _leaseScratch();
  final a = scratch.a;
  final b = scratch.b;
  final block = scratch.block;
  try {
    // Absorb full blocks.
    var offset = 0;
    final n = input.length;
    while (n - offset >= rateBytes) {
      _xorBlock(a, input, offset, rateBytes);
      _permute(a, b);
      offset += rateBytes;
    }

    // Final block: remaining bytes ‖ domain ‖ pad10*1.
    // [block] is zero from the lease. Only [rateBytes] of it are absorbed.
    final rem = n - offset;
    block.setRange(0, rem, input, offset);
    block[rem] = domain;
    block[rateBytes - 1] ^= 0x80;
    _xorBlock(a, block, 0, rateBytes);
    _permute(a, b);

    // Squeeze.
    final out = Uint8List(outLen);
    var got = 0;
    while (got < outLen) {
      final take = (outLen - got) < rateBytes ? (outLen - got) : rateBytes;
      _extractBlock(a, out, got, take);
      got += take;
      if (got < outLen) _permute(a, b);
    }
    return out;
  } finally {
    _recycleScratch(scratch);
  }
}

/// One reused Keccak workspace per isolate.
///
/// One-shot hashes borrow it and wipe it before the next borrow. A nested
/// call allocates its own. [KeccakXof] does not use this: its state has to
/// outlive one call. The wipe is best-effort, same as [secureZeroUint32].
final class _Scratch {
  final Uint32List a = Uint32List(50);
  final Uint32List b = Uint32List(50);

  /// Largest rate [_validateSpongeArguments] accepts: 192.
  final Uint8List block = Uint8List(192);
}

_Scratch? _idleScratch;

_Scratch _leaseScratch() {
  final idle = _idleScratch;
  if (idle != null) {
    _idleScratch = null;
    return idle;
  }
  return _Scratch();
}

void _recycleScratch(_Scratch scratch) {
  secureZeroUint32(scratch.a);
  secureZeroUint32(scratch.b);
  secureZero(scratch.block);
  _idleScratch ??= scratch;
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
      _permute(_a, _b);
      offset += rateBytes;
    }
    final block = Uint8List(rateBytes);
    try {
      final rem = n - offset;
      block.setRange(0, rem, input, offset);
      block[rem] = domain;
      block[rateBytes - 1] ^= 0x80;
      _xorBlock(_a, block, 0, rateBytes);
      _permute(_a, _b);
    } finally {
      secureZero(block);
    }
    _extractBlock(_a, _buf, 0, rateBytes);
  }

  void _refill() {
    _permute(_a, _b);
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

/// One-shot byte sponge with an explicit delimited suffix.
///
/// [domain] is written in the first byte after [input]. The final `pad10*1`
/// bit is `0x80` at the end of the rate block, including when both land in
/// the same byte. [shake128] and [shake256] keep domain `0x1F` and still go
/// through [_xof]. cSHAKE passes `0x04` for a byte string: suffix bits `00`
/// followed by the first bit of `pad10*1`.
///
/// This is not exported from `package:pqcrypto/pqcrypto.dart`.
Uint8List keccakAbsorbBytes(
  Uint8List input,
  int rateBytes,
  int domain,
  int outputLength,
) => _keccak(input, rateBytes, domain, outputLength);

/// Absorbs a FIPS 202 bit string and returns [outputBytes] bytes.
///
/// [messageBits] is in absorption order. The first bit becomes the least
/// significant bit of the first byte. [suffixBits] is the domain suffix in
/// that same order: `0, 1` for SHA3 and `1, 1, 1, 1` for SHAKE. The padding
/// rule is FIPS 202 `pad10*1`.
///
/// The byte-oriented wrappers in this file are unchanged. This entry exists
/// so the NIST examples whose length is not a multiple of 8 can be checked.
/// It is not exported from `package:pqcrypto/pqcrypto.dart`.
Uint8List fips202AbsorbBits({
  required List<int> messageBits,
  required int rateBytes,
  required List<int> suffixBits,
  required int outputBytes,
}) {
  if (rateBytes <= 0 ||
      rateBytes >= KeccakF1600Parameters.stateBits ~/ 8 ||
      rateBytes % 8 != 0) {
    throw ArgumentError.value(
      rateBytes,
      'rateBytes',
      'must be a positive multiple of 8 smaller than 200',
    );
  }
  _validateOutputLength(outputBytes);
  _requireBits(messageBits, 'messageBits');
  _requireBits(suffixBits, 'suffixBits');
  if (suffixBits.isEmpty) {
    throw ArgumentError.value(suffixBits, 'suffixBits', 'must be non-empty');
  }

  final rateBits = rateBytes * 8;
  final bodyBits = messageBits.length + suffixBits.length;
  final zeroPad = _nonNegativeMod(-bodyBits - 2, rateBits);
  final totalBits = bodyBits + 2 + zeroPad;
  final packed = Uint8List(totalBits >> 3);
  final scratch = _leaseScratch();
  final state = scratch.a;
  final scratchB = scratch.b;
  try {
    var bitIndex = 0;
    void writeBit(int bit) {
      if (bit != 0) {
        packed[bitIndex >> 3] |= 1 << (bitIndex & 7);
      }
      bitIndex++;
    }

    for (final bit in messageBits) {
      writeBit(bit);
    }
    for (final bit in suffixBits) {
      writeBit(bit);
    }
    writeBit(1);
    for (var i = 0; i < zeroPad; i++) {
      writeBit(0);
    }
    writeBit(1);

    for (var offset = 0; offset < packed.length; offset += rateBytes) {
      _xorBlock(state, packed, offset, rateBytes);
      _permute(state, scratchB);
    }

    final out = Uint8List(outputBytes);
    var got = 0;
    while (got < outputBytes) {
      final take = (outputBytes - got) < rateBytes
          ? (outputBytes - got)
          : rateBytes;
      _extractBlock(state, out, got, take);
      got += take;
      if (got < outputBytes) {
        _permute(state, scratchB);
      }
    }
    return out;
  } finally {
    secureZero(packed);
    _recycleScratch(scratch);
  }
}

void _requireBits(List<int> bits, String name) {
  for (final bit in bits) {
    if (bit != 0 && bit != 1) {
      throw ArgumentError.value(bit, name, 'must contain only 0 and 1');
    }
  }
}

int _nonNegativeMod(int value, int modulus) {
  final remainder = value % modulus;
  return remainder < 0 ? remainder + modulus : remainder;
}

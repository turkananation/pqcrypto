/// FIPS 180-4 SHA-2 (SHA-256, SHA-384, SHA-512), vendored in pure Dart.
///
/// SHA-512/384 use 64-bit words represented as 32-bit (hi, lo) pairs so the
/// implementation is byte-exact on the Dart VM, dart2js, and dart2wasm
/// (dart2js native integers are 53-bit and cannot hold 64-bit words directly).
///
/// These are needed by FIPS 204 HashML-DSA (§5.4) as the pre-hash functions.
library;

import 'dart:typed_data';

// ===========================================================================
// SHA-256
// ===========================================================================

const List<int> _k256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, //
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, //
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, //
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, //
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, //
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, //
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, //
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, //
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, //
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, //
];

int _rotr32(int x, int n) => ((x >>> n) | (x << (32 - n))) & 0xFFFFFFFF;

/// FIPS 180-4 SHA-256. Returns a 32-byte digest.
Uint8List sha256(Uint8List msg) {
  final h = Uint32List.fromList([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  // Pad: 0x80, zeros, 64-bit big-endian bit length, to a multiple of 64 bytes.
  final bitLen = msg.length * 8;
  final padLen = ((msg.length + 8) ~/ 64 + 1) * 64;
  final data = Uint8List(padLen)..setRange(0, msg.length, msg);
  data[msg.length] = 0x80;
  for (int i = 0; i < 8; i++) {
    data[padLen - 1 - i] = (bitLen >>> (8 * i)) & 0xFF;
  }

  final w = Uint32List(64);
  for (int off = 0; off < padLen; off += 64) {
    for (int t = 0; t < 16; t++) {
      final j = off + t * 4;
      w[t] =
          ((data[j] << 24) |
              (data[j + 1] << 16) |
              (data[j + 2] << 8) |
              data[j + 3]) &
          0xFFFFFFFF;
    }
    for (int t = 16; t < 64; t++) {
      final s0 =
          _rotr32(w[t - 15], 7) ^ _rotr32(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      final s1 =
          _rotr32(w[t - 2], 17) ^ _rotr32(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xFFFFFFFF;
    }

    int a = h[0], b = h[1], c = h[2], dd = h[3];
    int e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
      final s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25);
      final ch = (e & f) ^ (~e & g);
      final t1 = (hh + s1 + ch + _k256[t] + w[t]) & 0xFFFFFFFF;
      final s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & 0xFFFFFFFF;
      hh = g;
      g = f;
      f = e;
      e = (dd + t1) & 0xFFFFFFFF;
      dd = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xFFFFFFFF;
    }
    h[0] = (h[0] + a) & 0xFFFFFFFF;
    h[1] = (h[1] + b) & 0xFFFFFFFF;
    h[2] = (h[2] + c) & 0xFFFFFFFF;
    h[3] = (h[3] + dd) & 0xFFFFFFFF;
    h[4] = (h[4] + e) & 0xFFFFFFFF;
    h[5] = (h[5] + f) & 0xFFFFFFFF;
    h[6] = (h[6] + g) & 0xFFFFFFFF;
    h[7] = (h[7] + hh) & 0xFFFFFFFF;
  }

  final out = Uint8List(32);
  for (int i = 0; i < 8; i++) {
    final v = h[i] & 0xFFFFFFFF;
    out[i * 4] = (v >>> 24) & 0xFF;
    out[i * 4 + 1] = (v >>> 16) & 0xFF;
    out[i * 4 + 2] = (v >>> 8) & 0xFF;
    out[i * 4 + 3] = v & 0xFF;
  }
  return out;
}

// ===========================================================================
// SHA-512 / SHA-384 (64-bit words as 32-bit (hi, lo) pairs)
// ===========================================================================

// Round constants (hi, lo interleaved): 80 words -> 160 ints.
final Uint32List _k512 = Uint32List.fromList(<int>[
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, //
  0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, //
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242, //
  0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2, //
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, //
  0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, //
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275, //
  0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5, //
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, //
  0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, //
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc, //
  0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df, //
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, //
  0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, //
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218, //
  0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8, //
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, //
  0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, //
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc, //
  0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec, //
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, //
  0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, //
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba, //
  0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b, //
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, //
  0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, //
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817, //
]);

// rotate-right of a 64-bit (hi,lo) by n in (0,64), result into out[0],out[1].
void _rotr64(int hi, int lo, int n, List<int> out) {
  if (n == 32) {
    out[0] = lo & 0xFFFFFFFF;
    out[1] = hi & 0xFFFFFFFF;
  } else if (n < 32) {
    out[0] = ((hi >>> n) | (lo << (32 - n))) & 0xFFFFFFFF;
    out[1] = ((lo >>> n) | (hi << (32 - n))) & 0xFFFFFFFF;
  } else {
    final m = n - 32;
    out[0] = ((lo >>> m) | (hi << (32 - m))) & 0xFFFFFFFF;
    out[1] = ((hi >>> m) | (lo << (32 - m))) & 0xFFFFFFFF;
  }
}

// logical shift-right of a 64-bit (hi,lo) by n in (0,64).
void _shr64(int hi, int lo, int n, List<int> out) {
  if (n < 32) {
    out[0] = (hi >>> n) & 0xFFFFFFFF;
    out[1] = ((lo >>> n) | (hi << (32 - n))) & 0xFFFFFFFF;
  } else {
    out[0] = 0;
    out[1] = (hi >>> (n - 32)) & 0xFFFFFFFF;
  }
}

Uint8List _sha512Core(Uint8List msg, List<int> h, int outBytes) {
  final bitLen = msg.length * 8;
  // 128-bit length field; messages here are far below 2^32 bytes.
  final padLen = ((msg.length + 16) ~/ 128 + 1) * 128;
  final data = Uint8List(padLen)..setRange(0, msg.length, msg);
  data[msg.length] = 0x80;
  for (int i = 0; i < 8; i++) {
    data[padLen - 1 - i] = (bitLen >>> (8 * i)) & 0xFF;
  }

  final wHi = Uint32List(80), wLo = Uint32List(80);
  final r = List<int>.filled(2, 0);
  final r2 = List<int>.filled(2, 0);
  final r3 = List<int>.filled(2, 0);

  for (int off = 0; off < padLen; off += 128) {
    for (int t = 0; t < 16; t++) {
      final j = off + t * 8;
      wHi[t] =
          ((data[j] << 24) |
              (data[j + 1] << 16) |
              (data[j + 2] << 8) |
              data[j + 3]) &
          0xFFFFFFFF;
      wLo[t] =
          ((data[j + 4] << 24) |
              (data[j + 5] << 16) |
              (data[j + 6] << 8) |
              data[j + 7]) &
          0xFFFFFFFF;
    }
    for (int t = 16; t < 80; t++) {
      // sigma0(w[t-15]) = rotr(1) ^ rotr(8) ^ shr(7)
      _rotr64(wHi[t - 15], wLo[t - 15], 1, r);
      _rotr64(wHi[t - 15], wLo[t - 15], 8, r2);
      _shr64(wHi[t - 15], wLo[t - 15], 7, r3);
      final s0h = r[0] ^ r2[0] ^ r3[0];
      final s0l = r[1] ^ r2[1] ^ r3[1];
      // sigma1(w[t-2]) = rotr(19) ^ rotr(61) ^ shr(6)
      _rotr64(wHi[t - 2], wLo[t - 2], 19, r);
      _rotr64(wHi[t - 2], wLo[t - 2], 61, r2);
      _shr64(wHi[t - 2], wLo[t - 2], 6, r3);
      final s1h = r[0] ^ r2[0] ^ r3[0];
      final s1l = r[1] ^ r2[1] ^ r3[1];
      // w[t] = w[t-16] + s0 + w[t-7] + s1
      int lo =
          (wLo[t - 16] & 0xFFFF) +
          (s0l & 0xFFFF) +
          (wLo[t - 7] & 0xFFFF) +
          (s1l & 0xFFFF);
      int hi =
          (wLo[t - 16] >>> 16) +
          (s0l >>> 16) +
          (wLo[t - 7] >>> 16) +
          (s1l >>> 16) +
          (lo >>> 16);
      final outLo = ((hi & 0xFFFF) << 16 | (lo & 0xFFFF)) & 0xFFFFFFFF;
      int hi2 =
          (wHi[t - 16] & 0xFFFF) +
          (s0h & 0xFFFF) +
          (wHi[t - 7] & 0xFFFF) +
          (s1h & 0xFFFF) +
          (hi >>> 16);
      int hi3 =
          (wHi[t - 16] >>> 16) +
          (s0h >>> 16) +
          (wHi[t - 7] >>> 16) +
          (s1h >>> 16) +
          (hi2 >>> 16);
      wHi[t] = ((hi3 & 0xFFFF) << 16 | (hi2 & 0xFFFF)) & 0xFFFFFFFF;
      wLo[t] = outLo;
    }

    int aH = h[0], aL = h[1], bH = h[2], bL = h[3];
    int cH = h[4], cL = h[5], dH = h[6], dL = h[7];
    int eH = h[8], eL = h[9], fH = h[10], fL = h[11];
    int gH = h[12], gL = h[13], hH = h[14], hL = h[15];

    for (int t = 0; t < 80; t++) {
      // Sigma1(e) = rotr(14) ^ rotr(18) ^ rotr(41)
      _rotr64(eH, eL, 14, r);
      _rotr64(eH, eL, 18, r2);
      _rotr64(eH, eL, 41, r3);
      final sig1H = r[0] ^ r2[0] ^ r3[0];
      final sig1L = r[1] ^ r2[1] ^ r3[1];
      final chH = (eH & fH) ^ (~eH & gH);
      final chL = (eL & fL) ^ (~eL & gL);
      // T1 = h + Sigma1(e) + ch + K[t] + W[t]
      int lo =
          (hL & 0xFFFF) +
          (sig1L & 0xFFFF) +
          (chL & 0xFFFF) +
          (_k512[t * 2 + 1] & 0xFFFF) +
          (wLo[t] & 0xFFFF);
      int hi =
          (hL >>> 16) +
          (sig1L >>> 16) +
          (chL >>> 16) +
          (_k512[t * 2 + 1] >>> 16) +
          (wLo[t] >>> 16) +
          (lo >>> 16);
      final t1L = ((hi & 0xFFFF) << 16 | (lo & 0xFFFF)) & 0xFFFFFFFF;
      int hi2 =
          (hH & 0xFFFF) +
          (sig1H & 0xFFFF) +
          (chH & 0xFFFF) +
          (_k512[t * 2] & 0xFFFF) +
          (wHi[t] & 0xFFFF) +
          (hi >>> 16);
      int hi3 =
          (hH >>> 16) +
          (sig1H >>> 16) +
          (chH >>> 16) +
          (_k512[t * 2] >>> 16) +
          (wHi[t] >>> 16) +
          (hi2 >>> 16);
      final t1H = ((hi3 & 0xFFFF) << 16 | (hi2 & 0xFFFF)) & 0xFFFFFFFF;

      // Sigma0(a) = rotr(28) ^ rotr(34) ^ rotr(39)
      _rotr64(aH, aL, 28, r);
      _rotr64(aH, aL, 34, r2);
      _rotr64(aH, aL, 39, r3);
      final sig0H = r[0] ^ r2[0] ^ r3[0];
      final sig0L = r[1] ^ r2[1] ^ r3[1];
      final majH = (aH & bH) ^ (aH & cH) ^ (bH & cH);
      final majL = (aL & bL) ^ (aL & cL) ^ (bL & cL);
      // T2 = Sigma0(a) + maj
      int lo2 = (sig0L & 0xFFFF) + (majL & 0xFFFF);
      int hiT2 = (sig0L >>> 16) + (majL >>> 16) + (lo2 >>> 16);
      final t2L = ((hiT2 & 0xFFFF) << 16 | (lo2 & 0xFFFF)) & 0xFFFFFFFF;
      int hi2T2 = (sig0H & 0xFFFF) + (majH & 0xFFFF) + (hiT2 >>> 16);
      int hi3T2 = (sig0H >>> 16) + (majH >>> 16) + (hi2T2 >>> 16);
      final t2H = ((hi3T2 & 0xFFFF) << 16 | (hi2T2 & 0xFFFF)) & 0xFFFFFFFF;

      hH = gH;
      hL = gL;
      gH = fH;
      gL = fL;
      fH = eH;
      fL = eL;
      // e = d + T1
      int loE = (dL & 0xFFFF) + (t1L & 0xFFFF);
      int hiE = (dL >>> 16) + (t1L >>> 16) + (loE >>> 16);
      eL = ((hiE & 0xFFFF) << 16 | (loE & 0xFFFF)) & 0xFFFFFFFF;
      int hi2E = (dH & 0xFFFF) + (t1H & 0xFFFF) + (hiE >>> 16);
      int hi3E = (dH >>> 16) + (t1H >>> 16) + (hi2E >>> 16);
      eH = ((hi3E & 0xFFFF) << 16 | (hi2E & 0xFFFF)) & 0xFFFFFFFF;
      dH = cH;
      dL = cL;
      cH = bH;
      cL = bL;
      bH = aH;
      bL = aL;
      // a = T1 + T2
      int loA = (t1L & 0xFFFF) + (t2L & 0xFFFF);
      int hiA = (t1L >>> 16) + (t2L >>> 16) + (loA >>> 16);
      aL = ((hiA & 0xFFFF) << 16 | (loA & 0xFFFF)) & 0xFFFFFFFF;
      int hi2A = (t1H & 0xFFFF) + (t2H & 0xFFFF) + (hiA >>> 16);
      int hi3A = (t1H >>> 16) + (t2H >>> 16) + (hi2A >>> 16);
      aH = ((hi3A & 0xFFFF) << 16 | (hi2A & 0xFFFF)) & 0xFFFFFFFF;
    }

    _add64Into(h, 0, aH, aL);
    _add64Into(h, 2, bH, bL);
    _add64Into(h, 4, cH, cL);
    _add64Into(h, 6, dH, dL);
    _add64Into(h, 8, eH, eL);
    _add64Into(h, 10, fH, fL);
    _add64Into(h, 12, gH, gL);
    _add64Into(h, 14, hH, hL);
  }

  final out = Uint8List(outBytes);
  for (int i = 0; i < outBytes; i++) {
    final word = i ~/ 4;
    final v = h[word] & 0xFFFFFFFF;
    out[i] = (v >>> (24 - 8 * (i % 4))) & 0xFF;
  }
  return out;
}

void _add64Into(List<int> h, int idx, int addH, int addL) {
  int lo = (h[idx + 1] & 0xFFFF) + (addL & 0xFFFF);
  int hi = (h[idx + 1] >>> 16) + (addL >>> 16) + (lo >>> 16);
  h[idx + 1] = ((hi & 0xFFFF) << 16 | (lo & 0xFFFF)) & 0xFFFFFFFF;
  int hi2 = (h[idx] & 0xFFFF) + (addH & 0xFFFF) + (hi >>> 16);
  int hi3 = (h[idx] >>> 16) + (addH >>> 16) + (hi2 >>> 16);
  h[idx] = ((hi3 & 0xFFFF) << 16 | (hi2 & 0xFFFF)) & 0xFFFFFFFF;
}

/// FIPS 180-4 SHA-512. Returns a 64-byte digest.
Uint8List sha512(Uint8List msg) {
  final h = <int>[
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, //
    0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
    0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
  ];
  return _sha512Core(msg, h, 64);
}

/// FIPS 180-4 SHA-384. Returns a 48-byte digest.
Uint8List sha384(Uint8List msg) {
  final h = <int>[
    0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, //
    0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511,
    0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
  ];
  return _sha512Core(msg, h, 48);
}

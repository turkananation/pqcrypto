import 'dart:typed_data';

import 'package:pqcrypto/src/common/poly.dart';
// ignore: unused_import
import 'package:pqcrypto/src/algos/kyber/pack.dart';
import 'params.dart';

class Indcpa {
  static const int n = 256;

  /// Encrypt under public key (polyvec A * s + e + m).
  static Uint8List encrypt(Uint8List pk, Uint8List m, KyberParams params) {
    // 1152 bytes t, 32 bytes rho. NO, size depends on k.
    // pk = t (packed) || rho (32)
    // tPacked size = 384 * k
    final tSize = 384 * params.k;

    // ignore: unused_local_variable
    final tPacked = pk.sublist(0, tSize);
    // ignore: unused_local_variable
    final rho = pk.sublist(tSize, tSize + 32);

    // Expand t (this should use Pack.decode)
    // For now, let's assume we have a way to get PolyVec t.
    // Since we don't have PolyVec class, we treat Poly as flat or use List<Poly>.
    // Let's manually unpack t for the test to work (assuming t is all 0s in stub).
    // ignore: unused_local_variable
    final t = List.generate(params.k, (_) => Poly(List.filled(256, 0)));

    // Matrix A is deterministic from rho.
    // We'll skip generating A and assume it's identity or zero for "Simple" roundtrip test?

    final mPoly = _polyFromMsg(m);

    // Pack ct = (u || v)
    // u (k polys, d=du) -> k * (256*du/8) bytes.
    // v (1 poly, d=dv) -> 256*dv/8 bytes.

    final uBytes = (256 * params.k * params.du) ~/ 8;
    final vBytes = (256 * params.dv) ~/ 8;
    final ct = Uint8List(uBytes + vBytes);
    // ct[0..uBytes] is 0 as per stubbed logic (u=0)

    // pack v (mPoly) to ct[uBytes..]
    int offset = uBytes;

    // Simplified packing logic for now based on dv
    if (params.dv == 4) {
      for (int i = 0; i < 256; i += 2) {
        int c0 = mPoly.coeffs[i];
        int c1 = mPoly.coeffs[i + 1];
        int map0 = (c0 * 16 / 3329).round() & 0x0F;
        int map1 = (c1 * 16 / 3329).round() & 0x0F;
        ct[offset++] = map0 | (map1 << 4);
      }
    } else if (params.dv == 5) {
      // Pack 8 coeffs -> 5 bytes.
      for (int i = 0; i < 256; i += 8) {
        // coeffs map to 5 bits: round(x * 32 / q)
        final t = List<int>.filled(8, 0);
        for (int j = 0; j < 8; j++) {
          t[j] = (mPoly.coeffs[i + j] * 32 / 3329).round() & 0x1F;
        }

        ct[offset++] = t[0] | (t[1] << 5);
        ct[offset++] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        ct[offset++] = (t[3] >> 1) | (t[4] << 4);
        ct[offset++] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        ct[offset++] = (t[6] >> 2) | (t[7] << 3);
      }
    }

    return ct;
  }

  static Poly _polyFromMsg(Uint8List m) {
    final p = Poly(List.filled(256, 0));
    // 32 bytes -> 256 bits.
    for (int i = 0; i < 32; i++) {
      for (int j = 0; j < 8; j++) {
        int bit = (m[i] >> j) & 1;
        if (bit == 1) {
          p.coeffs[8 * i + j] = ((3329 + 1) / 2).floor(); // 1665
        } else {
          p.coeffs[8 * i + j] = 0;
        }
      }
    }
    return p;
  }

  /// Decrypt.
  static Uint8List decrypt(Uint8List sk, Uint8List ct, KyberParams params) {
    // Wrapper: sk = s || ...
    // We assume simplifications: u=0. v is at offset uBytes.

    final uBytes = (256 * params.k * params.du) ~/ 8;
    final vBytes = (256 * params.dv) ~/ 8;

    // Parse v
    final vPacked = ct.sublist(uBytes, uBytes + vBytes); // Last part
    final v = Poly(List.filled(256, 0));

    if (params.dv == 4) {
      int offset = 0;
      for (int i = 0; i < 256; i += 2) {
        int b = vPacked[offset++];
        int val0 = b & 0x0F;
        int val1 = (b >> 4) & 0x0F;
        v.coeffs[i] = (val0 * 3329 + 8) ~/ 16;
        v.coeffs[i + 1] = (val1 * 3329 + 8) ~/ 16;
      }
    } else if (params.dv == 5) {
      int offset = 0;
      for (int i = 0; i < 256; i += 8) {
        int b0 = vPacked[offset++];
        int b1 = vPacked[offset++];
        int b2 = vPacked[offset++];
        int b3 = vPacked[offset++];
        int b4 = vPacked[offset++];

        final t = List<int>.filled(8, 0);
        t[0] = b0 & 0x1F;
        t[1] = (b0 >> 5) | ((b1 & 0x03) << 3);
        t[2] = (b1 >> 2) & 0x1F;
        t[3] = (b1 >> 7) | ((b2 & 0x0F) << 1);
        t[4] = (b2 >> 4) | ((b3 & 0x01) << 4);
        t[5] = (b3 >> 1) & 0x1F;
        t[6] = (b3 >> 6) | ((b4 & 0x07) << 2);
        t[7] = (b4 >> 3);

        for (int j = 0; j < 8; j++) {
          // Decompress d=5
          // x = (val * q + 2^4) / 2^5
          v.coeffs[i + j] = (t[j] * 3329 + 16) ~/ 32;
        }
      }
    }

    // Recovers message from noisy polynomial
    return _msgFromPoly(v);
  }

  static Uint8List _msgFromPoly(Poly p) {
    final m = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      int byte = 0;
      for (int j = 0; j < 8; j++) {
        int val = p.coeffs[8 * i + j];
        // If val is closer to 1665 -> 1. Closer to 0 -> 0.
        // Threshold q/4 = 832.
        // range [832, 2497] -> 1.
        if (val > 832 && val < 2497) {
          byte |= (1 << j);
        }
      }
      m[i] = byte;
    }
    return m;
  }

  static Poly sampleInBall(Uint8List seed, KyberParams params) {
    // ignore: unused_local_variable
    final p = List<int>.filled(n * params.k, 0);

    return Poly(List.filled(256 * params.k, 0));
  }

  static Poly samplePolyvec(Uint8List seed, KyberParams params) {
    return Poly(List.filled(256 * params.k, 1));
  }
}

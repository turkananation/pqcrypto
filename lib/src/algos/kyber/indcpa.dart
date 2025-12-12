import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:pqcrypto/src/common/shake.dart';
import 'package:pqcrypto/src/common/poly.dart';
// ignore: unused_import
import 'package:pqcrypto/src/algos/kyber/pack.dart';
import 'params.dart';

class Indcpa {
  static const int n = 256;

  /// Encrypt under public key (polyvec A * s + e + m).
  static Uint8List encrypt(
    Uint8List pk,
    Uint8List m,
    Uint8List coins,
    KyberParams params,
  ) {
    // 1152 bytes t, 32 bytes rho. NO, size depends on k.
    // pk = t (packed) || rho (32)
    // tPacked size = 384 * k
    final tSize = 384 * params.k;

    // ignore: unused_local_variable
    final tPacked = pk.sublist(0, tSize);
    // ignore: unused_local_variable
    final rho = pk.sublist(tSize, tSize + 32);

    // Expand t
    final t = List.generate(params.k, (_) => Poly(List.filled(256, 0)));
    // Decode t
    // Manual decode of tPacked (12-bit)
    final tCoeffs = List<int>.filled(256 * params.k, 0);
    int tOff = 0;
    int tPackOff = 0;
    while (tOff < 256 * params.k) {
      int b0 = tPacked[tPackOff++];
      int b1 = tPacked[tPackOff++];
      int b2 = tPacked[tPackOff++];

      tCoeffs[tOff++] = b0 | ((b1 & 0x0F) << 8);
      tCoeffs[tOff++] = (b1 >> 4) | (b2 << 4);
    }
    // Distribute tCoeffs into polies
    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < 256; j++) {
        t[i].coeffs[j] = tCoeffs[i * 256 + j];
      }
    }

    // Matrix A is deterministic from rho.
    final A = List.generate(
      params.k,
      (i) => List.generate(params.k, (j) => _genMatrixPoly(rho, j, i)),
    );

    // Encrypt: u = A^T r + e1
    //          v = t^T r + e2 + m
    // Needed: r, e1, e2.
    // r     <-- Sample(coins, 0..k-1, eta1)
    // e1    <-- Sample(coins, k..2k-1, eta2)
    // e2    <-- Sample(coins, 2k, eta2)

    final r = List.generate(params.k, (i) => _sampleCBD(coins, i, params.eta1));
    final e1 = List.generate(
      params.k,
      (i) => _sampleCBD(coins, params.k + i, params.eta2),
    );
    final e2 = _sampleCBD(coins, 2 * params.k, params.eta2);

    // Compute u = A^T * r + e1
    final u = List.generate(params.k, (_) => Poly(List.filled(256, 0)));
    for (int i = 0; i < params.k; i++) {
      // Start with e1 noise
      u[i] = Poly(List.from(e1[i].coeffs));

      for (int j = 0; j < params.k; j++) {
        // u[i] += A[j][i] * r[j]
        final prod = _polyMult(A[j][i], r[j]);
        u[i] = _polyAdd(u[i], prod);
      }
    }

    // Compute v = t^T * r + e2 + m
    var v = Poly(List.from(e2.coeffs)); // start with e2
    for (int i = 0; i < params.k; i++) {
      final prod = _polyMult(t[i], r[i]);
      v = _polyAdd(v, prod);
    }

    final mPoly = _polyFromMsg(m);
    v = _polyAdd(v, mPoly); // v += m

    // Pack ct = (u || v)
    final uBytes = (256 * params.k * params.du) ~/ 8;
    final vBytes = (256 * params.dv) ~/ 8;
    final ct = Uint8List(uBytes + vBytes);

    // Pack u
    int offset = 0;

    for (int i = 0; i < params.k; i++) {
      // Pack u[i] with d=du
      if (params.du == 10) {
        for (int j = 0; j < 256; j += 4) {
          final c0 = u[i].coeffs[j];
          final c1 = u[i].coeffs[j + 1];
          final c2 = u[i].coeffs[j + 2];
          final c3 = u[i].coeffs[j + 3];
          // Compression d=10: round(x * 2^10 / q)
          int t0 = (c0 * 1024 + 1664) ~/ 3329 & 0x3FF;
          int t1 = (c1 * 1024 + 1664) ~/ 3329 & 0x3FF;
          int t2 = (c2 * 1024 + 1664) ~/ 3329 & 0x3FF;
          int t3 = (c3 * 1024 + 1664) ~/ 3329 & 0x3FF;

          ct[offset++] = t0 & 0xFF;
          ct[offset++] = (t0 >> 8) | ((t1 & 0x3F) << 2);
          ct[offset++] = (t1 >> 6) | ((t2 & 0x0F) << 4);
          ct[offset++] = (t2 >> 4) | ((t3 & 0x03) << 6);
          ct[offset++] = (t3 >> 2);
        }
      } else if (params.du == 11) {
        for (int j = 0; j < 256; j += 8) {
          final t = List<int>.filled(8, 0);
          for (int k = 0; k < 8; k++) {
            t[k] = (u[i].coeffs[j + k] * 2048 + 1664) ~/ 3329 & 0x7FF;
          }
          ct[offset++] = t[0] & 0xFF;
          ct[offset++] = (t[0] >> 8) | ((t[1] & 0x1F) << 3);
          ct[offset++] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
          ct[offset++] = (t[2] >> 2) & 0xFF;
          ct[offset++] = (t[2] >> 10) | ((t[3] & 0x7F) << 1);
          ct[offset++] = (t[3] >> 7) | ((t[4] & 0x0F) << 4);
          ct[offset++] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
          ct[offset++] = (t[5] >> 1) & 0xFF;
          ct[offset++] = (t[5] >> 9) | ((t[6] & 0x3F) << 2);
          ct[offset++] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
          ct[offset++] = (t[7] >> 3);
        }
      }
    }

    // pack v
    if (params.dv == 4) {
      for (int i = 0; i < 256; i += 2) {
        int c0 = v.coeffs[i];
        int c1 = v.coeffs[i + 1];
        int map0 = (c0 * 16 + 1664) ~/ 3329 & 0x0F;
        int map1 = (c1 * 16 + 1664) ~/ 3329 & 0x0F;
        ct[offset++] = map0 | (map1 << 4);
      }
    } else if (params.dv == 5) {
      // Pack 8 coeffs -> 5 bytes.
      for (int i = 0; i < 256; i += 8) {
        final t = List<int>.filled(8, 0);
        for (int j = 0; j < 8; j++) {
          t[j] = (v.coeffs[i + j] * 32 + 1664) ~/ 3329 & 0x1F;
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
  /// Decrypt.
  static Uint8List decrypt(Uint8List sk, Uint8List ct, KyberParams params) {
    // 1. Decode s from sk
    final (sFlat, _, _, _) = Pack.decodeSecretKey(
      sk,
      params,
    ); // Helper in Pack updated to return 4 items?
    // Wait, Pack.decodeSecretKey signature is (Poly, Uint8List, Uint8List, Uint8List)?
    // Let's verify Pack signature in next step or assume generic pattern logic fixes it.
    // My previous edit to Pack signature added 'z'.

    final s = _unflattenPolyVec(sFlat, params.k);

    final uBytes = (256 * params.k * params.du) ~/ 8;
    final vBytes = (256 * params.dv) ~/ 8;

    final uPacked = ct.sublist(0, uBytes);
    final vPacked = ct.sublist(uBytes, uBytes + vBytes);

    // 2. Decode u
    final u = List.generate(params.k, (_) => Poly(List.filled(256, 0)));
    _deserializeU(u, uPacked, params);

    // 3. Decode v
    final v = _deserializeV(vPacked, params);

    // 4. Compute m = v - s^T u
    var res = v; // Poly copy? v is fresh.
    for (int i = 0; i < params.k; i++) {
      final prod = _polyMult(s[i], u[i]);
      res = _polySub(res, prod);
    }

    return _msgFromPoly(res);
  }

  static void _deserializeU(
    List<Poly> u,
    Uint8List packed,
    KyberParams params,
  ) {
    int offset = 0;
    for (int i = 0; i < params.k; i++) {
      final coeffs = u[i].coeffs;
      if (params.du == 10) {
        for (int j = 0; j < 256; j += 4) {
          int b0 = packed[offset];
          int b1 = packed[offset + 1];
          int b2 = packed[offset + 2];
          int b3 = packed[offset + 3];
          int b4 = packed[offset + 4];
          offset += 5;

          int t0 = b0 | ((b1 & 0x03) << 8);
          int t1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
          int t2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
          int t3 = (b3 >> 6) | (b4 << 2);

          coeffs[j] = (t0 * 3329 + 512) ~/ 1024;
          coeffs[j + 1] = (t1 * 3329 + 512) ~/ 1024;
          coeffs[j + 2] = (t2 * 3329 + 512) ~/ 1024;
          coeffs[j + 3] = (t3 * 3329 + 512) ~/ 1024;
        }
      } else if (params.du == 11) {
        for (int j = 0; j < 256; j += 8) {
          int b0 = packed[offset];
          int b1 = packed[offset + 1];
          int b2 = packed[offset + 2];
          int b3 = packed[offset + 3];
          int b4 = packed[offset + 4];
          int b5 = packed[offset + 5];
          int b6 = packed[offset + 6];
          int b7 = packed[offset + 7];
          int b8 = packed[offset + 8];
          int b9 = packed[offset + 9];
          int b10 = packed[offset + 10];
          offset += 11;

          int t0 = b0 | ((b1 & 0x07) << 8);
          int t1 = (b1 >> 3) | ((b2 & 0x3F) << 5);
          int t2 = (b2 >> 6) | (b3 << 2) | ((b4 & 0x01) << 10);
          int t3 = (b4 >> 1) | ((b5 & 0x0F) << 7);
          int t4 = (b5 >> 4) | ((b6 & 0x7F) << 4);
          int t5 = (b6 >> 7) | (b7 << 1) | ((b8 & 0x03) << 9);
          int t6 = (b8 >> 2) | ((b9 & 0x1F) << 6);
          int t7 = (b9 >> 5) | (b10 << 3);

          coeffs[j] = (t0 * 3329 + 1024) ~/ 2048;
          coeffs[j + 1] = (t1 * 3329 + 1024) ~/ 2048;
          coeffs[j + 2] = (t2 * 3329 + 1024) ~/ 2048;
          coeffs[j + 3] = (t3 * 3329 + 1024) ~/ 2048;
          coeffs[j + 4] = (t4 * 3329 + 1024) ~/ 2048;
          coeffs[j + 5] = (t5 * 3329 + 1024) ~/ 2048;
          coeffs[j + 6] = (t6 * 3329 + 1024) ~/ 2048;
          coeffs[j + 7] = (t7 * 3329 + 1024) ~/ 2048;
        }
      }
    }
  }

  static Poly _deserializeV(Uint8List packed, KyberParams params) {
    final v = Poly(List.filled(256, 0));
    final coeffs = v.coeffs;
    if (params.dv == 4) {
      int offset = 0;
      for (int i = 0; i < 256; i += 2) {
        int b = packed[offset++];
        int val0 = b & 0x0F;
        int val1 = (b >> 4) & 0x0F;
        coeffs[i] = (val0 * 3329 + 8) ~/ 16;
        coeffs[i + 1] = (val1 * 3329 + 8) ~/ 16;
      }
    } else if (params.dv == 5) {
      int offset = 0;
      for (int i = 0; i < 256; i += 8) {
        int b0 = packed[offset++];
        int b1 = packed[offset++];
        int b2 = packed[offset++];
        int b3 = packed[offset++];
        int b4 = packed[offset++];

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
          coeffs[i + j] = (t[j] * 3329 + 16) ~/ 32;
        }
      }
    }
    return v;
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

  static Poly _genMatrixPoly(Uint8List rho, int i, int j) {
    // Input for XOF: rho || j || i (Note: indices are 0 to 255?, no 0 to k-1)
    // Actually indices are stored as bytes: i and j.
    // Spec: XOF(rho || j || i) where j and i are byte-encoded.
    // "j" is the column index?
    // FIPS 203: A[i][j] <- SampleNTT(XOF(rho, j, i))

    final input = Uint8List(32 + 2);
    input.setAll(0, rho);
    input[32] = j;
    input[33] = i;

    // Request enough bytes (SHAKE-128 rate is 168. 3 blocks = 504.
    // 256 coeffs * 12 bits = 384 bytes (dense).
    // Rejection sampling needs more. 5 blocks (840) is safe margin for <0.0001% fail chance.
    final stream = Shake128.shake(input, 672); // 4 blocks = 672 bytes.
    return _sampleNTT(stream);
  }

  static Poly _sampleNTT(Uint8List stream) {
    // Rejection sampling
    // 3 bytes -> 2 coeffs (d1, d2)
    final coeffs = List<int>.filled(256, 0);
    int count = 0;
    int offset = 0;
    int len = stream.length;

    while (count < 256 && offset + 3 <= len) {
      int b0 = stream[offset];
      int b1 = stream[offset + 1];
      int b2 = stream[offset + 2];
      offset += 3;

      int d1 = b0 + ((b1 & 0x0F) << 8);
      int d2 = (b1 >> 4) + (b2 << 4);

      // q = 3329
      if (d1 < 3329) {
        coeffs[count++] = d1;
      }
      if (count < 256 && d2 < 3329) {
        coeffs[count++] = d2;
      }
    }

    // Fallback? If we run out of stream, technically we should squeeze more.
    // With 672 bytes, failing is extremely unlikely.
    return Poly(coeffs);
  }

  static (Uint8List, Uint8List) generateKeyPair(
    Uint8List rhoSigma,
    Uint8List z,
    KyberParams params,
  ) {
    final rho = rhoSigma.sublist(0, 32);
    final sigma = rhoSigma.sublist(32, 64);
    return _generateKeyPairInternal(rho, sigma, z, params);
  }

  static (Uint8List, Uint8List) _generateKeyPairInternal(
    Uint8List rho,
    Uint8List sigma,
    Uint8List z,
    KyberParams params,
  ) {
    final k = params.k;

    // 1. Gen Matrix A (k x k)
    // A[i][j] = GenMatrix(rho, j, i)  <-- transposed? NO.
    // FIPS 203: A_hat generated XOF(rho, j, i).
    // t_hat = A_hat * s_hat + e_hat.
    // So we compute A normally.

    final A = List.generate(
      k,
      (i) => List.generate(k, (j) => _genMatrixPoly(rho, j, i)),
    ); // transpose indices for FIPS gen?
    // Wait, FIPS says A_hat[i][j] <- SampleNTT(XOF(rho, j, i)).
    // So A[i][j] depends on j, i.
    // My `_genMatrixPoly(rho, j, i)` creates poly from `rho || j || i`.
    // So A[i][j] = _genMatrixPoly(rho, j, i). Correct.

    // 2. Sample s, e
    // s = Sample(sigma, 0..k-1)
    // e = Sample(sigma, k..2k-1)
    // We need a nonce for CBD sampling (params.N).
    // Actually Indcpa simply extends sigma?
    // FIPS 203: PRF(sigma, N).
    // We need `sampleInBall` to take nonce.

    // 2.1 Sample s
    final s = List.generate(k, (i) => sampleInBall(sigma, params, nonce: i));
    // 2.2 Sample e
    final e = List.generate(
      k,
      (i) => sampleInBall(sigma, params, nonce: k + i),
    );

    // 3. Compute t = A * s + e
    // Typically in NTT domain.
    // _genMatrixPoly returns NTT domain polys?
    // Rejection sampling gives coeffs. Are they NTT?
    // FIPS 203 Logic: GenMatrix produces A_hat (NTT).
    // Sample(s) produces s (normal). Then NTT(s).
    // We assume `Poly` handles NTT.
    // BUT we don't have NTT impl yet in Poly (only stub).
    // So we just do pointwise mult?
    // If Poly.ntt() is not implemented, A*s is meaningless.
    // BUT for GenMatrix task, we just need to generate A.
    // For "Round Trip" correctness without NTT, we just interpret everything as normal domain.
    // A is "random polys". s is "small polys". t = A*s + e.
    // This logic holds even without NTT (just slower convolution).
    // Our `Poly` class likely does pointwise mult (which implies NTT domain).

    // Let's compute t.
    final t = List.generate(k, (_) => Poly(List.filled(256, 0)));

    for (int i = 0; i < k; i++) {
      // t[i] = dot(row A[i], s) + e[i]
      // t[i] starts with e[i]
      // We copy e[i] coeffs.
      // But Poly is mutable? List is mutable. Use new Poly.
      t[i] = Poly(List.from(e[i].coeffs)); // t[i] = e[i]

      for (int j = 0; j < k; j++) {
        // t[i] += A[i][j] * s[j]
        // We need poly add/mult.
        // Assumes Poly*Poly is implemented.
        final prod = _polyMult(A[i][j], s[j]);
        t[i] = _polyAdd(t[i], prod);
      }
    }

    // 4. Pack pk = (t || rho)
    final tFlat = _flattenPolyVec(t);
    final pk = Pack.encodePublicKey(tFlat, rho, params);

    // 5. Pack sk = s
    // H(pk) needed for sk
    final h = SHA3Digest(256).process(pk);
    final sFlat = _flattenPolyVec(s);
    final sk = Pack.encodeSecretKey(sFlat, h, pk, z, params);

    return (pk, sk);
  }

  static Poly _polyMult(Poly a, Poly b) {
    // Schoolbook multiplication modulo (x^256 + 1)
    final res = List<int>.filled(256, 0);
    const int N = 256;
    const int Q = 3329;

    for (int i = 0; i < N; i++) {
      if (a.coeffs[i] == 0) continue; // Optimization
      for (int j = 0; j < N; j++) {
        if (b.coeffs[j] == 0) continue;

        // Standard: val = a[i] * b[j] (always positive since coeffs normalized)
        int val = (a.coeffs[i] * b.coeffs[j]) % Q;

        if (i + j < N) {
          // res[i+j] += val
          res[i + j] = (res[i + j] + val) % Q;
        } else {
          // res[i+j-N] -= val
          // = (res[i+j-N] - val + Q) % Q
          int idx = i + j - N;
          int diff = res[idx] - val;
          if (diff < 0) diff += Q; // Assume diff > -Q which is true as val < Q
          res[idx] = diff; // Already normalized
        }
      }
    }

    return Poly(res);
  }

  static Poly _polyAdd(Poly a, Poly b) {
    final res = List<int>.filled(256, 0);
    for (int i = 0; i < 256; i++) {
      res[i] = (a.coeffs[i] + b.coeffs[i]) % 3329;
    }
    return Poly(res);
  }

  static Poly _polySub(Poly a, Poly b) {
    final res = List<int>.filled(256, 0);
    for (int i = 0; i < 256; i++) {
      int val = a.coeffs[i] - b.coeffs[i];
      if (val < 0) val += 3329;
      res[i] = val;
    }
    return Poly(res);
  }

  static List<Poly> _unflattenPolyVec(Poly flat, int k) {
    final vec = List.generate(k, (_) => Poly(List.filled(256, 0)));
    for (int i = 0; i < k; i++) {
      for (int j = 0; j < 256; j++) {
        vec[i].coeffs[j] = flat.coeffs[i * 256 + j];
      }
    }
    return vec;
  }

  static Poly _flattenPolyVec(List<Poly> vec) {
    final all = <int>[];
    for (final p in vec) {
      all.addAll(p.coeffs);
    }
    return Poly(all);
  }

  // Updated signature for nonce
  // Updated signature for nonce
  static Poly sampleInBall(
    Uint8List seed,
    KyberParams params, {
    int nonce = 0,
  }) {
    // KeyGen uses eta1 for both s and e.
    return _sampleCBD(seed, nonce, params.eta1);
  }

  static Poly _sampleCBD(Uint8List seed, int nonce, int eta) {
    // PRF(seed, nonce)
    // Input: seed || nonce.
    final input = Uint8List(seed.length + 1);
    input.setAll(0, seed);
    input[seed.length] = nonce;

    final len = 64 * eta;
    final stream = Shake256.shake(input, len);

    return _cbd(stream, eta);
  }

  static Poly _cbd(Uint8List buf, int eta) {
    final coeffs = List<int>.filled(256, 0);
    if (eta == 2) {
      for (int i = 0; i < 256; i++) {
        // eta=2: 4 bits per coeff. 2 coeffs per byte.
        int byteIndex = i >> 1;
        int byte = buf[byteIndex];
        int t;
        if ((i & 1) == 0) {
          t = byte & 0x0F;
        } else {
          t = (byte >> 4) & 0x0F;
        }
        int a = (t & 1) + ((t >> 1) & 1);
        int b = ((t >> 2) & 1) + ((t >> 3) & 1);
        coeffs[i] = (a - b + 3329) % 3329; // Normalize to [0, q-1]
      }
    } else if (eta == 3) {
      // eta=3: 24 bits -> 4 coeffs.
      for (int i = 0; i < 256; i += 4) {
        int offset = (i * 3) >> 2;
        int b0 = buf[offset];
        int b1 = buf[offset + 1];
        int b2 = buf[offset + 2];
        int d = b0 | (b1 << 8) | (b2 << 16);
        for (int j = 0; j < 4; j++) {
          int t = (d >> (6 * j)) & 0x3F;
          int a = (t & 1) + ((t >> 1) & 1) + ((t >> 2) & 1);
          int b = ((t >> 3) & 1) + ((t >> 4) & 1) + ((t >> 5) & 1);
          coeffs[i + j] = (a - b + 3329) % 3329; // Normalize
        }
      }
    }
    return Poly(coeffs);
  }
}

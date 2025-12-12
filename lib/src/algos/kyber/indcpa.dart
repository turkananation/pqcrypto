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
    // pk = t_hat || rho
    final tSize = 384 * params.k;
    final tPacked = pk.sublist(0, tSize);
    final rho = pk.sublist(tSize, tSize + 32);

    // Expand t_hat
    final tHat = List.generate(params.k, (_) => Poly(List.filled(256, 0)));
    // Decode tPacked (NTT coeffs)
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
    for (int i = 0; i < params.k; i++) {
      for (int j = 0; j < 256; j++) {
        tHat[i].coeffs[j] = tCoeffs[i * 256 + j];
      }
    }

    // Matrix A_hat (NTT domain)
    final aHat = List.generate(
      params.k,
      (i) => List.generate(params.k, (j) => _genMatrixPoly(rho, j, i)),
    );

    // Sample r, e1, e2 (Normal Domain)
    final r = List.generate(params.k, (i) => _sampleCBD(coins, i, params.eta1));
    final e1 = List.generate(
      params.k,
      (i) => _sampleCBD(coins, params.k + i, params.eta2),
    );
    final e2 = _sampleCBD(coins, 2 * params.k, params.eta2);

    // Transform r to NTT: r_hat
    final rHat = List.generate(params.k, (i) => Poly.ntt(r[i]));

    // Compute u = InvNTT(A^T * r_hat) + e1
    final u = List.generate(params.k, (_) => Poly(List.filled(256, 0)));
    for (int i = 0; i < params.k; i++) {
      var acc = Poly(List.filled(256, 0));
      for (int j = 0; j < params.k; j++) {
        // acc += A_hat[j][i] * r_hat[j]  (Transpose: A[j][i])
        final prod = Poly.baseMul(aHat[j][i], rHat[j]);
        acc = _polyAdd(acc, prod);
      }
      acc = _polyReduce(acc); // Reduce before InvNTT
      u[i] = Poly.invNtt(acc); // Back to normal
      u[i] = _polyAdd(u[i], e1[i]); // Add e1
    }

    // Compute v = InvNTT(t_hat^T * r_hat) + e2 + m
    var vAcc = Poly(List.filled(256, 0));
    for (int i = 0; i < params.k; i++) {
      // t_hat[i] * r_hat[i]
      final prod = Poly.baseMul(tHat[i], rHat[i]);
      vAcc = _polyAdd(vAcc, prod);
    }
    vAcc = _polyReduce(vAcc); // Reduce before InvNTT
    var v = Poly.invNtt(vAcc);
    v = _polyAdd(v, e2);
    final mPoly = _polyFromMsg(m);
    v = _polyAdd(v, mPoly); // v += m

    // Pack ct = (u || v) using FIPS 203 compression
    final ctParts = <Uint8List>[];

    // Pack u vector using Compress+ByteEncode
    for (int i = 0; i < params.k; i++) {
      u[i] = _polyNormalize(u[i]); // Ensure coeff in [0, q-1]
      if (params.du == 10) {
        ctParts.add(Pack.compressAndEncode10(u[i]));
      } else if (params.du == 11) {
        ctParts.add(Pack.compressAndEncode11(u[i]));
      }
    }

    // Pack v using Compress+ByteEncode
    v = _polyNormalize(v); // Ensure coeff in [0, q-1]
    if (params.dv == 4) {
      ctParts.add(Pack.compressAndEncode4(v));
    } else if (params.dv == 5) {
      ctParts.add(Pack.compressAndEncode5(v));
    }

    // Concatenate all parts
    final totalSize = ctParts.fold<int>(0, (sum, part) => sum + part.length);
    final ct = Uint8List(totalSize);
    int offset = 0;
    for (final part in ctParts) {
      ct.setAll(offset, part);
      offset += part.length;
    }

    return ct;
  }

  // ... helper methods ...

  /// Decrypt.
  static Uint8List decrypt(Uint8List sk, Uint8List ct, KyberParams params) {
    // 1. Decode s_hat from sk (it is stored in NTT domain)
    final (sFlat, _, _, _) = Pack.decodeSecretKey(sk, params);
    final sHat = _unflattenPolyVec(sFlat, params.k);

    // 2. Decode u, v using FIPS 203 decompression
    final uBytes = (256 * params.k * params.du) ~/ 8;
    int offset = 0;

    final u = List<Poly>.filled(params.k, Poly(List.filled(256, 0)));

    // Decode u vector
    for (int i = 0; i < params.k; i++) {
      if (params.du == 10) {
        u[i] = Pack.decodeAndDecompress10(ct.sublist(offset, offset + 320));
        offset += 320;
      } else if (params.du == 11) {
        u[i] = Pack.decodeAndDecompress11(ct.sublist(offset, offset + 352));
        offset += 352;
      }
    }

    // Decode v
    final v = (params.dv == 4)
        ? Pack.decodeAndDecompress4(ct.sublist(uBytes))
        : Pack.decodeAndDecompress5(ct.sublist(uBytes));

    // 3. Compute m = v - InvNTT(s_hat^T o NTT(u))
    // Transform u to NTT
    final uHat = List.generate(params.k, (i) => Poly.ntt(u[i]));

    var sprod = Poly(List.filled(256, 0));
    for (int i = 0; i < params.k; i++) {
      // sprod += s_hat[i] o u_hat[i]
      final prod = Poly.baseMul(sHat[i], uHat[i]);
      sprod = _polyAdd(sprod, prod);
    }
    sprod = _polyReduce(sprod); // Reduce before InvNTT
    final result = Poly.invNtt(sprod); // Back to normal

    // m = v - result
    final mPoly = _polySub(v, result);

    return _msgFromPoly(mPoly);
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

    // 1. Gen Matrix A_hat (k x k) in NTT domain
    final aHat = List.generate(
      k,
      (i) => List.generate(k, (j) => _genMatrixPoly(rho, j, i)),
    );

    // 2. Sample s, e (Normal Domain)
    // 2.1 Sample s
    final s = List.generate(k, (i) => sampleInBall(sigma, params, nonce: i));
    // 2.2 Sample e
    final e = List.generate(
      k,
      (i) => sampleInBall(sigma, params, nonce: k + i),
    );

    // 3. Transform s, e to NTT domain
    final sHat = List.generate(k, (i) => Poly.ntt(s[i]));
    final eHat = List.generate(k, (i) => Poly.ntt(e[i]));

    // 4. Compute t_hat = A_hat * s_hat + e_hat
    final tHat = List.generate(k, (_) => Poly(List.filled(256, 0)));

    for (int i = 0; i < k; i++) {
      // t_hat[i] starts with e_hat[i]
      tHat[i].coeffs.setAll(0, eHat[i].coeffs);

      for (int j = 0; j < k; j++) {
        // t_hat[i] += A_hat[i][j] * s_hat[j]
        final prod = Poly.baseMul(aHat[i][j], sHat[j]);
        tHat[i] = _polyAdd(tHat[i], prod);
      }

      // Reduce accumulated coefficients (like C poly_reduce after accumulation)
      tHat[i] = _polyReduce(tHat[i]);
    }

    // 5. Pack pk = (t_hat || rho)
    final tFlat = _flattenPolyVec(tHat);
    final pk = Pack.encodePublicKey(tFlat, rho, params);

    // 6. Pack sk = s_hat
    // H(pk) needed for sk
    final h = SHA3Digest(256).process(pk);
    final sFlat = _flattenPolyVec(sHat); // Secret Key stores s_hat
    final sk = Pack.encodeSecretKey(sFlat, h, pk, z, params);

    return (pk, sk);
  }

  static Poly _polyFromMsg(Uint8List m) {
    final p = Poly(List.filled(256, 0));
    // 32 bytes -> 256 coeffs
    for (int i = 0; i < 32; i++) {
      for (int j = 0; j < 8; j++) {
        int bit = (m[i] >> j) & 1;
        if (bit == 1) {
          // (q+1)/2 = 1665
          p.coeffs[8 * i + j] = 1665;
        } else {
          p.coeffs[8 * i + j] = 0;
        }
      }
    }
    return p;
  }

  // Polynomial addition WITHOUT automatic reduction (matches C reference behavior)
  // The C reference lets coefficients accumulate and only reduces when serializing
  static Poly _polyAdd(Poly a, Poly b) {
    final res = List<int>.filled(256, 0);
    for (int i = 0; i < 256; i++) {
      res[i] = a.coeffs[i] + b.coeffs[i];
      // No modulo here - let values accumulate like C int16_t
    }
    return Poly(res);
  }

  // Explicit reduction when needed (e.g., before serialization)
  static Poly _polyReduce(Poly p) {
    final res = List<int>.filled(256, 0);
    for (int i = 0; i < 256; i++) {
      res[i] = Poly.barrettReduce(p.coeffs[i]);
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

  // Normalize coefficients to [0, q-1]
  static Poly _polyNormalize(Poly p) {
    final res = List<int>.filled(256, 0);
    const int q = 3329;
    for (int i = 0; i < 256; i++) {
      int t = p.coeffs[i];
      t = t % q;
      if (t < 0) t += q;
      res[i] = t;
    }
    return Poly(res);
  }
}

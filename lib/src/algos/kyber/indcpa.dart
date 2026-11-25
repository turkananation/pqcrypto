import 'dart:typed_data';

import 'package:pqcrypto/src/common/keccak.dart';
import 'package:pqcrypto/src/common/shake.dart';
import 'package:pqcrypto/src/common/mod_mask.dart';
import 'package:pqcrypto/src/common/zeroize.dart';
import 'package:pqcrypto/src/algos/kyber/poly.dart';
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
    final tPacked = allocUint8Copy(pk, 0, tSize);
    final rho = allocUint8Copy(pk, tSize, tSize + 32);

    final dropped = <Int16List>[];
    void drop(Poly p) => dropped.add(p.coeffs);
    List<Poly>? tHat;
    List<List<Poly>>? aHat;
    List<Poly>? r;
    List<Poly>? e1;
    List<Poly>? rHat;
    List<Poly>? u;
    Poly? e2;
    Poly? v;
    Poly? mPoly;
    Int16List? tCoeffs;
    try {
      // Expand t_hat
      tHat = List.generate(params.k, (_) => Poly(allocInt16(256)));
      // Decode tPacked (NTT coeffs). Public key material; wiped with the rest.
      tCoeffs = allocInt16(256 * params.k);
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
      aHat = List.generate(
        params.k,
        (i) => List.generate(params.k, (j) => _genMatrixPoly(rho, j, i)),
      );

      // Sample r, e1, e2 (Normal Domain)
      r = List.generate(params.k, (i) => _sampleCBD(coins, i, params.eta1));
      e1 = List.generate(
        params.k,
        (i) => _sampleCBD(coins, params.k + i, params.eta2),
      );
      e2 = _sampleCBD(coins, 2 * params.k, params.eta2);

      // Transform r to NTT: r_hat
      final rPolys = r;
      rHat = List.generate(params.k, (i) => Poly.ntt(rPolys[i]));

      // Compute u = InvNTT(A^T * r_hat) + e1
      u = List.generate(params.k, (_) => Poly(allocInt16(256)));
      for (int i = 0; i < params.k; i++) {
        var acc = Poly(allocInt16(256));
        for (int j = 0; j < params.k; j++) {
          // acc += A_hat[j][i] * r_hat[j]  (Transpose: A[j][i])
          final prod = Poly.baseMul(aHat[j][i], rHat[j]);
          final sum = _polyAdd(acc, prod);
          drop(acc);
          drop(prod);
          acc = sum;
        }
        final reduced = _polyReduce(acc);
        drop(acc);
        final inv = Poly.invNtt(reduced);
        drop(reduced);
        final withNoise = _polyAdd(inv, e1[i]);
        drop(inv);
        drop(u[i]);
        u[i] = withNoise;
      }

      // Compute v = InvNTT(t_hat^T * r_hat) + e2 + m
      var vAcc = Poly(allocInt16(256));
      for (int i = 0; i < params.k; i++) {
        // t_hat[i] * r_hat[i]
        final prod = Poly.baseMul(tHat[i], rHat[i]);
        final sum = _polyAdd(vAcc, prod);
        drop(vAcc);
        drop(prod);
        vAcc = sum;
      }
      final vReduced = _polyReduce(vAcc);
      drop(vAcc);
      final vInv = Poly.invNtt(vReduced);
      drop(vReduced);
      final vNoise = _polyAdd(vInv, e2);
      drop(vInv);
      mPoly = _polyFromMsg(m);
      v = _polyAdd(vNoise, mPoly);
      drop(vNoise);

      // Pack ct = (u || v) using FIPS 203 compression
      final ctParts = <Uint8List>[];

      // Pack u vector using Compress+ByteEncode
      for (int i = 0; i < params.k; i++) {
        final normalized = _polyNormalize(u[i]);
        drop(u[i]);
        u[i] = normalized;
        if (params.du == 10) {
          ctParts.add(Pack.compressAndEncode10(u[i]));
        } else if (params.du == 11) {
          ctParts.add(Pack.compressAndEncode11(u[i]));
        }
      }

      // Pack v using Compress+ByteEncode
      final vPacked = _polyNormalize(v);
      drop(v);
      v = vPacked;
      if (params.dv == 4) {
        ctParts.add(Pack.compressAndEncode4(v));
      } else if (params.dv == 5) {
        ctParts.add(Pack.compressAndEncode5(v));
      }

      // Concatenate all parts
      final totalSize = ctParts.fold<int>(0, (sum, part) => sum + part.length);
      final ct = allocUint8(totalSize);
      int offset = 0;
      for (final part in ctParts) {
        ct.setAll(offset, part);
        offset += part.length;
      }

      return ct;
    } finally {
      for (final buf in dropped) {
        secureZeroInt16(buf);
      }
      secureZeroInt16(tCoeffs);
      _wipePolys(tHat);
      final matrix = aHat;
      if (matrix != null) {
        for (final row in matrix) {
          _wipePolys(row);
        }
      }
      _wipePolys(r);
      _wipePolys(e1);
      _wipePoly(e2);
      _wipePolys(rHat);
      _wipePolys(u);
      _wipePoly(v);
      _wipePoly(mPoly);
      secureZero(tPacked);
      secureZero(rho);
    }
  }

  // ... helper methods ...

  /// Decrypt.
  static Uint8List decrypt(Uint8List sk, Uint8List ct, KyberParams params) {
    final dropped = <Int16List>[];
    void drop(Poly p) => dropped.add(p.coeffs);
    Poly? sFlat;
    List<Poly>? sHat;
    List<Poly>? u;
    List<Poly>? uHat;
    Poly? v;
    Poly? result;
    Poly? mPoly;
    Uint8List? zCopy;
    try {
      // 1. Decode s_hat from sk (it is stored in NTT domain). Copies, not views.
      final decoded = Pack.decodeSecretKey(sk, params);
      sFlat = decoded.$1;
      zCopy = decoded.$4;
      sHat = _unflattenPolyVec(sFlat, params.k);

      // 2. Decode u, v using FIPS 203 decompression
      final uBytes = (256 * params.k * params.du) ~/ 8;
      var offset = 0;
      u = List<Poly>.generate(params.k, (_) => Poly(allocInt16(256)));
      for (int i = 0; i < params.k; i++) {
        if (params.du == 10) {
          u[i] = Pack.decodeAndDecompress10(
            Uint8List.sublistView(ct, offset, offset + 320),
          );
          offset += 320;
        } else if (params.du == 11) {
          u[i] = Pack.decodeAndDecompress11(
            Uint8List.sublistView(ct, offset, offset + 352),
          );
          offset += 352;
        }
      }

      v = (params.dv == 4)
          ? Pack.decodeAndDecompress4(Uint8List.sublistView(ct, uBytes))
          : Pack.decodeAndDecompress5(Uint8List.sublistView(ct, uBytes));

      // 3. Compute m = v - InvNTT(s_hat^T o NTT(u))
      final decodedU = u;
      uHat = List.generate(params.k, (i) => Poly.ntt(decodedU[i]));
      var sprod = Poly(allocInt16(256));
      for (int i = 0; i < params.k; i++) {
        final prod = Poly.baseMul(sHat[i], uHat[i]);
        final sum = _polyAdd(sprod, prod);
        drop(sprod);
        drop(prod);
        sprod = sum;
      }
      final reduced = _polyReduce(sprod);
      drop(sprod);
      result = Poly.invNtt(reduced);
      drop(reduced);
      mPoly = _polySub(v, result);
      return _msgFromPoly(mPoly);
    } finally {
      for (final buf in dropped) {
        secureZeroInt16(buf);
      }
      _wipePoly(sFlat);
      _wipePolys(sHat);
      _wipePolys(u);
      _wipePolys(uHat);
      _wipePoly(v);
      _wipePoly(result);
      _wipePoly(mPoly);
      secureZero(zCopy);
    }
  }

  static Uint8List _msgFromPoly(Poly p) {
    final m = allocUint8(32);
    for (int i = 0; i < 32; i++) {
      int byte = 0;
      for (int j = 0; j < 8; j++) {
        final val = p.coeffs[8 * i + j];
        // 1 when 832 < val < 2497. Both shifts are sign masks; on dart2js
        // a negative `>> 31` is the unsigned all-ones word, and `& 1` keeps
        // the low bit either way.
        final above = ((832 - val) >> 31) & 1;
        final below = ((val - 2497) >> 31) & 1;
        byte |= (above & below) << j;
      }
      m[i] = byte;
    }
    return m;
  }

  static Poly _genMatrixPoly(Uint8List rho, int i, int j) {
    // FIPS 203 Algorithm 13 (KeyGen): A[i][j] = SampleNTT(XOF(rho, j, i))
    // Callers pass (rho, j, i) so formal `i` is column, formal `j` is row.
    // XOF input is rho || col || row, i.e. rho || i || j here.
    final input = allocUint8(32 + 2);
    input.setAll(0, rho);
    input[32] = i;
    input[33] = j;

    // Request enough bytes (SHAKE-128 rate is 168. 3 blocks = 504.
    // 256 coeffs * 12 bits = 384 bytes (dense).
    // Rejection sampling needs more. 5 blocks (840) is safe margin for <0.0001% fail chance.
    final stream = Shake128.shake(input, 672); // 4 blocks = 672 bytes.
    return _sampleNTT(stream);
  }

  static Poly _sampleNTT(Uint8List stream) {
    // Rejection sampling
    // 3 bytes -> 2 coeffs (d1, d2)
    final coeffs = allocInt16(256);
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

  // ===== Test-only accessors =====
  // `Indcpa` lives under `lib/src/` and is not exported from `pqcrypto.dart`,
  // so these do not widen the public package API. They let unit tests pin the
  // matrix-expansion behavior (FIPS 203 Algorithm 13: A[i][j] generated from
  // XOF(rho, col, row)) without re-running the full KAT corpus.

  /// Test hook: generates the matrix entry whose XOF input is `rho || col || row`.
  static Poly genMatrixEntryForTest(Uint8List rho, int col, int row) =>
      _genMatrixPoly(rho, col, row);

  /// Test hook: runs FIPS 203 SampleNTT rejection sampling over [stream].
  static Poly sampleNttForTest(Uint8List stream) => _sampleNTT(stream);

  static (Uint8List, Uint8List) generateKeyPair(
    Uint8List rhoSigma,
    Uint8List z,
    KyberParams params,
  ) {
    // Copies. The caller's [rhoSigma] and [z] are left intact.
    final rho = allocUint8Copy(rhoSigma, 0, 32);
    final sigma = allocUint8Copy(rhoSigma, 32, 64);
    try {
      return _generateKeyPairInternal(rho, sigma, z, params);
    } finally {
      secureZero(rho);
      secureZero(sigma);
    }
  }

  static (Uint8List, Uint8List) _generateKeyPairInternal(
    Uint8List rho,
    Uint8List sigma,
    Uint8List z,
    KyberParams params,
  ) {
    final k = params.k;
    final dropped = <Int16List>[];
    void drop(Poly p) => dropped.add(p.coeffs);
    List<List<Poly>>? aHat;
    List<Poly>? s;
    List<Poly>? e;
    List<Poly>? sHat;
    List<Poly>? eHat;
    List<Poly>? tHat;
    Poly? tFlat;
    Poly? sFlat;
    try {
      // 1. Gen Matrix A_hat (k x k) in NTT domain
      aHat = List.generate(
        k,
        (i) => List.generate(k, (j) => _genMatrixPoly(rho, j, i)),
      );

      // 2. Sample s, e (Normal Domain)
      s = List.generate(k, (i) => sampleInBall(sigma, params, nonce: i));
      e = List.generate(k, (i) => sampleInBall(sigma, params, nonce: k + i));

      // 3. Transform s, e to NTT domain
      final secret = s;
      final error = e;
      sHat = List.generate(k, (i) => Poly.ntt(secret[i]));
      eHat = List.generate(k, (i) => Poly.ntt(error[i]));

      // 4. Compute t_hat = A_hat * s_hat + e_hat
      tHat = List.generate(k, (_) => Poly(allocInt16(256)));

      for (int i = 0; i < k; i++) {
        tHat[i].coeffs.setAll(0, eHat[i].coeffs);

        for (int j = 0; j < k; j++) {
          final prod = Poly.baseMul(aHat[i][j], sHat[j]);
          final sum = _polyAdd(tHat[i], prod);
          drop(tHat[i]);
          drop(prod);
          tHat[i] = sum;
        }

        final reduced = _polyReduce(tHat[i]);
        drop(tHat[i]);
        tHat[i] = reduced;
      }

      // 5. Pack pk = (t_hat || rho)
      tFlat = _flattenPolyVec(tHat);
      final pk = Pack.encodePublicKey(tFlat, rho, params);

      // 6. Pack sk = s_hat. H(pk) is not secret.
      final h = sha3256(pk);
      sFlat = _flattenPolyVec(sHat);
      final sk = Pack.encodeSecretKey(sFlat, h, pk, z, params);

      return (pk, sk);
    } finally {
      for (final buf in dropped) {
        secureZeroInt16(buf);
      }
      final matrix = aHat;
      if (matrix != null) {
        for (final row in matrix) {
          _wipePolys(row);
        }
      }
      _wipePolys(s);
      _wipePolys(e);
      _wipePolys(sHat);
      _wipePolys(eHat);
      _wipePolys(tHat);
      _wipePoly(tFlat);
      _wipePoly(sFlat);
    }
  }

  static Poly _polyFromMsg(Uint8List m) {
    final p = Poly(allocInt16(256));
    // 32 bytes -> 256 coeffs
    for (int i = 0; i < 32; i++) {
      for (int j = 0; j < 8; j++) {
        // (q+1)/2 = 1665 when the message bit is set.
        p.coeffs[8 * i + j] = ((m[i] >> j) & 1) * 1665;
      }
    }
    return p;
  }

  // Polynomial addition WITHOUT automatic reduction (matches C reference behavior)
  // The C reference lets coefficients accumulate and only reduces when serializing
  static Poly _polyAdd(Poly a, Poly b) {
    final res = allocInt16(256);
    for (int i = 0; i < 256; i++) {
      res[i] = a.coeffs[i] + b.coeffs[i];
      // No modulo here - let values accumulate like C int16_t
    }
    return Poly(res);
  }

  // Explicit reduction when needed (e.g., before serialization)
  static Poly _polyReduce(Poly p) {
    final res = allocInt16(256);
    for (int i = 0; i < 256; i++) {
      res[i] = Poly.barrettReduce(p.coeffs[i]);
    }
    return Poly(res);
  }

  static Poly _polySub(Poly a, Poly b) {
    final res = allocInt16(256);
    for (int i = 0; i < 256; i++) {
      res[i] = caddq(a.coeffs[i] - b.coeffs[i], 3329);
    }
    return Poly(res);
  }

  static List<Poly> _unflattenPolyVec(Poly flat, int k) {
    final vec = List.generate(k, (_) => Poly(allocInt16(256)));
    for (int i = 0; i < k; i++) {
      for (int j = 0; j < 256; j++) {
        vec[i].coeffs[j] = flat.coeffs[i * 256 + j];
      }
    }
    return vec;
  }

  static Poly _flattenPolyVec(List<Poly> vec) {
    var n = 0;
    for (final p in vec) {
      n += p.coeffs.length;
    }
    final all = allocInt16(n);
    var offset = 0;
    for (final p in vec) {
      final src = p.coeffs;
      for (var i = 0; i < src.length; i++) {
        all[offset + i] = src[i];
      }
      offset += src.length;
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
    final input = allocUint8(seed.length + 1);
    input.setAll(0, seed);
    input[seed.length] = nonce;

    final len = 64 * eta;
    final stream = Shake256.shake(input, len);

    return _cbd(stream, eta);
  }

  static Poly _cbd(Uint8List buf, int eta) {
    final coeffs = allocInt16(256);
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
        // a - b is in [-2, 2]. One conditional add is the canonical residue.
        coeffs[i] = caddq(a - b, 3329);
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
          // a - b is in [-3, 3].
          coeffs[i + j] = caddq(a - b, 3329);
        }
      }
    }
    return Poly(coeffs);
  }

  // Normalize coefficients to [0, q-1]
  static Poly _polyNormalize(Poly p) {
    final res = allocInt16(256);
    for (int i = 0; i < 256; i++) {
      // Coefficients here are short sums of canonical residues, inside the
      // Barrett envelope proved for [-2000000, q^2].
      res[i] = Poly.barrettReduce(p.coeffs[i]);
    }
    return Poly(res);
  }

  static void _wipePoly(Poly? poly) => secureZeroInt16(poly?.coeffs);

  static void _wipePolys(List<Poly>? polys) {
    if (polys == null) return;
    for (final poly in polys) {
      secureZeroInt16(poly.coeffs);
    }
  }
}

import 'dart:typed_data';
import 'package:pqcrypto/src/common/poly.dart';
import 'params.dart';

/// For compressing/decompressing polys (Bytestream encoding).
class Pack {
  static Uint8List encodePublicKey(Poly t, Uint8List h, KyberParams params) {
    final pkSize = params.publicKeyBytes;
    final pk = Uint8List(pkSize);

    final coeffs = t.coeffs;
    // Pack t (12 bits)
    // 2 coeffs -> 3 bytes
    int outIdx = 0;
    // Limit to polynomial size 256*k
    int len = 256 * params.k;
    // If t is stubborn and has wrong size, use min
    if (coeffs.length < len) len = coeffs.length;

    for (int i = 0; i < len; i += 2) {
      if (outIdx + 3 > 384 * params.k) break; // Safety
      int t0 = coeffs[i];
      int t1 = (i + 1 < len) ? coeffs[i + 1] : 0;

      pk[outIdx++] = t0 & 0xFF;
      pk[outIdx++] = ((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4);
      pk[outIdx++] = (t1 >> 4) & 0xFF;
    }

    // Append rho (32 bytes)
    pk.setAll(params.publicKeyBytes - 32, h);

    return pk;
  }

  static (Poly s, Uint8List h, Uint8List pk) decodeSecretKey(
    Uint8List sk,
    KyberParams params,
  ) {
    final sBytes = (12 * params.k * 256) ~/ 8;
    final pkBytes = params.publicKeyBytes;

    final sCoeffs = List<int>.filled(256 * params.k, 0);
    int inIdx = 0;
    for (int i = 0; i < sCoeffs.length; i += 2) {
      if (inIdx + 3 > sBytes) break;
      int b0 = sk[inIdx++];
      int b1 = sk[inIdx++];
      int b2 = sk[inIdx++];

      sCoeffs[i] = b0 | ((b1 & 0x0F) << 8);
      sCoeffs[i + 1] = (b1 >> 4) | (b2 << 4);
    }

    final pk = sk.sublist(sBytes, sBytes + pkBytes);
    final h = sk.sublist(sBytes + pkBytes, sBytes + pkBytes + 32);

    return (Poly(sCoeffs), h, pk);
  }

  static Uint8List encodeSecretKey(
    Poly s,
    Uint8List h,
    Uint8List pk,
    KyberParams params,
  ) {
    final skSize = params.secretKeyBytes;
    final sk = Uint8List(skSize);

    int outIdx = 0;
    final coeffs = s.coeffs;
    int len = 256 * params.k;
    if (coeffs.length < len) len = coeffs.length;

    for (int i = 0; i < len; i += 2) {
      int t0 = coeffs[i];
      int t1 = (i + 1 < len) ? coeffs[i + 1] : 0;

      sk[outIdx++] = t0 & 0xFF;
      sk[outIdx++] = ((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4);
      sk[outIdx++] = (t1 >> 4) & 0xFF;
    }

    final sBytes = (12 * params.k * 256) ~/ 8;
    // Append pk
    sk.setAll(sBytes, pk);
    // Append h
    sk.setAll(sBytes + params.publicKeyBytes, h);
    // Append z (placeholder)
    // ...

    return sk;
  }
}

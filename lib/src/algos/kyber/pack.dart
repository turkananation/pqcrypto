import 'dart:typed_data';
import 'package:pqcrypto/src/common/poly.dart';
import 'params.dart';

/// Serialization for ML-KEM (FIPS 203 compliant)
class Pack {
  static const int q = 3329;

  /// Compress coefficient to d bits per FIPS 203 Definition 4.7
  /// Maps field element uniformly to range [0, 2^d - 1]
  static int compress(int x, int d) {
    // Formula from FIPS 203: compress_d(x) = ⌈(2^d / q) * x⌉ mod 2^d
    // where ⌈⌉ is "round to nearest, ties round up"

    // To avoid floating point, we compute: round((x * 2^d) / q)
    // Using the formula: round(a/b) = (a + b/2) / b (integer division)
    // BUT we need to handle the case where this might give 2^d

    // Compute (2 * x * (1 << d) + q) / (2 * q) to do proper rounding
    final numerator = 2 * x * (1 << d) + q;
    final denominator = 2 * q;
    final result = numerator ~/ denominator;

    // Clamp to [0, 2^d - 1] to handle edge cases where rounding gives 2^d
    final maxVal = (1 << d) - 1;
    return result > maxVal ? maxVal : result;
  }

  /// Decompress d-bit value to field element per FIPS 203 Definition 4.8
  /// Maps uniformly from [0, 2^d - 1] to full coefficient range
  static int decompress(int y, int d) {
    // Compute (y * q) / 2^d, rounded to nearest integer
    final dividend = y * q;
    int quotient = dividend >> d;

    // Round up if d-th bit of dividend is set (top half rounds up)
    if ((dividend >> (d - 1)) & 1 == 1) quotient++;

    return quotient;
  }

  /// ByteEncode₁₂ per FIPS 203 Algorithm 5 (for public keys)
  /// 256 coefficients → 384 bytes (12 bits per coeff, 2 coeffs → 3 bytes)
  static Uint8List byteEncode12(Poly poly) {
    final result = Uint8List(384);
    int outIdx = 0;

    for (int i = 0; i < 256; i += 2) {
      final c0 = poly.coeffs[i] & 0xFFF; // 12 bits
      final c1 = poly.coeffs[i + 1] & 0xFFF; // 12 bits

      result[outIdx++] = c0 & 0xFF;
      result[outIdx++] = ((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4);
      result[outIdx++] = (c1 >> 4) & 0xFF;
    }

    return result;
  }

  /// ByteDecode₁₂ per FIPS 203 Algorithm 6 (for public keys)
  /// Decodes 384 bytes → 256 coefficients with bounds checking
  static Poly byteDecode12(Uint8List bytes) {
    if (bytes.length != 384) {
      throw ArgumentError('Invalid encoding length for ByteDecode12');
    }

    final coeffs = List<int>.filled(256, 0);
    int inIdx = 0;

    for (int i = 0; i < 256; i += 2) {
      final b0 = bytes[inIdx++];
      final b1 = bytes[inIdx++];
      final b2 = bytes[inIdx++];

      final c0 = b0 | ((b1 & 0x0F) << 8);
      final c1 = (b1 >> 4) | (b2 << 4);

      // Bounds check: coefficients must be < q
      if (c0 >= q || c1 >= q) {
        throw ArgumentError('Invalid polynomial encoding: coefficient >= q');
      }

      coeffs[i] = c0;
      coeffs[i + 1] = c1;
    }

    return Poly(coeffs);
  }

  /// Compress₁₀ + ByteEncode₁₀ for ciphertext u (ML-KEM-768)
  /// 256 coefficients → 320 bytes (10 bits per coeff, 4 coeffs → 5 bytes)
  static Uint8List compressAndEncode10(Poly poly) {
    final result = Uint8List(320);
    int outIdx = 0;

    for (int i = 0; i < 256; i += 4) {
      final c0 = compress(poly.coeffs[i], 10);
      final c1 = compress(poly.coeffs[i + 1], 10);
      final c2 = compress(poly.coeffs[i + 2], 10);
      final c3 = compress(poly.coeffs[i + 3], 10);

      // Pack 4 × 10-bit values into 5 bytes
      final x = c0 | (c1 << 10) | (c2 << 20) | (c3 << 30);

      result[outIdx++] = x & 0xFF;
      result[outIdx++] = (x >> 8) & 0xFF;
      result[outIdx++] = (x >> 16) & 0xFF;
      result[outIdx++] = (x >> 24) & 0xFF;
      result[outIdx++] = (x >> 32) & 0xFF;
    }

    return result;
  }

  /// ByteDecode₁₀ + Decompress₁₀ for ciphertext u
  static Poly decodeAndDecompress10(Uint8List bytes) {
    if (bytes.length != 320) {
      throw ArgumentError('Invalid encoding length for DecodeDecompress10');
    }

    final coeffs = List<int>.filled(256, 0);
    int inIdx = 0;

    for (int i = 0; i < 256; i += 4) {
      final b0 = bytes[inIdx++];
      final b1 = bytes[inIdx++];
      final b2 = bytes[inIdx++];
      final b3 = bytes[inIdx++];
      final b4 = bytes[inIdx++];

      final x = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32);

      coeffs[i] = decompress((x >> 0) & 0x3FF, 10); // 10 bits
      coeffs[i + 1] = decompress((x >> 10) & 0x3FF, 10);
      coeffs[i + 2] = decompress((x >> 20) & 0x3FF, 10);
      coeffs[i + 3] = decompress((x >> 30) & 0x3FF, 10);
    }

    return Poly(coeffs);
  }

  /// Compress₄ + ByteEncode₄ for ciphertext v (ML-KEM-768)
  /// 256 coefficients → 128 bytes (4 bits per coeff, 2 coeffs → 1 byte)
  static Uint8List compressAndEncode4(Poly poly) {
    final result = Uint8List(128);

    for (int i = 0; i < 256; i += 2) {
      final c0 = compress(poly.coeffs[i], 4);
      final c1 = compress(poly.coeffs[i + 1], 4);

      result[i ~/ 2] = (c0 & 0xF) | ((c1 & 0xF) << 4);
    }

    return result;
  }

  /// ByteDecode₄ + Decompress₄ for ciphertext v
  static Poly decodeAndDecompress4(Uint8List bytes) {
    if (bytes.length != 128) {
      throw ArgumentError('Invalid encoding length for DecodeDecompress4');
    }

    final coeffs = List<int>.filled(256, 0);

    for (int i = 0; i < 256; i += 2) {
      final byte = bytes[i ~/ 2];

      coeffs[i] = decompress(byte & 0xF, 4);
      coeffs[i + 1] = decompress(byte >> 4, 4);
    }

    return Poly(coeffs);
  }

  /// Compress₁ + ByteEncode₁ for messages
  /// 256 coefficients → 32 bytes (1 bit per coeff, 8 coeffs → 1 byte)
  static Uint8List compressAndEncode1(Poly poly) {
    final result = Uint8List(32);

    for (int i = 0; i < 256; i++) {
      final bit = compress(poly.coeffs[i], 1);
      result[i ~/ 8] |= (bit << (i % 8));
    }

    return result;
  }

  /// ByteDecode₁ + Decompress₁ for messages
  static Poly decodeAndDecompress1(Uint8List bytes) {
    if (bytes.length != 32) {
      throw ArgumentError('Invalid encoding length for DecodeDecompress1');
    }

    final coeffs = List<int>.filled(256, 0);

    for (int i = 0; i < 256; i++) {
      final bit = (bytes[i ~/ 8] >> (i % 8)) & 1;
      const halfQ = (q + 1) ~/ 2; // ⌈q/2⌋ = 1665
      coeffs[i] = bit * halfQ; // 0 → 0, 1 → 1665
    }

    return Poly(coeffs);
  }

  // ========== Legacy public/secret key encoding (keeping for compatibility) ==========

  static Uint8List encodePublicKey(Poly t, Uint8List h, KyberParams params) {
    final pkSize = params.publicKeyBytes;
    final pk = Uint8List(pkSize);

    final coeffs = t.coeffs;
    // Pack t (12 bits) using ByteEncode12
    int outIdx = 0;
    int len = 256 * params.k;
    if (coeffs.length < len) len = coeffs.length;

    for (int i = 0; i < len; i += 2) {
      if (outIdx + 3 > 384 * params.k) break;
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

  static (Poly s, Uint8List h, Uint8List pk, Uint8List z) decodeSecretKey(
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
    final z = sk.sublist(sBytes + pkBytes + 32, sBytes + pkBytes + 32 + 32);

    return (Poly(sCoeffs), h, pk, z);
  }

  static Uint8List encodeSecretKey(
    Poly s,
    Uint8List h,
    Uint8List pk,
    Uint8List z,
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
    // Append z
    sk.setAll(sBytes + params.publicKeyBytes + 32, z);

    return sk;
  }
}

import 'dart:typed_data';
import '../../common/shake.dart';
import '../../common/sha2.dart';
import 'poly.dart';
import 'params.dart';
import 'packing.dart';

class DilithiumSymmetric {
  /// CRH(seed): variable output bytes from SHAKE-256 (default 64)
  static Uint8List crh(Uint8List seed, [int length = 64]) {
    // FIPS 204: H produces 2*lambda output.
    return Shake256.shake(seed, length);
  }

  /// HashML-DSA pre-hash (FIPS 204 §5.4).
  ///
  /// Returns `(DER(OID), PH(M))` for the approved pre-hash bound to the
  /// security level (selected by [cTildeSize] = lambda/4):
  /// SHA-256 (ML-DSA-44), SHA-384 (ML-DSA-65), SHA-512 (ML-DSA-87).
  static (Uint8List, Uint8List) preHash(Uint8List m, int cTildeSize) {
    switch (cTildeSize) {
      case 32: // ML-DSA-44 -> SHA-256, OID 2.16.840.1.101.3.4.2.1
        return (
          Uint8List.fromList(const [
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,
          ]),
          sha256(m),
        );
      case 48: // ML-DSA-65 -> SHA-384, OID 2.16.840.1.101.3.4.2.2
        return (
          Uint8List.fromList(const [
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x02,
          ]),
          sha384(m),
        );
      case 64: // ML-DSA-87 -> SHA-512, OID 2.16.840.1.101.3.4.2.3
        return (
          Uint8List.fromList(const [
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x03,
          ]),
          sha512(m),
        );
      default:
        throw ArgumentError('Unsupported cTildeSize: $cTildeSize');
    }
  }

  /// ExpandA(rho) -> Matrix A (k x l) of DilithiumPoly in NTT domain.
  static List<DilithiumPolyVec> expandA(Uint8List rho, int k, int l) {
    final matrix = List.generate(k, (_) => DilithiumPolyVec.zero(l));
    for (int r = 0; r < k; r++) {
      for (int s = 0; s < l; s++) {
        matrix[r].components[s] = _rejNttPoly(rho, s, r);
      }
    }
    return matrix;
  }

  /// ExpandS(rho, eta) -> (s1, s2) vectors
  static (DilithiumPolyVec, DilithiumPolyVec) expandS(
    Uint8List rho,
    int k,
    int l,
    int eta,
  ) {
    final s1 = DilithiumPolyVec.zero(l);
    final s2 = DilithiumPolyVec.zero(k);

    // Logic from FIPS 204 Alg 14 (ExpandS) approx
    // s1:
    for (int r = 0; r < l; r++) {
      s1[r] = _rejBoundedPoly(rho, r, eta);
    }

    // s2:
    for (int r = 0; r < k; r++) {
      s2[r] = _rejBoundedPoly(rho, l + r, eta);
    }

    return (s1, s2);
  }

  // --- Sampling Algorithms ---

  // FIPS 204 Algorithm 30: RejNTTPoly(rho || IntegerToBytes(s,1) || IntegerToBytes(r,1))
  // C ref: nonce = (r << 8) + s, t[0] = s, t[1] = r → 34 bytes total
  static DilithiumPoly _rejNttPoly(Uint8List rho, int s, int r) {
    final inputStrict = Uint8List(34);
    inputStrict.setRange(0, 32, rho);
    inputStrict[32] = s & 0xFF;
    inputStrict[33] = r & 0xFF;

    // FIPS 204 Algorithm 30 RejNTTPoly: incremental SHAKE128 squeeze, three
    // bytes per candidate, accept when the 23-bit value is < q. Using the XOF
    // means the sampler can never exhaust a fixed buffer.
    final xof = Shake128.xof(inputStrict);
    final coeffs = Int32List(n);
    int ctr = 0;
    while (ctr < n) {
      final b0 = xof.squeezeByte();
      final b1 = xof.squeezeByte();
      final b2 = xof.squeezeByte();
      final t = (b0 | (b1 << 8) | (b2 << 16)) & 0x7FFFFF; // 23 bits
      if (t < q) {
        coeffs[ctr++] = t;
      }
    }

    return DilithiumPoly(coeffs);
  }

  // FIPS 204 Algorithm 31: RejBoundedPoly(rho' || IntegerToBytes(kappa, 2))
  // C ref: seed is CRHBYTES=64 bytes, nonce is 2 bytes → 66 bytes total
  static DilithiumPoly _rejBoundedPoly(Uint8List rho, int kappa, int eta) {
    final input = Uint8List(64 + 2);
    input.setRange(0, 64, rho);
    input[64] = kappa & 0xFF;
    input[65] = (kappa >> 8) & 0xFF;

    // FIPS 204 Algorithm 31 RejBoundedPoly + Algorithm 15 CoeffFromHalfByte:
    // incremental SHAKE256 squeeze, one byte (two half-bytes) per step.
    //   eta=2: accept half-byte b<15, value = 2 - (b mod 5); reject b==15.
    //   eta=4: accept half-byte b<9,  value = 4 - b;        reject b>=9.
    final xof = Shake256.xof(input);
    final coeffs = Int32List(n);
    int ctr = 0;
    if (eta == 2) {
      while (ctr < n) {
        final b = xof.squeezeByte();
        final t0 = b & 0x0F, t1 = b >> 4;
        if (t0 < 15) coeffs[ctr++] = 2 - (t0 % 5);
        if (ctr < n && t1 < 15) coeffs[ctr++] = 2 - (t1 % 5);
      }
    } else {
      while (ctr < n) {
        final b = xof.squeezeByte();
        final t0 = b & 0x0F, t1 = b >> 4;
        if (t0 < 9) coeffs[ctr++] = 4 - t0;
        if (ctr < n && t1 < 9) coeffs[ctr++] = 4 - t1;
      }
    }
    return DilithiumPoly(coeffs);
  }

  /// ExpandMask(rho, kappa, gamma1) -> vector y
  static DilithiumPolyVec expandMask(
    Uint8List rho,
    int kappa,
    int l,
    int gamma1,
  ) {
    final y = DilithiumPolyVec.zero(l);
    for (int r = 0; r < l; r++) {
      // Input: rho || IntegerToBytes(kappa + r, 2)
      // Standard uses a simplified kappa logic:
      // For each poly, increment kappa logic?
      // FIPS: y_r = SamplePoly(rho || (kappa+r))
      // Be careful with kappa offset.

      final nonce = kappa + r;
      // We use _rejGamma1 (alg?)
      // FIPS 204 uses "RejBoundedPoly" logic but with large bound gamma1 (2^17 or 2^19)
      // This generally requires 5 blocks of SHAKE256?
      // Let's implement _rejGamma1 logic inline or helper.

      y[r] = _rejGamma1(rho, nonce, gamma1);
    }
    return y;
  }

  // FIPS 204 Algorithm 16 (ExpandMask): Direct BitUnpack, no rejection.
  // C ref: polyz_unpack(a, buf) with coeff = GAMMA1 - unpacked_val
  static DilithiumPoly _rejGamma1(Uint8List rho, int nonce, int gamma1) {
    final input = Uint8List(64 + 2);
    input.setRange(0, 64, rho);
    input[64] = nonce & 0xFF;
    input[65] = (nonce >> 8) & 0xFF;

    // 18 bits per coeff for gamma1=2^17, 20 bits for gamma1=2^19
    int bits = (gamma1 == (1 << 17)) ? 18 : 20;
    int streamLen = 256 * bits ~/ 8; // 576 or 640 bytes
    final stream = Shake256.shake(input, streamLen);

    // Direct BitUnpack: unpack 18/20 bits per coefficient
    final mapped = simpleBitUnpack(stream, bits);
    final coeffs = Int32List(256);
    for (int i = 0; i < 256; i++) {
      coeffs[i] = gamma1 - mapped.coeffs[i];
    }
    return DilithiumPoly(coeffs);
  }

  /// SampleInBall(rho) -> Poly c with tau +/- 1's.
  /// Used for challenge.
  static DilithiumPoly sampleInBall(Uint8List rho, int tau) {
    // Input: seed (32 bytes). Actually rho is c_tilde (32 bytes).
    // Output: c

    // SampleInBall (Alg 14 in draft)
    // 1. SHAKE-256(rho, 8*tau)? No.
    // Spec:
    // Shake256(rho, ...). Output byte stream.
    // Use first 8 bytes for "signs". (64 bits, enough for tau=60).
    // Use remaining bytes for rejection sampling of positions.
    // Positions: sample j in [0, i-1]? No, Fisher-Yates shuffle logic?

    // Logic:
    // c = 0
    // s <- Shake256(rho, 8 + n? )?
    // sign_bits = s[0...7]
    // for i from n-tau to n-1:
    //   sample j uniform in [0, i] using rejection on s stream.
    //   c[i] = c[j]
    //   c[j] = (-1)^bit * 1

    // FIPS 204 Algorithm 29 SampleInBall: the first 8 squeezed bytes provide
    // the 64 sign bits; subsequent bytes drive a Fisher-Yates placement of the
    // tau non-zero entries. Incremental squeeze => no buffer-exhaustion path.
    final c = DilithiumPoly.zero();
    final xof = Shake256.xof(rho);
    final signs = xof.squeeze(8);

    int k = 0;
    for (int i = 256 - tau; i < 256; i++) {
      int j;
      do {
        j = xof.squeezeByte();
      } while (j > i);

      c.coeffs[i] = c.coeffs[j];
      final signBit = (signs[k >> 3] >> (k & 7)) & 1;
      c.coeffs[j] = (signBit == 1) ? -1 : 1;
      k++;
    }

    return c;
  }
}

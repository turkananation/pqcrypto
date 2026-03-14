import 'dart:typed_data';
import '../../common/shake.dart';
import 'poly.dart';
import 'params.dart';
import 'packing.dart';

// Import rounding? maybe for some checks.

class DilithiumSymmetric {
  /// CRH(seed): variable output bytes from SHAKE-256 (default 64)
  static Uint8List crh(Uint8List seed, [int length = 64]) {
    // FIPS 204: H produces 2*lambda output.
    return Shake256.shake(seed, length);
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

    // SHAKE-128
    // We squeeze enough blocks.
    // Spec suggests separate calls, but Shake128.shake does strict output length.
    // SHAKE128 rate = 168 bytes.
    // Need approx. 12 bits * 256 = 3072 bits = 384 bytes.
    // Rejection rate analysis: need ~5 blocks (840 bytes) to be safe.

    final stream = Shake128.shake(inputStrict, 840);

    final coeffs = Int32List(n);
    int ctr = 0;
    int offset = 0;

    while (ctr < n && offset + 3 <= stream.length) {
      int b0 = stream[offset];
      int b1 = stream[offset + 1];
      int b2 = stream[offset + 2];
      offset += 3;

      // Coeff = b0 + (b1 << 8) + (b2 << 16) & 0x7FFFFF
      int t = b0 | (b1 << 8) | (b2 << 16);
      t &= 0x7FFFFF; // 23 bits

      if (t < q) {
        coeffs[ctr++] = t;
      }
    }

    if (ctr < n) {
      throw Exception("RejNTTPoly failed to generate enough coefficients");
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

    // SHAKE-256 (Uses PRF logic usually)
    // Length depends on eta.

    // We implement specific logic per eta because packing differs.
    // But FIPS 204 RejBoundedPoly(rho) logic:
    // Parse stream into coefficients in range [-eta, eta].

    final stream = Shake256.shake(input, 1008); // Large buffer

    final coeffs = Int32List(n);
    int ctr = 0;
    int offset = 0;

    // Loop based on eta?
    // "Sample from [-eta, eta]"
    // Uses Rejection Sampling on specific bits?

    /* 
       For eta=2:
       Read byte. t0 = b & 0x0F, t1 = b >> 4.
       If t0 < 15, then t0 = t0 - (15-4)/2 ? No.
       Spec:
       if t0 <= 15 - 5 (??)
       
       Correct logic:
       We want uniform in [-2, 2]. Size 5.
       Closest power of 2 is 8 (3 bits) or 16 (4 bits).
       Using 4 bits (nibble):
       If nibble < 5: take it? range 0..4 map to -2..2?
       t = nibble.
       If t < 5 return 2 - t.
       (2, 1, 0, -1, -2)
    */

    if (eta == 2) {
      while (ctr < n && offset < stream.length) {
        int b = stream[offset++];
        int t0 = b & 0x0F;
        int t1 = b >> 4;

        if (t0 < 5) {
          coeffs[ctr++] = 2 - t0;
        }
        if (ctr < n && t1 < 5) {
          coeffs[ctr++] = 2 - t1;
        }
      }
    } else if (eta == 4) {
      // eta=4. Range [-4, 4]. Size 9.
      // Byte maps to 0..255.
      // Need 9.
      // 4 bits gives 0..15.
      // if t < 9: return 4 - t.
      while (ctr < n && offset < stream.length) {
        int b = stream[offset++];
        int t0 = b & 0x0F;
        int t1 = b >> 4;

        if (t0 < 9) {
          coeffs[ctr++] = 4 - t0;
        }
        if (ctr < n && t1 < 9) {
          coeffs[ctr++] = 4 - t1;
        }
      }
    }

    if (ctr < n) throw Exception("RejBoundedPoly failed");
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

    final c = DilithiumPoly.zero();
    // 8 bytes for signs.
    // Sample tau positions in [0, 255].
    // Note: FIPS 204 Alg is slightly different from old Dilithium.

    // Alg 9 (SampleInBall):
    // k = 256
    // S = Shake256(rho, 860?)? Rate is 136. Getting enough bytes.
    // signs = S[0..7] (64 bits used)

    // Implementation:
    final stream = Shake256.shake(rho, 840); // 6 SHAKE-256 blocks, safe for tau=60

    int offset = 8;
    int k = 0;

    for (int i = 256 - tau; i < 256; i++) {
      int j;
      while (true) {
        if (offset >= stream.length) {
          // Should verify needed length or expand stream
          throw Exception("SampleInBall stream exhausted");
        }
        int byte = stream[offset++];
        if (byte <= i) {
          j = byte;
          break;
        }
      }

      c.coeffs[i] = c.coeffs[j];
      // Set c[j] to +/- 1 based on sign bit k
      // Need k-th bit of 'signs'.
      // Or simpler: access stream[k/8] >> (k%8).
      int signByte = stream[k >> 3];
      int signBit = (signByte >> (k & 7)) & 1;
      c.coeffs[j] = (signBit == 1) ? -1 : 1;

      k++;
    }

    return c;
  }
}

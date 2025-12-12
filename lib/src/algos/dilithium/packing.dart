import 'dart:typed_data';
import 'params.dart';
import 'poly.dart';

/// FIPS 204 Algorithm 9: SimpleBitPack(w, b)
/// Packs polynomial coefficients w where each coeff is in [0, 2^b - 1]
/// Returns byte array of length 32 * b
Uint8List simpleBitPack(DilithiumPoly w, int b) {
  final out = Uint8List(32 * b);

  // Logic depends on b.
  // FIPS 204 defines standard bitpacking for b < 8?
  // "Standard little-endian packing"

  // Implementation note: w.length = 256.
  // We pack 'b' bits per coefficient.
  // Total bits = 256 * b. Total bytes = 32 * b.

  // General implementation:
  int buffer = 0;
  int bitsInBuffer = 0;
  int outIdx = 0;

  for (int i = 0; i < n; i++) {
    int val = w.coeffs[i];
    // assert(val < (1 << b) && val >= 0);

    buffer |= (val << bitsInBuffer);
    bitsInBuffer += b;

    while (bitsInBuffer >= 8) {
      out[outIdx++] = buffer & 0xFF;
      buffer >>=
          8; // This must be logical shift for unsigned? Dart int is signed.
      // If buffer is negative, >> fills with 1s.
      // We need >>> but Dart doesn't have it standardly until recently (triple shift).
      // Or we mask buffer?
      // Wait, buffer should be treated as unsigned.
      // If buffer has high bit set (bit 63), >> 8 will sign extend.
      // val is positive. buffer starts 0.
      // buffer |= (val << bits).
      // If bitsInBuffer grows large?
      // bitsInBuffer never exceeds 8 + b - 1.
      // max b = 20. bitsInBuffer < 28.
      // buffer never exceeds 28 bits used.
      // Dart int is 64 bit. So sign bit is never touched.
      // So >> 8 is safe.

      bitsInBuffer -= 8;
    }
  }

  // Drain remaining? Should be 0 if b is integer.
  if (bitsInBuffer > 0) {
    out[outIdx++] = buffer & 0xFF;
  }

  return out;
}

/// FIPS 204 Algorithm 10: SimpleBitUnpack(v, b)
/// Unpacks byte array v into polynomial w with coefficients in [0, 2^b - 1]
DilithiumPoly simpleBitUnpack(Uint8List v, int b) {
  final w = Int32List(n);

  int buffer = 0;
  int bitsInBuffer = 0;
  int inIdx = 0;

  final mask = (1 << b) - 1;

  for (int i = 0; i < n; i++) {
    while (bitsInBuffer < b) {
      buffer |= (v[inIdx++] << bitsInBuffer);
      bitsInBuffer += 8;
    }

    w[i] = buffer & mask;
    buffer >>= b;
    bitsInBuffer -= b;
  }

  return DilithiumPoly(w);
}

/// FIPS 204 Algorithm 11: BitPack(w, a, b)
/// Packs w with range [-a, b]. Used for t1 ??
/// Actually FIPS 204 spec refers to pk/sk/sig packing specifically.
/// Algorithm 11 is "BitPack(w, eta)" ? No.
/// Standard specifies specific packing for t1, s1, s2, etc.

/// Pack t1 (10 bits per coeff)
Uint8List packT1(DilithiumPoly t1) {
  return simpleBitPack(t1, 10);
}

DilithiumPoly unpackT1(Uint8List bytes) {
  return simpleBitUnpack(bytes, 10);
}

/// Pack Public Key pk = (rho, t1)
/// rho: 32 bytes
/// t1: Vector of polynomials (k elements), each packed with 10 bits.
/// Total size = 32 + k * 320
Uint8List packPK(Uint8List rho, DilithiumPolyVec t1) {
  final k = t1.length;
  final out = Uint8List(32 + k * 320);

  // Copy rho
  out.setRange(0, 32, rho);

  // Pack t1
  int offset = 32;
  for (int i = 0; i < k; i++) {
    final packed = simpleBitPack(t1.components[i], 10);
    out.setRange(offset, offset + 320, packed);
    offset += 320;
  }
  return out;
}

(Uint8List rho, DilithiumPolyVec t1) unpackPK(Uint8List pk, int k) {
  if (pk.length != 32 + k * 320) throw ArgumentError("Invalid PK length");

  final rho = Uint8List(32);
  rho.setRange(0, 32, pk.sublist(0, 32));

  final t1Vec = DilithiumPolyVec.zero(k);
  int offset = 32;
  for (int i = 0; i < k; i++) {
    t1Vec.components[i] = simpleBitUnpack(pk.sublist(offset, offset + 320), 10);
    offset += 320;
  }

  return (rho, t1Vec);
}

/// Pack Hints (hamming weight packed)
Uint8List packHint(DilithiumPoly h, int omega) {
  // This is sparse packing.
  // Record indices of non-zero coefficients.
  // Plus appending the count.
  // See FIPS 204 Alg ... (HintBitPack)
  // Actually Alg 13 in draft?

  final out = Uint8List(omega + n ~/ 8); // Usually omega + k?
  // Correct logic:
  // Store indices i such that h[i] == 1.

  int outIdx = 0;
  int count = 0;

  for (int i = 0; i < n; i++) {
    if (h.coeffs[i] != 0) {
      out[outIdx++] = i;
      count++;
    }
  }
  out[omega] = count; // Store count at end?
  // Verify exact format for FIPS 204 Hint Packing.
  // "The indices are stored in the first k*omega bytes..."
  // It's a bit more complex for vectors.

  return out;
}

/// Pack Secret Key sk = (rho, K, tr, s1, s2, t0)
/// rho: 32
/// K: 32
/// tr: 64 (CRH of pk) - wait, spec says tr is 64 bytes?
/// FIPS 204: tr is 64 bytes (output of CRH)
/// s1: vector size l, coeff range eta
/// s2: vector size k, coeff range eta
/// t0: vector size k, coeff range 2^(d-1) (13 bits usually)
Uint8List packSK(
  Uint8List rho,
  Uint8List K,
  Uint8List tr,
  DilithiumPolyVec s1,
  DilithiumPolyVec s2,
  DilithiumPolyVec t0,
  int eta,
) {
  // Calculate sizes
  int s1Bits = (eta == 2) ? 3 : 4;
  int s2Bits = (eta == 2) ? 3 : 4;
  int t0Bits = 13;

  int s1Size = s1.length * 32 * s1Bits;
  int s2Size = s2.length * 32 * s2Bits;
  int t0Size = t0.length * 32 * t0Bits; // t0 has same dimension as t1 (k)

  int totalSize = 32 + 32 + 64 + s1Size + s2Size + t0Size;
  final out = Uint8List(totalSize);

  int offset = 0;
  out.setRange(offset, offset + 32, rho);
  offset += 32;
  out.setRange(offset, offset + 32, K);
  offset += 32;
  out.setRange(offset, offset + 64, tr);
  offset += 64;

  // Pack s1
  for (int i = 0; i < s1.length; i++) {
    final packed = bitPack(s1[i], eta);
    out.setRange(offset, offset + packed.length, packed);
    offset += packed.length;
  }

  // Pack s2
  for (int i = 0; i < s2.length; i++) {
    final packed = bitPack(s2[i], eta);
    out.setRange(offset, offset + packed.length, packed);
    offset += packed.length;
  }

  // Pack t0
  for (int i = 0; i < t0.length; i++) {
    final packed = simpleBitPack(t0[i], 13);
    out.setRange(offset, offset + packed.length, packed);
    offset += packed.length;
  }

  return out;
}

(
  Uint8List rho,
  Uint8List K,
  Uint8List tr,
  DilithiumPolyVec s1,
  DilithiumPolyVec s2,
  DilithiumPolyVec t0,
)
unpackSK(Uint8List sk, int k, int l, int eta) {
  // Recalculate sizes
  int s1Bits = (eta == 2) ? 3 : 4;
  // s1 has length l
  int s1Bytes = 32 * s1Bits;

  // s2 has length k
  int s2Bits = (eta == 2) ? 3 : 4;
  int s2Bytes = 32 * s2Bits;

  // t0 has length k
  int t0Bytes = 416; // 32 * 13 = 416

  int offset = 0;
  final rho = Uint8List(32);
  rho.setRange(0, 32, sk.sublist(offset, offset + 32));
  offset += 32;

  final K = Uint8List(32);
  K.setRange(0, 32, sk.sublist(offset, offset + 32));
  offset += 32;

  final tr = Uint8List(64);
  tr.setRange(0, 64, sk.sublist(offset, offset + 64));
  offset += 64;

  final s1Vec = DilithiumPolyVec.zero(l);
  for (int i = 0; i < l; i++) {
    s1Vec[i] = bitUnpack(sk.sublist(offset, offset + s1Bytes), eta);
    offset += s1Bytes;
  }

  final s2Vec = DilithiumPolyVec.zero(k);
  for (int i = 0; i < k; i++) {
    s2Vec[i] = bitUnpack(sk.sublist(offset, offset + s2Bytes), eta);
    offset += s2Bytes;
  }

  final t0Vec = DilithiumPolyVec.zero(k);
  for (int i = 0; i < k; i++) {
    t0Vec[i] = simpleBitUnpack(sk.sublist(offset, offset + t0Bytes), 13);
    // Correct sign for t0 (13 bits, centered)
    // Range [-4096, 4096] map from [0, 8191]
    const limit = 1 << 12; // 4096
    const modulus = 1 << 13; // 8192

    for (int j = 0; j < n; j++) {
      int val = t0Vec[i].coeffs[j];
      if (val > limit) {
        val -= modulus;
      }
      // Normalize to [0, q-1]
      if (val < 0) val += 8380417; // q
      t0Vec[i].coeffs[j] = val;
    }

    offset += t0Bytes;
  }

  return (rho, K, tr, s1Vec, s2Vec, t0Vec);
}

/// Helper: BitPack(w, eta)
/// Standard logic: w coefficients in [-eta, eta].
/// Map to [eta - w, eta + w]?
/// FIPS 204 Alg 11:
/// z_i = eta - w_i.
/// Then pack z_i as integer of appropriate bits.
/// if eta=2, bits=3.
/// if eta=4, bits=4.
Uint8List bitPack(DilithiumPoly w, int eta) {
  int bits = (eta == 2) ? 3 : 4;
  final out = Uint8List(32 * bits);

  // Map w -> eta - w_i
  final z = DilithiumPoly.zero();
  for (int i = 0; i < n; i++) {
    z.coeffs[i] = eta - w.coeffs[i];
  }

  // Use simpleBitPack-like logic for fixed bits
  return simpleBitPack(z, bits);
}

DilithiumPoly bitUnpack(Uint8List v, int eta) {
  int bits = (eta == 2) ? 3 : 4;

  final z = simpleBitUnpack(v, bits);

  final w = DilithiumPoly.zero();
  for (int i = 0; i < n; i++) {
    int val = eta - z.coeffs[i];
    if (val < 0) val += q; // Normalize
    w.coeffs[i] = val;
  }
  return w;
}

// Z Packing (for signatures)
// Gamma1 = 2^17 or 2^19.
// Bits: 18 or 20.
Uint8List bitPackZ(DilithiumPoly z, int gamma1) {
  int bits = (gamma1 == (1 << 17)) ? 18 : 20;

  // Map w -> gamma1 - 1 - w (where w is centered)
  final mapped = DilithiumPoly.zero();
  for (int i = 0; i < n; i++) {
    int val = z.coeffs[i];
    if (val > (q >> 1)) val -= q;
    mapped.coeffs[i] = (gamma1 - 1) - val;
  }

  if (z.coeffs[0] != 0 || mapped.coeffs[0] != 0) {
    print(
      "bitPackZ: z[0]=${z.coeffs[0]} mapped[0]=${mapped.coeffs[0]} bits=$bits",
    );
  }

  return simpleBitPack(mapped, bits);
}

DilithiumPoly bitUnpackZ(Uint8List v, int gamma1) {
  int bits = (gamma1 == (1 << 17)) ? 18 : 20;

  final mapped = simpleBitUnpack(v, bits);
  final z = DilithiumPoly.zero();

  for (int i = 0; i < n; i++) {
    int val = (gamma1 - 1) - mapped.coeffs[i];
    // Put back to [0, q-1]
    if (val < 0) val += q;
    z.coeffs[i] = val;
  }

  print("bitUnpackZ: mapped[0]=${mapped.coeffs[0]} z[0]=${z.coeffs[0]}");

  return z;
}

Uint8List packSig(
  Uint8List cTilde,
  DilithiumPolyVec z,
  DilithiumPolyVec h,
  int gamma1,
  int omega,
) {
  // Sig = c_tilde || z || h

  // Calculate sizes
  int zBits = (gamma1 == (1 << 17)) ? 18 : 20;
  int zBytes = 32 * zBits;
  int zSize = z.length * zBytes;

  int hSize = omega + h.length; // Hint size

  final out = Uint8List(cTilde.length + zSize + hSize);

  int offset = 0;
  out.setRange(offset, offset + cTilde.length, cTilde);
  offset += cTilde.length;

  for (int i = 0; i < z.length; i++) {
    final packed = bitPackZ(z[i], gamma1);
    out.setRange(offset, offset + packed.length, packed);
    offset += packed.length;
  }

  // Hint Packing logic (Alg 13)
  int hintBase = offset;
  int limitC = 0;

  for (int i = 0; i < h.length; i++) {
    for (int j = 0; j < n; j++) {
      if (h[i].coeffs[j] != 0) {
        if (limitC < omega) {
          // Should not exceed
          out[hintBase + limitC] = j;
          limitC++;
        }
      }
    }
    out[hintBase + omega + i] = limitC; // Store cumulative count
  }

  // Fill zero padding implicitly (Uint8List initialized to 0)
  return out;
}

(Uint8List cTilde, DilithiumPolyVec z, DilithiumPolyVec h) unpackSig(
  Uint8List sig,
  int k,
  int l,
  int gamma1,
  int omega,
  int cTildeSize,
) {
  int offset = 0;
  final cTilde = Uint8List(cTildeSize);
  cTilde.setRange(0, cTildeSize, sig.sublist(offset, offset + cTildeSize));
  offset += cTildeSize;

  int zBits = (gamma1 == (1 << 17)) ? 18 : 20;
  int zBytes = 32 * zBits;

  final zVec = DilithiumPolyVec.zero(l);
  for (int i = 0; i < l; i++) {
    zVec[i] = bitUnpackZ(sig.sublist(offset, offset + zBytes), gamma1);
    offset += zBytes;
  }

  // Unpack Hints
  final hVec = DilithiumPolyVec.zero(k);
  int hintBase = offset;
  int index = 0;

  for (int i = 0; i < k; i++) {
    int limit = sig[hintBase + omega + i];
    if (limit < index || limit > omega) {
      throw ArgumentError("Invalid Signature Hint Structure");
    }

    // Hints for poly i are from index to limit-1
    int start = index;
    int end = limit;

    // Check ordering
    int lastJ = -1;
    for (int x = start; x < end; x++) {
      int j = sig[hintBase + x];
      // Strict check: strictly increasing
      if (j <= lastJ || j >= 256) throw ArgumentError("Malformed Hint");
      lastJ = j;
      hVec[i].coeffs[j] = 1;
    }
    index = limit;
  }

  for (int j = index; j < omega; j++) {
    if (sig[hintBase + j] != 0) {
      throw ArgumentError("Non-zero padding in hints");
    }
  }

  return (cTilde, zVec, hVec);
}
